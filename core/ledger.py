"""Transactional execution ledger — the system of record (ADR-002).

One SQLite database holds both the execution state machine and its audit events,
so a state transition and the evidence for it commit together or not at all.
The hash-chained JSONL journal is an export of this ledger, not the truth.

The property that makes at-most-once dispatch provable (invariant 3A):

    claim_lease() commits `DISPATCHING` *before* the caller performs the external
    call. Two workers racing on the same lease both run the same conditional
    UPDATE; SQLite serialises them, so exactly one sees rowcount == 1.

Crash during dispatch leaves the row in `DISPATCHING`; recovery reclassifies it
as `UNKNOWN` rather than retrying, because the external side effect may or may
not have happened.
"""

from __future__ import annotations

import json
import math
import sqlite3
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Iterator, Mapping

CREATED = "CREATED"
APPROVED = "APPROVED"
DISPATCHING = "DISPATCHING"
SUCCEEDED = "SUCCEEDED"
FAILED = "FAILED"
UNKNOWN = "UNKNOWN"
PERMANENTLY_UNRESOLVED = "PERMANENTLY_UNRESOLVED"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"

TERMINAL = frozenset({SUCCEEDED, FAILED, PERMANENTLY_UNRESOLVED, REVOKED, EXPIRED})

SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (
    execution_id   TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL,
    actor_id       TEXT NOT NULL,
    tool_id        TEXT NOT NULL,
    operation      TEXT NOT NULL,
    scope_digest   TEXT NOT NULL,
    state          TEXT NOT NULL,
    lease_id       TEXT UNIQUE,
    expires_at     REAL,
    approved_at    REAL,
    dispatcher_id  TEXT,
    created_at     REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    sequence     INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT NOT NULL REFERENCES executions(execution_id),
    kind         TEXT NOT NULL,
    from_state   TEXT,
    to_state     TEXT,
    detail       TEXT NOT NULL,
    recorded_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_execution ON events(execution_id, sequence);
CREATE TABLE IF NOT EXISTS clock_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    high_water REAL NOT NULL
);
"""


class LedgerError(RuntimeError):
    """Raised when a caller attempts an illegal transition."""


PRINCIPAL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789._-:@+"
)


def normalize_principal(value: object, *, field: str) -> str:
    """The one spelling of an actor, approver, revoker or reconciler.

    The separation-of-duty checks compared these strings with ``==`` on whatever
    the caller passed. An agent picks its own ``approver_id``, so the whole
    control came down to spelling. Measured 2026-08-22 against an execution
    requested by ``agent-1``:

    ============================  ==================
    ``approver_id``               result
    ============================  ==================
    ``"agent-1"``                 refused
    ``"Agent-1"``                 **approved**
    ``" agent-1"``                **approved**
    ``"agent-1\n"``               **approved**
    ``"agent\u20111"``            **approved**
    ============================  ==================

    Every row but the first is the same principal wearing a different hat. Both
    `self-approval refused` and `self-reconciliation refused` were bypassable by
    capitalising one letter.

    Normalising is the safe direction on its own - it can only make the refusal
    broader, never narrower. It is not enough by itself: NFKC does **not** fold
    ``\u2011`` (non-breaking hyphen) to ASCII ``-``, so a look-alike would still
    read as a different principal. So the character set is restricted as well,
    the way ``mcp-gateway``'s ``_valid_identifier`` already does it.

    The cost is that a principal id must be ASCII-safe. For a machine-to-machine
    identity in a ledger that is the right trade; a human-readable display name
    belongs somewhere that is not used for comparison.
    """
    if not isinstance(value, str):
        raise LedgerError(f"{field} must be a string")
    folded = unicodedata.normalize("NFKC", value).strip().casefold()
    if not folded:
        raise LedgerError(f"{field} must not be empty")
    bad = sorted({character for character in folded if character not in PRINCIPAL_CHARS})
    if bad:
        raise LedgerError(
            f"{field} may only contain {''.join(sorted(PRINCIPAL_CHARS))}; "
            f"refused {bad!r} - a look-alike character is a different principal "
            f"to a comparison and the same one to a reader"
        )
    return folded


@dataclass(frozen=True)
class Execution:
    execution_id: str
    run_id: str
    actor_id: str
    tool_id: str
    operation: str
    scope_digest: str
    state: str
    lease_id: str | None
    expires_at: float | None


class ExecutionLedger:
    """Durable state machine for side-effecting executions."""

    def __init__(self, path: str, *, clock=None, dispatcher_id: str | None = None) -> None:
        # Which process claimed a lease. Recovery must only reclassify this
        # instance's interrupted dispatches; see recover_interrupted.
        self.dispatcher_id = dispatcher_id or uuid.uuid4().hex
        self._connection = sqlite3.connect(path, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(SCHEMA)
        self._clock = clock or (lambda: __import__("time").time())

    def close(self) -> None:
        self._connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except Exception:
            self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _observe_clock(self, connection: sqlite3.Connection) -> tuple[float, float | None]:
        """Return (now, previous high-water), recording the new high-water.

        A TTL bounds the approval window only while the clock moves forward, and
        `time.time()` gives no such promise: an NTP correction or a restored VM
        snapshot can move it back. Comparing against the approval timestamp alone
        does not catch it - the interesting case is a clock that ran past the
        deadline and then came back to a moment before it, which leaves the
        approval looking live again while nothing in the row has changed.

        So the ledger remembers the furthest point in time it has seen. Going
        back before that is not a legal reading, whatever the row says.

        No tolerance is allowed. A threshold here would be a number invented to
        make the check quiet, and refusing to dispatch is the safe direction: the
        cost is a refusal that names the clock, against dispatching under an
        approval that has already lapsed.
        """
        now = self._clock()
        row = connection.execute("SELECT high_water FROM clock_state WHERE id=1").fetchone()
        previous = row["high_water"] if row else None
        if previous is None or now > previous:
            connection.execute(
                "INSERT INTO clock_state (id, high_water) VALUES (1, ?)"
                " ON CONFLICT(id) DO UPDATE SET high_water=excluded.high_water",
                (now,),
            )
        return now, previous

    def _append_event(
        self,
        connection: sqlite3.Connection,
        execution_id: str,
        kind: str,
        from_state: str | None,
        to_state: str | None,
        detail: Mapping[str, Any],
    ) -> None:
        # Every write observes the clock, so the high-water mark reflects all
        # ledger activity rather than only lease claims. A clock that runs past
        # a deadline and comes back is then contradicted by whatever else the
        # ledger handled in between.
        now, _ = self._observe_clock(connection)
        connection.execute(
            "INSERT INTO events (execution_id, kind, from_state, to_state, detail, recorded_at)"
            " VALUES (?,?,?,?,?,?)",
            (
                execution_id,
                kind,
                from_state,
                to_state,
                json.dumps(detail, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                now,
            ),
        )

    # ------------------------------------------------------------------ writes

    def _record_refusal(self, execution_id: str, kind: str, from_state: str | None,
                        detail: Mapping[str, Any]) -> None:
        """거절을 남긴다. **거절한 뒤에, 따로 연 트랜잭션에서.**

        `_transaction`은 예외가 나면 ROLLBACK한다 — 그래서 거절과 함께 쓴 이벤트는
        거절과 함께 사라진다. `claim_lease`는 이벤트를 쓰고 **`return None`**으로
        빠져나가기 때문에 살아남았고, `approve`와 `reconcile`은 `raise`로 빠져나가
        아무것도 남지 않았다. **같은 종류의 거절인데 한쪽만 기록됐다.**

        2026-08-22에 쟀다: 자기승인 5회 + 범위 불일치 3회, 총 8번의 거절 뒤에도
        이벤트는 `created` 하나뿐이었다. 지난 회차에 시연한 자기승인 우회 탐색
        (`Agent-1`·` agent-1`·`agent\u20111`)도 그러니 아무 흔적을 남기지 않았을
        것이다. **거절당한 시도야말로 기록이 존재하는 이유다.**

        기록에 실패해도 거절 자체는 유지한다 — 남기지 못한 것이 통과시킬 이유는
        되지 않는다. 다만 조용히 넘어가지 않는다.
        """
        try:
            with self._transaction() as connection:
                self._append_event(connection, execution_id, kind, from_state, None, detail)
        except Exception as exc:  # pragma: no cover - 기록 실패는 재현이 어렵다
            print(f"[ledger] {kind} 이벤트를 남기지 못했다: {exc}")

    def create(self, *, run_id: str, actor_id: str, tool_id: str, operation: str,
               scope_digest: str) -> str:
        """Record an intent. The core issues the identity; callers cannot supply it."""
        actor_id = normalize_principal(actor_id, field="actor_id")
        execution_id = uuid.uuid4().hex
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO executions (execution_id, run_id, actor_id, tool_id, operation,"
                " scope_digest, state, lease_id, expires_at, created_at)"
                " VALUES (?,?,?,?,?,?,?,NULL,NULL,?)",
                (execution_id, run_id, actor_id, tool_id, operation, scope_digest,
                 CREATED, self._clock()),
            )
            self._append_event(connection, execution_id, "created", None, CREATED,
                               {"tool_id": tool_id, "operation": operation})
        return execution_id

    def approve(self, execution_id: str, *, approver_id: str, scope_digest: str,
                ttl_seconds: float) -> str:
        """Bind an approval to an exact scope and issue a single-use lease.

        Refuses self-approval. `access.py` has always defined the permission and
        the separation rule, but nothing here consulted it, so an agent could
        approve its own request by passing its own id - the whole control was a
        docstring. The check that needs no configuration is made unconditional:
        the requester is already on the row.

        `ttl_seconds` must be a finite number above zero. It was not checked, and
        two degenerate values produced a lease that never expires - the most
        permissive outcome reachable through this call:

        ``nan``
            ``now + nan`` is ``nan``, SQLite stores that as NULL, and NULL is how
            this schema spells "no expiry". A lease meant to last a minute lasted
            forever, and nothing in the row said anything was wrong.
        ``inf``
            ``now > inf`` is never true, so the expiry branch cannot fire.

        Neither is exotic to produce: a TTL read from configuration, divided, or
        parsed from text arrives as a float like any other. Measured 2026-08-22 -
        both were claimable a simulated thirty years later.

        A lease is single-use *and* time-bounded. Half of that is not the control.
        """
        approver_id = normalize_principal(approver_id, field="approver_id")
        ttl = ttl_seconds
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float, Decimal)):
            raise LedgerError("ttl_seconds must be a number")
        ttl = float(ttl)
        if not math.isfinite(ttl):
            raise LedgerError("ttl_seconds must be finite: a lease that cannot expire is not a lease")
        if ttl <= 0:
            raise LedgerError("ttl_seconds must be greater than zero")
        lease_id = uuid.uuid4().hex
        expires_at = self._clock() + ttl
        refusal = None
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state, scope_digest, actor_id FROM executions WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
            if row is None:
                # 실행이 없으면 이벤트를 붙일 곳도 없다(events.execution_id는 FK다).
                raise LedgerError("unknown execution")
            if row["state"] != CREATED:
                refusal = ("wrong_state", f"cannot approve from state {row['state']}")
            elif row["scope_digest"] != scope_digest:
                refusal = ("scope_mismatch",
                           "scope digest does not match the recorded intent")
            elif row["actor_id"] == approver_id:
                refusal = ("self_approval",
                           "self-approval refused: the actor that requested this execution "
                           "cannot also approve it")
            # **검사와 쓰기는 한 트랜잭션 안에 있어야 한다.** 처음 고칠 때 거절을
            # 기록하려고 두 트랜잭션으로 쪼갰다가 동시 승인 원자성을 깨뜨렸고,
            # `test_concurrent_approvals_issue_exactly_one`이 2를 세면서 잡아냈다.
            # 거절 기록만 밖에서 한다 - 그쪽은 원자적일 필요가 없다.
            if refusal is None:
                connection.execute(
                    "UPDATE executions SET state=?, lease_id=?, expires_at=?, approved_at=?"
                    " WHERE execution_id=?",
                    (APPROVED, lease_id, expires_at, self._clock(), execution_id),
                )
                self._append_event(connection, execution_id, "approved", CREATED, APPROVED,
                                   {"approver_id": approver_id, "lease_id": lease_id,
                                    "expires_at": expires_at})
        if refusal is not None:
            reason, message = refusal
            self._record_refusal(execution_id, "approve_refused", row["state"],
                                 {"reason": reason, "approver_id": approver_id})
            raise LedgerError(message)
        return lease_id

    def claim_lease(self, lease_id: str, *, scope_digest: str) -> str | None:
        """Consume a lease atomically. Returns the execution id, or None if refused.

        This is invariant 3A: the conditional UPDATE and its audit event commit in
        one transaction, and the caller must not perform the external call until
        this returns. Concurrent claimants see rowcount 0.
        """
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT execution_id, state, scope_digest, expires_at, approved_at"
                " FROM executions WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            if row is None:
                return None
            execution_id = row["execution_id"]
            if row["state"] != APPROVED:
                self._append_event(connection, execution_id, "claim_refused", row["state"], None,
                                   {"reason": "lease_already_consumed_or_invalid_state"})
                return None
            if row["scope_digest"] != scope_digest:
                self._append_event(connection, execution_id, "claim_refused", row["state"], None,
                                   {"reason": "scope_mismatch"})
                return None
            now, high_water = self._observe_clock(connection)
            if high_water is not None and now < high_water:
                self._append_event(connection, execution_id, "claim_refused", row["state"], None,
                                   {"reason": "clock_moved_backwards",
                                    "high_water": high_water, "observed_now": now})
                return None
            if row["expires_at"] is not None and now > row["expires_at"]:
                connection.execute("UPDATE executions SET state=? WHERE execution_id=?",
                                   (EXPIRED, execution_id))
                self._append_event(connection, execution_id, "claim_refused", APPROVED, EXPIRED,
                                   {"reason": "lease_expired"})
                return None
            changed = connection.execute(
                "UPDATE executions SET state=?, dispatcher_id=? WHERE execution_id=? AND state=?",
                (DISPATCHING, self.dispatcher_id, execution_id, APPROVED),
            ).rowcount
            if changed != 1:  # pragma: no cover - BEGIN IMMEDIATE holds the row
                # Unreachable: the state was read as APPROVED a few lines above,
                # inside this same `BEGIN IMMEDIATE` transaction, and the UPDATE
                # re-asserts `state=APPROVED`. No other writer can move it in
                # between - that is what the immediate write lock buys.
                #
                # Measured on 2026-08-22, when a coverage sweep left this as the
                # single unexecuted line in the package. Kept rather than
                # deleted: the compare-and-set is what makes the claim atomic,
                # and reading it without its refusal branch would suggest the
                # UPDATE is unconditional.
                return None
            self._append_event(connection, execution_id, "lease_claimed", APPROVED, DISPATCHING,
                               {"lease_id": lease_id, "dispatcher_id": self.dispatcher_id})
            return execution_id

    def revoke(self, execution_id: str, *, revoker_id: str, reason: str) -> bool:
        """Revoke an approval before dispatch. Expiry and revocation are distinct."""
        revoker_id = normalize_principal(revoker_id, field="revoker_id")
        with self._transaction() as connection:
            changed = connection.execute(
                "UPDATE executions SET state=? WHERE execution_id=? AND state IN (?,?)",
                (REVOKED, execution_id, CREATED, APPROVED),
            ).rowcount
            if changed == 1:
                self._append_event(connection, execution_id, "revoked", APPROVED, REVOKED,
                                   {"revoker_id": revoker_id, "reason": reason})
            return changed == 1

    def record_outcome(self, execution_id: str, *, state: str, evidence: Mapping[str, Any]) -> None:
        """Record a dispatch outcome. Only the core may write terminal states."""
        if state not in {SUCCEEDED, FAILED, UNKNOWN}:
            raise LedgerError(f"illegal outcome state {state}")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state FROM executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
            if row is None:
                raise LedgerError("unknown execution")
            if row["state"] != DISPATCHING:
                raise LedgerError(f"cannot record an outcome from state {row['state']}")
            connection.execute("UPDATE executions SET state=? WHERE execution_id=?",
                               (state, execution_id))
            self._append_event(connection, execution_id, "outcome", DISPATCHING, state,
                               dict(evidence))

    def reconcile(self, execution_id: str, *, new_state: str, reconciler_id: str,
                  evidence: Mapping[str, Any]) -> None:
        """Resolve an UNKNOWN outcome.

        The actor that requested the execution may not resolve it. This used to
        be a sentence in this docstring and nothing else: `reconciler_id` was a
        free string, so the agent whose call ended in UNKNOWN could declare it
        SUCCEEDED and move on - which is precisely the state that exists to stop
        an agent from deciding on its own what happened.
        """
        reconciler_id = normalize_principal(reconciler_id, field="reconciler_id")
        refusal = None
        if new_state not in {SUCCEEDED, FAILED, PERMANENTLY_UNRESOLVED}:
            raise LedgerError(f"illegal reconciliation target {new_state}")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state, actor_id FROM executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
            if row is None:
                raise LedgerError("reconciliation requires an UNKNOWN execution")
            if row["state"] != UNKNOWN:
                refusal = ("wrong_state", "reconciliation requires an UNKNOWN execution")
            elif row["actor_id"] == reconciler_id:
                refusal = ("self_reconciliation",
                           "self-reconciliation refused: the actor whose execution ended "
                           "UNKNOWN cannot be the one who declares how it ended")
            else:
                connection.execute("UPDATE executions SET state=? WHERE execution_id=?",
                                   (new_state, execution_id))
                self._append_event(connection, execution_id, "reconciled", UNKNOWN, new_state,
                                   {"reconciler_id": reconciler_id, **dict(evidence)})
        if refusal is not None:
            reason, message = refusal
            self._record_refusal(execution_id, "reconcile_refused", row["state"],
                                 {"reason": reason, "reconciler_id": reconciler_id})
            raise LedgerError(message)

    def recover_interrupted(self, *, all_dispatchers: bool = False) -> tuple[str, ...]:
        """Reclassify *this* dispatcher's interrupted dispatches as UNKNOWN.

        Never retries: the external side effect may or may not have happened.

        Scoped to this instance because it previously was not. Two workers can
        share a ledger, and a sweep over every DISPATCHING row meant one worker
        restarting declared another worker's in-flight call UNKNOWN while it was
        still running. The live worker could then no longer record its own
        result - record_outcome requires DISPATCHING - so a call that actually
        succeeded was left permanently unresolved by a process that had nothing
        to do with it.

        `all_dispatchers=True` restores the sweep for the single-process case
        and for an operator cleaning up after a worker that is definitely gone.
        It is opt-in because it is only safe when the caller knows no other
        dispatcher is live, and that is not a fact this ledger can check.
        """
        recovered: list[str] = []
        with self._transaction() as connection:
            if all_dispatchers:
                rows = connection.execute(
                    "SELECT execution_id FROM executions WHERE state=?", (DISPATCHING,)
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT execution_id FROM executions WHERE state=? AND dispatcher_id=?",
                    (DISPATCHING, self.dispatcher_id),
                ).fetchall()
            for row in rows:
                connection.execute("UPDATE executions SET state=? WHERE execution_id=?",
                                   (UNKNOWN, row["execution_id"]))
                self._append_event(connection, row["execution_id"], "recovered",
                                   DISPATCHING, UNKNOWN,
                                   {"reason": "process_interrupted_during_dispatch"})
                recovered.append(row["execution_id"])
        return tuple(recovered)

    # ------------------------------------------------------------------- reads

    def get(self, execution_id: str) -> Execution | None:
        row = self._connection.execute(
            "SELECT * FROM executions WHERE execution_id=?", (execution_id,)
        ).fetchone()
        if row is None:
            return None
        return Execution(
            row["execution_id"], row["run_id"], row["actor_id"], row["tool_id"],
            row["operation"], row["scope_digest"], row["state"], row["lease_id"],
            row["expires_at"],
        )

    def events(self, execution_id: str | None = None) -> tuple[dict[str, Any], ...]:
        if execution_id is None:
            rows = self._connection.execute(
                "SELECT * FROM events ORDER BY sequence"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM events WHERE execution_id=? ORDER BY sequence", (execution_id,)
            ).fetchall()
        return tuple(
            {**dict(row), "detail": json.loads(row["detail"])} for row in rows
        )
