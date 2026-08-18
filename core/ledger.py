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
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
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
"""


class LedgerError(RuntimeError):
    """Raised when a caller attempts an illegal transition."""


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

    def __init__(self, path: str, *, clock=None) -> None:
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

    def _append_event(
        self,
        connection: sqlite3.Connection,
        execution_id: str,
        kind: str,
        from_state: str | None,
        to_state: str | None,
        detail: Mapping[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO events (execution_id, kind, from_state, to_state, detail, recorded_at)"
            " VALUES (?,?,?,?,?,?)",
            (
                execution_id,
                kind,
                from_state,
                to_state,
                json.dumps(detail, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                self._clock(),
            ),
        )

    # ------------------------------------------------------------------ writes

    def create(self, *, run_id: str, actor_id: str, tool_id: str, operation: str,
               scope_digest: str) -> str:
        """Record an intent. The core issues the identity; callers cannot supply it."""
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
        """Bind an approval to an exact scope and issue a single-use lease."""
        lease_id = uuid.uuid4().hex
        expires_at = self._clock() + ttl_seconds
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state, scope_digest FROM executions WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("unknown execution")
            if row["state"] != CREATED:
                raise LedgerError(f"cannot approve from state {row['state']}")
            if row["scope_digest"] != scope_digest:
                raise LedgerError("scope digest does not match the recorded intent")
            connection.execute(
                "UPDATE executions SET state=?, lease_id=?, expires_at=? WHERE execution_id=?",
                (APPROVED, lease_id, expires_at, execution_id),
            )
            self._append_event(connection, execution_id, "approved", CREATED, APPROVED,
                               {"approver_id": approver_id, "lease_id": lease_id,
                                "expires_at": expires_at})
        return lease_id

    def claim_lease(self, lease_id: str, *, scope_digest: str) -> str | None:
        """Consume a lease atomically. Returns the execution id, or None if refused.

        This is invariant 3A: the conditional UPDATE and its audit event commit in
        one transaction, and the caller must not perform the external call until
        this returns. Concurrent claimants see rowcount 0.
        """
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT execution_id, state, scope_digest, expires_at FROM executions"
                " WHERE lease_id=?",
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
            if row["expires_at"] is not None and self._clock() > row["expires_at"]:
                connection.execute("UPDATE executions SET state=? WHERE execution_id=?",
                                   (EXPIRED, execution_id))
                self._append_event(connection, execution_id, "claim_refused", APPROVED, EXPIRED,
                                   {"reason": "lease_expired"})
                return None
            changed = connection.execute(
                "UPDATE executions SET state=? WHERE execution_id=? AND state=?",
                (DISPATCHING, execution_id, APPROVED),
            ).rowcount
            if changed != 1:
                return None
            self._append_event(connection, execution_id, "lease_claimed", APPROVED, DISPATCHING,
                               {"lease_id": lease_id})
            return execution_id

    def revoke(self, execution_id: str, *, revoker_id: str, reason: str) -> bool:
        """Revoke an approval before dispatch. Expiry and revocation are distinct."""
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
        """Resolve an UNKNOWN outcome. Agents may not perform this transition."""
        if new_state not in {SUCCEEDED, FAILED, PERMANENTLY_UNRESOLVED}:
            raise LedgerError(f"illegal reconciliation target {new_state}")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state FROM executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
            if row is None or row["state"] != UNKNOWN:
                raise LedgerError("reconciliation requires an UNKNOWN execution")
            connection.execute("UPDATE executions SET state=? WHERE execution_id=?",
                               (new_state, execution_id))
            self._append_event(connection, execution_id, "reconciled", UNKNOWN, new_state,
                               {"reconciler_id": reconciler_id, **dict(evidence)})

    def recover_interrupted(self) -> tuple[str, ...]:
        """Reclassify executions interrupted mid-dispatch as UNKNOWN (never retry)."""
        recovered: list[str] = []
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT execution_id FROM executions WHERE state=?", (DISPATCHING,)
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
