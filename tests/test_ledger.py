"""Regression tests for the findings that produced the NO(재설계) verdict.

Each test names the finding it closes. These are the ADR-002 §9 exit criteria
that were provable at the ledger layer; the rest (scope content, policy digest,
resource identity) land with the M1 scope binder.
"""

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ledger import (  # noqa: E402
    APPROVED,
    DISPATCHING,
    EXPIRED,
    PERMANENTLY_UNRESOLVED,
    REVOKED,
    SUCCEEDED,
    UNKNOWN,
    ExecutionLedger,
    LedgerError,
)

SCOPE = "a" * 64


@pytest.fixture
def ledger(tmp_path):
    instance = ExecutionLedger(str(tmp_path / "ledger.db"))
    yield instance
    instance.close()


def approved_lease(ledger, *, ttl=60.0, scope=SCOPE):
    execution_id = ledger.create(
        run_id="run-1", actor_id="agent-1", tool_id="payments",
        operation="transfer", scope_digest=scope,
    )
    lease_id = ledger.approve(
        execution_id, approver_id="human-1", scope_digest=scope, ttl_seconds=ttl
    )
    return execution_id, lease_id


class TestF02LeaseAtomicity:
    """F-02: check→consume must be atomic, even across concurrent workers."""

    def test_second_claim_is_refused(self, ledger):
        _, lease_id = approved_lease(ledger)
        assert ledger.claim_lease(lease_id, scope_digest=SCOPE) is not None
        assert ledger.claim_lease(lease_id, scope_digest=SCOPE) is None

    def test_concurrent_claims_yield_exactly_one_winner(self, tmp_path):
        """The regression test ADR-002 §9 row 1 demands."""
        path = str(tmp_path / "race.db")
        setup = ExecutionLedger(path)
        _, lease_id = approved_lease(setup)
        setup.close()

        winners: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(24)

        def worker():
            own = ExecutionLedger(path)
            try:
                barrier.wait()
                for _ in range(40):  # retry on SQLITE_BUSY, do not lose the race
                    try:
                        claimed = own.claim_lease(lease_id, scope_digest=SCOPE)
                        break
                    except Exception:
                        continue
                else:
                    claimed = None
                if claimed is not None:
                    with lock:
                        winners.append(claimed)
            finally:
                own.close()

        threads = [threading.Thread(target=worker) for _ in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(winners) == 1, f"expected exactly one dispatch, got {len(winners)}"

    def test_expired_lease_is_refused_and_marked(self, tmp_path):
        now = [1000.0]
        instance = ExecutionLedger(str(tmp_path / "ttl.db"), clock=lambda: now[0])
        execution_id, lease_id = approved_lease(instance, ttl=10.0)
        now[0] = 1011.0
        assert instance.claim_lease(lease_id, scope_digest=SCOPE) is None
        assert instance.get(execution_id).state == EXPIRED
        instance.close()


class TestF03CrossStoreAtomicity:
    """F-03: a state transition and its evidence commit together or not at all."""

    def test_claim_records_evidence_in_the_same_commit(self, ledger):
        execution_id, lease_id = approved_lease(ledger)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)
        kinds = [event["kind"] for event in ledger.events(execution_id)]
        assert kinds == ["created", "approved", "lease_claimed"]
        assert ledger.get(execution_id).state == DISPATCHING

    def test_no_consumed_lease_without_evidence(self, ledger):
        """Every execution that left APPROVED has an event explaining why."""
        execution_id, lease_id = approved_lease(ledger)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)  # refused
        events = ledger.events(execution_id)
        assert any(event["kind"] == "claim_refused" for event in events)

    def test_interrupted_dispatch_recovers_to_unknown_not_retry(self, tmp_path):
        """Crash mid-dispatch: the row must become UNKNOWN, never re-dispatchable."""
        path = str(tmp_path / "crash.db")
        first = ExecutionLedger(path, dispatcher_id="worker-1")
        execution_id, lease_id = approved_lease(first)
        first.claim_lease(lease_id, scope_digest=SCOPE)
        first.close()  # simulate process death while DISPATCHING

        # The same worker coming back, not a different one: recovery is scoped to
        # a dispatcher so a live worker's in-flight call is never swept up.
        restarted = ExecutionLedger(path, dispatcher_id="worker-1")
        assert restarted.recover_interrupted() == (execution_id,)
        assert restarted.get(execution_id).state == UNKNOWN
        # The lease cannot be reused to dispatch again (invariant 3A).
        assert restarted.claim_lease(lease_id, scope_digest=SCOPE) is None
        restarted.close()


class TestScopeAndApprovalLifecycle:
    def test_scope_mismatch_refuses_claim(self, ledger):
        """F-01/F-06/F-07 at the ledger layer: a different digest cannot claim."""
        _, lease_id = approved_lease(ledger)
        assert ledger.claim_lease(lease_id, scope_digest="b" * 64) is None

    def test_approval_requires_matching_intent_scope(self, ledger):
        execution_id = ledger.create(
            run_id="r", actor_id="a", tool_id="t", operation="o", scope_digest=SCOPE
        )
        with pytest.raises(LedgerError):
            ledger.approve(execution_id, approver_id="h", scope_digest="c" * 64, ttl_seconds=60)

    def test_revoked_approval_cannot_be_claimed(self, ledger):
        """F-08: revocation is distinct from expiry and beats a live TTL."""
        execution_id, lease_id = approved_lease(ledger, ttl=3600.0)
        assert ledger.revoke(execution_id, revoker_id="human-1", reason="risk found")
        assert ledger.get(execution_id).state == REVOKED
        assert ledger.claim_lease(lease_id, scope_digest=SCOPE) is None

    def test_revocation_after_dispatch_is_refused(self, ledger):
        execution_id, lease_id = approved_lease(ledger)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)
        assert ledger.revoke(execution_id, revoker_id="h", reason="too late") is False


class TestF09ReconciliationAuthority:
    """F-09: who may resolve UNKNOWN, and on what evidence."""

    def test_unknown_requires_reconciliation_before_final_state(self, ledger):
        execution_id, lease_id = approved_lease(ledger)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state=UNKNOWN, evidence={"reason": "timeout"})
        ledger.reconcile(
            execution_id, new_state=SUCCEEDED, reconciler_id="reconciler-1",
            evidence={"external_lookup_target": "psp:tx/1", "evidence_digest": "d" * 64},
        )
        assert ledger.get(execution_id).state == SUCCEEDED
        last = ledger.events(execution_id)[-1]
        assert last["kind"] == "reconciled"
        assert last["detail"]["reconciler_id"] == "reconciler-1"

    def test_reconcile_only_applies_to_unknown(self, ledger):
        execution_id, lease_id = approved_lease(ledger)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state=SUCCEEDED, evidence={})
        with pytest.raises(LedgerError):
            ledger.reconcile(execution_id, new_state=SUCCEEDED, reconciler_id="r", evidence={})

    def test_unresolvable_outcome_terminates_honestly(self, ledger):
        execution_id, lease_id = approved_lease(ledger)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state=UNKNOWN, evidence={"reason": "no response"})
        ledger.reconcile(
            execution_id, new_state=PERMANENTLY_UNRESOLVED, reconciler_id="r",
            evidence={"reason": "external system offers no lookup"},
        )
        assert ledger.get(execution_id).state == PERMANENTLY_UNRESOLVED


class TestF10Provenance:
    """F-10: the core issues identity and sequence; callers cannot forge them."""

    def test_sequence_is_issued_by_the_store(self, ledger):
        approved_lease(ledger)
        approved_lease(ledger)
        sequences = [event["sequence"] for event in ledger.events()]
        assert sequences == sorted(sequences)
        assert len(set(sequences)) == len(sequences)

    def test_outcome_requires_dispatching_state(self, ledger):
        """An agent cannot declare success for work that was never dispatched."""
        execution_id, _ = approved_lease(ledger)
        with pytest.raises(LedgerError):
            ledger.record_outcome(execution_id, state=SUCCEEDED, evidence={})

    def test_illegal_outcome_state_is_rejected(self, ledger):
        execution_id, lease_id = approved_lease(ledger)
        ledger.claim_lease(lease_id, scope_digest=SCOPE)
        with pytest.raises(LedgerError):
            ledger.record_outcome(execution_id, state=APPROVED, evidence={})
