"""Second adversarial pass over the post-ADR-002 ledger.

The first red team judged the design NO and ADR-002 answered it. These are
attacks on what was built afterwards. Four were attempted; all four landed.

    self-approval          the agent that requested an execution approved it
    self-reconciliation    the agent whose call ended UNKNOWN declared it SUCCEEDED
    clock rollback         a lapsed approval became claimable again
    cross-worker recovery  one worker declared another's live call UNKNOWN

The first two share a cause worth naming, because this project has met it
before. `core/access.py` defines EXECUTION_RECONCILE, a RECONCILER role and a
separation-of-duties helper - and `core/ledger.py` never imported any of it.
The docstring said agents may not reconcile; nothing checked. That is the same
defect `retention.py` was written to fix in its own area: "a label that enforces
nothing is worse than no label: it reads like a control in an audit and behaves
like a comment." The control existed and was not wired up.

Each test below fails on the code as it stood before this file was written.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ledger import ExecutionLedger, LedgerError

SCOPE = "scope-digest"


@pytest.fixture
def ledger(tmp_path):
    item = ExecutionLedger(str(tmp_path / "core.db"))
    yield item
    item.close()


def requested(ledger, actor="agent-1"):
    return ledger.create(run_id="run", actor_id=actor, tool_id="tool",
                         operation="write", scope_digest=SCOPE)


def approved(ledger, actor="agent-1", approver="human-1", ttl=60.0):
    execution_id = requested(ledger, actor)
    lease = ledger.approve(execution_id, approver_id=approver,
                           scope_digest=SCOPE, ttl_seconds=ttl)
    return execution_id, lease


class TestSelfApproval:
    """An approval by the requester is not a second pair of eyes."""

    def test_the_requester_cannot_approve_its_own_execution(self, ledger):
        execution_id = requested(ledger, actor="agent-1")
        with pytest.raises(LedgerError, match="self-approval"):
            ledger.approve(execution_id, approver_id="agent-1",
                           scope_digest=SCOPE, ttl_seconds=60)

    def test_a_refused_self_approval_issues_no_lease(self, ledger):
        execution_id = requested(ledger, actor="agent-1")
        with pytest.raises(LedgerError):
            ledger.approve(execution_id, approver_id="agent-1",
                           scope_digest=SCOPE, ttl_seconds=60)
        assert ledger.get(execution_id).lease_id is None
        assert ledger.get(execution_id).state == "CREATED"

    def test_a_different_approver_still_works(self, ledger):
        """The check must not break the case it exists to protect."""
        execution_id, lease = approved(ledger, actor="agent-1", approver="human-1")
        assert lease
        assert ledger.get(execution_id).state == "APPROVED"


class TestSelfReconciliation:
    """UNKNOWN exists so the agent does not get to decide what happened."""

    def _unknown(self, ledger, actor="agent-1"):
        execution_id, lease = approved(ledger, actor=actor)
        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state="UNKNOWN", evidence={})
        return execution_id

    def test_the_actor_cannot_resolve_its_own_unknown(self, ledger):
        execution_id = self._unknown(ledger, actor="agent-1")
        with pytest.raises(LedgerError, match="self-reconciliation"):
            ledger.reconcile(execution_id, new_state="SUCCEEDED",
                             reconciler_id="agent-1", evidence={})

    def test_a_refused_reconciliation_leaves_the_state_unknown(self, ledger):
        execution_id = self._unknown(ledger, actor="agent-1")
        with pytest.raises(LedgerError):
            ledger.reconcile(execution_id, new_state="SUCCEEDED",
                             reconciler_id="agent-1", evidence={})
        assert ledger.get(execution_id).state == "UNKNOWN"

    def test_an_independent_reconciler_may_resolve_it(self, ledger):
        execution_id = self._unknown(ledger, actor="agent-1")
        ledger.reconcile(execution_id, new_state="SUCCEEDED",
                         reconciler_id="operator-1", evidence={"checked": True})
        assert ledger.get(execution_id).state == "SUCCEEDED"


class TestClockRollback:
    """A TTL bounds anything only while the clock moves forward.

    What is detectable here has a limit worth stating. The ledger can only
    contradict a clock reading against times it has itself observed. If the
    clock runs past a deadline and returns while the ledger is completely idle,
    nothing recorded it and no check can recover the fact - the information does
    not exist. A first attempt at these tests demanded exactly that and was
    wrong to.

    A live ledger is doing other work, so the forward excursion is witnessed by
    whatever else it handles. That is the case these cover.
    """

    def test_a_lapsed_approval_does_not_revive_when_the_clock_goes_back(self, tmp_path):
        now = [1000.0]
        ledger = ExecutionLedger(str(tmp_path / "clock.db"), clock=lambda: now[0])
        _, lease = approved(ledger, ttl=10)

        now[0] = 5000.0
        approved(ledger)         # unrelated traffic: the ledger witnesses 5000
        now[0] = 1005.0          # NTP correction, or a restored VM snapshot

        assert ledger.claim_lease(lease, scope_digest=SCOPE) is None
        ledger.close()

    def test_the_refusal_names_the_clock_rather_than_the_lease(self, tmp_path):
        """"Expired" and "your clock is wrong" need different responses."""
        now = [1000.0]
        ledger = ExecutionLedger(str(tmp_path / "clock.db"), clock=lambda: now[0])
        execution_id, lease = approved(ledger, ttl=10)
        now[0] = 900.0
        ledger.claim_lease(lease, scope_digest=SCOPE)
        reasons = [event["detail"].get("reason") for event in ledger.events(execution_id)]
        assert "clock_moved_backwards" in reasons
        ledger.close()

    def test_an_unwitnessed_excursion_is_documented_as_undetectable(self, tmp_path):
        """Pins the limit rather than pretending it is covered.

        No ledger activity between the jump forward and the jump back means no
        record of the excursion. The claim succeeds. This is a statement about
        what the mechanism can see, not an endorsement.
        """
        now = [1000.0]
        ledger = ExecutionLedger(str(tmp_path / "blind.db"), clock=lambda: now[0])
        _, lease = approved(ledger, ttl=10)
        now[0] = 5000.0          # nothing happens here, so nothing records it
        now[0] = 1005.0
        assert ledger.claim_lease(lease, scope_digest=SCOPE) is not None
        ledger.close()

    def test_an_ordinary_expiry_is_still_an_expiry(self, tmp_path):
        now = [1000.0]
        ledger = ExecutionLedger(str(tmp_path / "clock.db"), clock=lambda: now[0])
        execution_id, lease = approved(ledger, ttl=10)
        now[0] = 1011.0
        assert ledger.claim_lease(lease, scope_digest=SCOPE) is None
        assert ledger.get(execution_id).state == "EXPIRED"
        ledger.close()


class TestCrossWorkerRecovery:
    """Recovery must not reach into a dispatch that is still running."""

    def test_one_worker_restarting_does_not_disturb_another(self, tmp_path):
        path = str(tmp_path / "shared.db")
        worker_one = ExecutionLedger(path, dispatcher_id="worker-1")
        worker_two = ExecutionLedger(path, dispatcher_id="worker-2")

        execution_id, lease = approved(worker_one)
        worker_one.claim_lease(lease, scope_digest=SCOPE)   # now dispatching

        assert worker_two.recover_interrupted() == ()
        assert worker_one.get(execution_id).state == "DISPATCHING"
        worker_one.close(); worker_two.close()

    def test_the_live_worker_can_still_record_its_result(self, tmp_path):
        """The damage was not the label - it was losing a real outcome.

        record_outcome requires DISPATCHING, so a sweep by another process left
        a call that actually succeeded with no way to say so.
        """
        path = str(tmp_path / "shared.db")
        worker_one = ExecutionLedger(path, dispatcher_id="worker-1")
        worker_two = ExecutionLedger(path, dispatcher_id="worker-2")

        execution_id, lease = approved(worker_one)
        worker_one.claim_lease(lease, scope_digest=SCOPE)
        worker_two.recover_interrupted()

        worker_one.record_outcome(execution_id, state="SUCCEEDED", evidence={"ok": True})
        assert worker_one.get(execution_id).state == "SUCCEEDED"
        worker_one.close(); worker_two.close()

    def test_a_worker_recovers_its_own_interrupted_dispatch(self, tmp_path):
        """Scoping must not cost the recovery that matters."""
        path = str(tmp_path / "restart.db")
        before = ExecutionLedger(path, dispatcher_id="worker-1")
        execution_id, lease = approved(before)
        before.claim_lease(lease, scope_digest=SCOPE)
        before.close()

        after = ExecutionLedger(path, dispatcher_id="worker-1")
        assert after.recover_interrupted() == (execution_id,)
        assert after.get(execution_id).state == "UNKNOWN"
        after.close()

    def test_an_operator_can_still_sweep_everything_deliberately(self, tmp_path):
        """Opt-in, because no ledger can verify that no dispatcher is live."""
        path = str(tmp_path / "sweep.db")
        dead = ExecutionLedger(path, dispatcher_id="worker-gone")
        execution_id, lease = approved(dead)
        dead.claim_lease(lease, scope_digest=SCOPE)
        dead.close()

        operator = ExecutionLedger(path, dispatcher_id="operator")
        assert operator.recover_interrupted(all_dispatchers=True) == (execution_id,)
        operator.close()

    def test_recovery_never_retries(self, tmp_path):
        """UNKNOWN, not APPROVED: the side effect may already have happened."""
        path = str(tmp_path / "noretry.db")
        ledger = ExecutionLedger(path, dispatcher_id="worker-1")
        execution_id, lease = approved(ledger)
        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.recover_interrupted()

        assert ledger.get(execution_id).state == "UNKNOWN"
        assert ledger.claim_lease(lease, scope_digest=SCOPE) is None
        ledger.close()
