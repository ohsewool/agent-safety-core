"""The benchmark's claims, re-run against the real core instead of a model of it.

Each test here corresponds to a finding from `benchmark/README.md`, but the
mechanism under test is the shipped ledger, scope binder, and access control
rather than a purpose-built arm. Ground truth is the processor's own record of
charges performed.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.access import AccessControl, AccessDenied, Principal, Role
from core.ledger import ExecutionLedger
from core.scope import PolicyBinding
from profiles.ap2.payment_guard import (
    ChargeIntent,
    OutcomeUncertain,
    PaymentGuard,
    PaymentRefused,
)

POLICY = PolicyBinding.from_document("payments", "3", {"charge": "require_approval"})
CONTEXT = {"code_revision": "abc123", "tool_version": "1.0.0",
           "execution_identity": "svc-agent"}


class Processor:
    """Records what actually happened, and can be made to fail specifically."""

    def __init__(self, *, fail_after_charging=False, decline=False, lookup_fails=False):
        self.charges: list[dict] = []
        self.fail_after_charging = fail_after_charging
        self.decline = decline
        self.lookup_fails = lookup_fails

    def __call__(self, *, intent_id, amount, currency, payee_id, idempotency_key):
        if self.decline:
            return {"status": "failed", "reason": "insufficient_funds"}
        existing = next((c for c in self.charges if c["key"] == idempotency_key), None)
        if existing is None:
            self.charges.append({"key": idempotency_key, "intent_id": intent_id,
                                 "amount": amount, "payee_id": payee_id})
        if self.fail_after_charging:
            raise ConnectionError("connection lost after the request was sent")
        return {"status": "succeeded", "charge_id": f"ch_{len(self.charges)}"}

    def lookup(self, intent_id):
        if self.lookup_fails:
            raise ConnectionError("processor unavailable")
        found = [c for c in self.charges if c["intent_id"] == intent_id]
        return {"status": "succeeded"} if found else {"status": "not_found"}

    def count_for(self, intent_id):
        return sum(1 for c in self.charges if c["intent_id"] == intent_id)


@pytest.fixture
def access():
    return AccessControl([
        Principal.with_roles("agent-1", Role.OPERATOR),
        Principal.with_roles("human-1", Role.APPROVER),
        Principal.with_roles("reconciler-1", Role.RECONCILER),
    ])


@pytest.fixture
def build(tmp_path, access):
    created = []

    def make(processor, *, with_lookup=True):
        ledger = ExecutionLedger(str(tmp_path / f"ledger{len(created)}.db"))
        created.append(ledger)
        return PaymentGuard(
            ledger, access=access, policy=POLICY, context=CONTEXT,
            processor=processor,
            lookup=processor.lookup if with_lookup else None,
        )

    yield make
    for ledger in created:
        ledger.close()


def intent(amount=1000, payee="merchant-1"):
    return ChargeIntent(run_id="run-1", actor_id="agent-1", payee_id=payee,
                        amount=amount, currency="KRW")


def approved(guard, charge):
    execution_id = guard.propose(charge)
    lease = guard.approve(execution_id, charge, approver_id="human-1")
    return execution_id, lease


class TestHappyPath:
    def test_an_approved_charge_happens_once(self, build):
        processor = Processor()
        guard = build(processor)
        charge = intent()
        _, lease = approved(guard, charge)
        result = guard.dispatch(lease, charge, actor_id="agent-1")
        assert result["status"] == "succeeded"
        assert processor.count_for(result["execution_id"]) == 1
        assert guard.state_of(result["execution_id"]) == "SUCCEEDED"

    def test_nothing_is_charged_before_approval(self, build):
        """The proposal alone must not move money."""
        processor = Processor()
        guard = build(processor)
        guard.propose(intent())
        assert processor.charges == []


class TestScopeBinding:
    def test_a_different_amount_cannot_use_the_approval(self, build):
        """Approving 1000 does not approve 10000."""
        processor = Processor()
        guard = build(processor)
        _, lease = approved(guard, intent(amount=1000))
        with pytest.raises(PaymentRefused):
            guard.dispatch(lease, intent(amount=10000), actor_id="agent-1")
        assert processor.charges == []

    def test_a_different_payee_cannot_use_the_approval(self, build):
        processor = Processor()
        guard = build(processor)
        _, lease = approved(guard, intent(payee="merchant-1"))
        with pytest.raises(PaymentRefused):
            guard.dispatch(lease, intent(payee="attacker-1"), actor_id="agent-1")
        assert processor.charges == []

    def test_a_changed_code_revision_invalidates_the_approval(self, tmp_path, access):
        """Approved under one build; a different build is a different execution."""
        processor = Processor()
        ledger = ExecutionLedger(str(tmp_path / "ledger.db"))
        try:
            guard = PaymentGuard(ledger, access=access, policy=POLICY, context=CONTEXT,
                                 processor=processor, lookup=processor.lookup)
            charge = intent()
            _, lease = approved(guard, charge)

            moved = PaymentGuard(ledger, access=access, policy=POLICY,
                                 context={**CONTEXT, "code_revision": "def456"},
                                 processor=processor, lookup=processor.lookup)
            with pytest.raises(PaymentRefused):
                moved.dispatch(lease, charge, actor_id="agent-1")
            assert processor.charges == []
        finally:
            ledger.close()

    def test_a_rewritten_policy_invalidates_the_approval(self, tmp_path, access):
        """Same version string, different content: the approval no longer applies."""
        processor = Processor()
        ledger = ExecutionLedger(str(tmp_path / "ledger.db"))
        try:
            guard = PaymentGuard(ledger, access=access, policy=POLICY, context=CONTEXT,
                                 processor=processor, lookup=processor.lookup)
            charge = intent()
            _, lease = approved(guard, charge)

            weakened = PolicyBinding.from_document("payments", "3", {"charge": "allow"})
            after = PaymentGuard(ledger, access=access, policy=weakened, context=CONTEXT,
                                 processor=processor, lookup=processor.lookup)
            with pytest.raises(PaymentRefused):
                after.dispatch(lease, charge, actor_id="agent-1")
        finally:
            ledger.close()


class TestSingleUse:
    def test_a_lease_cannot_be_spent_twice(self, build):
        processor = Processor()
        guard = build(processor)
        charge = intent()
        _, lease = approved(guard, charge)
        first = guard.dispatch(lease, charge, actor_id="agent-1")
        with pytest.raises(PaymentRefused):
            guard.dispatch(lease, charge, actor_id="agent-1")
        assert processor.count_for(first["execution_id"]) == 1

    def test_a_revoked_approval_cannot_be_spent(self, build, tmp_path):
        processor = Processor()
        guard = build(processor)
        charge = intent()
        execution_id, lease = approved(guard, charge)
        guard._ledger.revoke(execution_id, revoker_id="human-1", reason="risk found")
        with pytest.raises(PaymentRefused):
            guard.dispatch(lease, charge, actor_id="agent-1")
        assert processor.charges == []


class TestUncertainOutcomes:
    def test_a_lost_response_is_unknown_not_failed(self, build):
        """The money may already have moved; calling it a failure invites a retry."""
        processor = Processor(fail_after_charging=True)
        guard = build(processor)
        charge = intent()
        _, lease = approved(guard, charge)
        with pytest.raises(OutcomeUncertain) as error:
            guard.dispatch(lease, charge, actor_id="agent-1")
        assert guard.state_of(error.value.execution_id) == "UNKNOWN"
        assert processor.count_for(error.value.execution_id) == 1

    def test_reconciliation_resolves_an_unknown_to_the_truth(self, build):
        processor = Processor(fail_after_charging=True)
        guard = build(processor)
        charge = intent()
        _, lease = approved(guard, charge)
        with pytest.raises(OutcomeUncertain) as error:
            guard.dispatch(lease, charge, actor_id="agent-1")
        execution_id = error.value.execution_id
        assert guard.reconcile(execution_id, reconciler_id="reconciler-1") == "SUCCEEDED"
        assert processor.count_for(execution_id) == 1  # still exactly one charge

    def test_without_a_lookup_the_outcome_stays_unresolved(self, build):
        """Stated rather than guessed: no way to check means no final answer."""
        processor = Processor(fail_after_charging=True)
        guard = build(processor, with_lookup=False)
        charge = intent()
        _, lease = approved(guard, charge)
        with pytest.raises(OutcomeUncertain) as error:
            guard.dispatch(lease, charge, actor_id="agent-1")
        resolved = guard.reconcile(error.value.execution_id, reconciler_id="reconciler-1")
        assert resolved == "PERMANENTLY_UNRESOLVED"

    def test_a_failed_lookup_also_terminates_honestly(self, build):
        processor = Processor(fail_after_charging=True, lookup_fails=True)
        guard = build(processor)
        charge = intent()
        _, lease = approved(guard, charge)
        with pytest.raises(OutcomeUncertain) as error:
            guard.dispatch(lease, charge, actor_id="agent-1")
        assert guard.reconcile(error.value.execution_id,
                               reconciler_id="reconciler-1") == "PERMANENTLY_UNRESOLVED"

    def test_a_declined_charge_is_a_failure_not_an_unknown(self, build):
        processor = Processor(decline=True)
        guard = build(processor)
        charge = intent()
        _, lease = approved(guard, charge)
        result = guard.dispatch(lease, charge, actor_id="agent-1")
        assert guard.state_of(result["execution_id"]) == "FAILED"


class TestCrashRecovery:
    def test_an_interrupted_dispatch_recovers_to_unknown(self, tmp_path, access):
        """A crash between claiming and recording must not look like it never happened."""
        processor = Processor()
        path = str(tmp_path / "ledger.db")
        first = ExecutionLedger(path, dispatcher_id="payments-worker")
        guard = PaymentGuard(first, access=access, policy=POLICY, context=CONTEXT,
                             processor=processor, lookup=processor.lookup)
        charge = intent()
        execution_id, lease = approved(guard, charge)
        first.claim_lease(lease, scope_digest=charge.scope(policy=POLICY,
                                                           context=CONTEXT).digest())
        first.close()  # process dies mid-dispatch

        # Same dispatcher identity: recovery is scoped so that one worker
        # restarting cannot declare another worker's live call UNKNOWN.
        second = ExecutionLedger(path, dispatcher_id="payments-worker")
        try:
            restarted = PaymentGuard(second, access=access, policy=POLICY, context=CONTEXT,
                                     processor=processor, lookup=processor.lookup)
            assert restarted.recover() == (execution_id,)
            assert restarted.state_of(execution_id) == "UNKNOWN"
            with pytest.raises(PaymentRefused):
                restarted.dispatch(lease, charge, actor_id="agent-1")
        finally:
            second.close()


class TestAuthorisation:
    def test_an_agent_cannot_approve_its_own_charge(self, build):
        guard = build(Processor())
        charge = intent()
        execution_id = guard.propose(charge)
        with pytest.raises(AccessDenied):
            guard.approve(execution_id, charge, approver_id="agent-1")

    def test_an_approver_cannot_dispatch(self, build):
        guard = build(Processor())
        charge = intent()
        _, lease = approved(guard, charge)
        with pytest.raises(AccessDenied):
            guard.dispatch(lease, charge, actor_id="human-1")

    def test_only_a_reconciler_resolves_unknowns(self, build):
        processor = Processor(fail_after_charging=True)
        guard = build(processor)
        charge = intent()
        _, lease = approved(guard, charge)
        with pytest.raises(OutcomeUncertain) as error:
            guard.dispatch(lease, charge, actor_id="agent-1")
        with pytest.raises(AccessDenied):
            guard.reconcile(error.value.execution_id, reconciler_id="agent-1")


class TestEvidence:
    def test_the_whole_sequence_is_recorded_in_order(self, build):
        processor = Processor()
        guard = build(processor)
        charge = intent()
        execution_id, lease = approved(guard, charge)
        guard.dispatch(lease, charge, actor_id="agent-1")
        kinds = [event["kind"] for event in guard._ledger.events(execution_id)]
        assert kinds == ["created", "approved", "lease_claimed", "outcome"]

    def test_a_refused_dispatch_leaves_a_reason_behind(self, build):
        processor = Processor()
        guard = build(processor)
        execution_id, lease = approved(guard, intent(amount=1000))
        with pytest.raises(PaymentRefused):
            guard.dispatch(lease, intent(amount=9999), actor_id="agent-1")
        reasons = [event["detail"].get("reason")
                   for event in guard._ledger.events(execution_id)
                   if event["kind"] == "claim_refused"]
        assert "scope_mismatch" in reasons
