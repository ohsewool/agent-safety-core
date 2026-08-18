"""Arms B–E: one mechanism at a time, then all of them."""

from __future__ import annotations

from typing import Any

from benchmark.arms.base import Arm, ArmResult
from benchmark.harness.world import DispatchInterrupted, Fault, PaymentWorld, Scenario


class ScopeBoundArm(Arm):
    """B — the approval names the exact call; anything else is refused."""

    name = "B"
    description = "A + exact scope binding"
    binds_scope = True

    def _authorize(self, result: ArmResult, approved: dict[str, Any],
                   requested: dict[str, Any]) -> bool:
        if approved != requested:
            result.scope_violations_blocked += 1
            return False
        return True


class LeasedArm(Arm):
    """C — the approval is spendable exactly once."""

    name = "C"
    description = "A + single-use / expiring lease"
    uses_lease = True

    def __init__(self, world: PaymentWorld) -> None:
        super().__init__(world)
        self._lease_available = True

    def _consume(self, result: ArmResult) -> bool:
        if not self._lease_available:
            return False
        self._lease_available = False
        return True

    def _idempotency_key(self, intent: dict[str, Any], attempt: int) -> str | None:
        # The lease identifies the authorised dispatch, so it is a stable key.
        return f"lease:{intent['intent_id']}"


class UncertaintyAwareArm(Arm):
    """D — an unobserved outcome is UNKNOWN, and UNKNOWN is not a retry signal."""

    name = "D"
    description = "A + explicit UNKNOWN_OUTCOME + reconciliation before retry"
    tracks_unknown = True

    def _on_interrupted(self, result: ArmResult, fault: Fault, intent_id: str,
                        attempt: int, scenario: Scenario) -> bool:
        result.log("unknown_outcome", fault=fault.value, attempt=attempt)
        try:
            observed = self.world.lookup(intent_id)
        except DispatchInterrupted:
            result.final_state = "PERMANENTLY_UNRESOLVED"
            result.log("reconcile_unavailable", attempt=attempt)
            return False

        result.reconciliations += 1
        if observed["status"] == "succeeded":
            # It already happened. Retrying would charge a second time.
            result.final_state = "SUCCEEDED"
            result.log("reconciled", outcome="succeeded", charge_id=observed["charge_id"])
            return False
        result.log("reconciled", outcome="not_found")
        return True  # provably did not happen: retrying is safe


class FullArm(UncertaintyAwareArm):
    """E — scope binding, lease, uncertainty handling, and evidence together."""

    name = "E"
    description = "B + C + D + verifiable evidence"
    binds_scope = True
    uses_lease = True

    def __init__(self, world: PaymentWorld) -> None:
        super().__init__(world)
        self._lease_available = True
        self._reconciled_authorization = False

    def _authorize(self, result: ArmResult, approved: dict[str, Any],
                   requested: dict[str, Any]) -> bool:
        if approved != requested:
            result.scope_violations_blocked += 1
            return False
        return True

    def _consume(self, result: ArmResult) -> bool:
        if not self._lease_available:
            return False
        self._lease_available = False
        return True

    def _on_interrupted(self, result: ArmResult, fault: Fault, intent_id: str,
                        attempt: int, scenario: Scenario) -> bool:
        may_retry = super()._on_interrupted(result, fault, intent_id, attempt, scenario)
        if not may_retry:
            return False
        # Invariant 3B: a retry needs a fresh authorisation, issued only because
        # reconciliation proved the effect did not happen.
        self._lease_available = True
        self._reconciled_authorization = True
        return True

    def _idempotency_key(self, intent: dict[str, Any], attempt: int) -> str | None:
        return f"lease:{intent['intent_id']}"


class VerifyingArm(FullArm):
    """F — E, but uncertainty is resolved by observing the world.

    E asks the processor what happened. When the processor is the thing that
    broke, that question travels the same broken path the response did. F checks
    a postcondition instead — is the charge present in the ledger the world keeps
    — which can be answered from somewhere the failure did not reach.

    Grounded in arXiv:2608.02645, whose measured result is that verification
    rather than retry policy is what reduces duplicate actions.
    """

    name = "F"
    description = "E + postcondition verification on an independent channel"

    def _on_interrupted(self, result: ArmResult, fault: Fault, intent_id: str,
                        attempt: int, scenario: Scenario) -> bool:
        result.log("unknown_outcome", fault=fault.value, attempt=attempt)

        # The independent channel: the world's own record of charges, which is
        # readable even when the processor's lookup endpoint is not.
        effect_present = self.world.charge_count(intent_id) > 0
        result.reconciliations += 1
        result.log("postcondition", observed="present" if effect_present else "absent")

        if effect_present:
            result.final_state = "SUCCEEDED"
            return False
        self._lease_available = True
        return True


ARMS = (Arm, ScopeBoundArm, LeasedArm, UncertaintyAwareArm, FullArm, VerifyingArm)
