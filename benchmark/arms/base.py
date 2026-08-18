"""The five arms of the ablation (ADR-002 / verification prompt §10).

Each arm is a complete agent runtime that decides how to dispatch a payment and
what to do when an attempt is interrupted.  They differ only in which mechanism
is enabled, so a difference in outcome is attributable to that mechanism:

A  ordinary approval + logging          (what most agent runtimes do)
B  A + exact scope binding
C  A + single-use / expiring lease
D  A + explicit UNKNOWN + reconciliation-before-retry
E  B + C + D + verifiable evidence      (the full proposal)

Arm A is deliberately written the way a reasonable engineer would write it
without these ideas: it approves, it retries on error, and it logs. It is not a
strawman — its retry is the natural response to a timeout.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from benchmark.harness.world import (
    DispatchInterrupted,
    Fault,
    PaymentWorld,
    Scenario,
)


@dataclass
class ArmResult:
    """What one arm did in one scenario, from the arm's own point of view."""

    arm: str
    scenario: str
    dispatches_attempted: int = 0
    unauthorized_dispatches: int = 0
    scope_violations_blocked: int = 0
    retries_after_uncertainty: int = 0
    reconciliations: int = 0
    final_state: str = "UNSET"
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def log(self, kind: str, **detail: Any) -> None:
        self.evidence.append({"kind": kind, **detail})


class Arm:
    """Base runtime: approval, dispatch, and a log."""

    name = "A"
    description = "ordinary approval + logging"

    binds_scope = False
    uses_lease = False
    tracks_unknown = False

    def __init__(self, world: PaymentWorld) -> None:
        self.world = world

    # -- hooks the richer arms override -------------------------------------

    def _authorize(self, result: ArmResult, approved: dict[str, Any],
                   requested: dict[str, Any]) -> bool:
        """May this attempt proceed? Arm A checks nothing beyond 'was approved'."""
        return True

    def _consume(self, result: ArmResult) -> bool:
        """Claim the right to dispatch. Arm A has no notion of spending one."""
        return True

    def _on_interrupted(self, result: ArmResult, fault: Fault, intent_id: str,
                        attempt: int, scenario: Scenario) -> bool:
        """Return True to allow another attempt.

        Arm A cannot distinguish 'never happened' from 'happened, unobserved',
        so it does what a timeout normally invites: it tries again.
        """
        result.retries_after_uncertainty += 1
        return True

    # -- the run ------------------------------------------------------------

    def run(self, scenario: Scenario, intent: dict[str, Any]) -> ArmResult:
        result = ArmResult(arm=self.name, scenario=scenario.name)
        approved = dict(intent)
        requested = dict(intent)
        if scenario.mutate_arguments:
            requested = {**intent, "amount": intent["amount"] * 10}

        for attempt in range(scenario.attempts):
            if not self._authorize(result, approved, requested):
                result.final_state = "BLOCKED_SCOPE"
                result.log("blocked", reason="scope_violation", attempt=attempt)
                return result
            if not self._consume(result):
                result.final_state = "BLOCKED_LEASE"
                result.log("blocked", reason="lease_unavailable", attempt=attempt)
                return result

            fault = scenario.fault_for(attempt)
            result.dispatches_attempted += 1
            if requested["amount"] != approved["amount"]:
                result.unauthorized_dispatches += 1

            try:
                response = self.world.charge(
                    intent["intent_id"], requested["amount"], fault=fault,
                    idempotency_key=self._idempotency_key(intent, attempt),
                )
            except DispatchInterrupted as interruption:
                result.log("interrupted", fault=interruption.fault.value, attempt=attempt)
                if not self._on_interrupted(result, interruption.fault,
                                            intent["intent_id"], attempt, scenario):
                    return result
                continue

            if response["status"] == "succeeded":
                result.final_state = "SUCCEEDED"
                result.log("succeeded", charge_id=response["charge_id"], attempt=attempt)
                return result
            result.final_state = "FAILED"
            result.log("failed", reason=response.get("reason"), attempt=attempt)
            return result

        if result.final_state == "UNSET":
            result.final_state = "EXHAUSTED"
        return result

    def _idempotency_key(self, intent: dict[str, Any], attempt: int) -> str | None:
        """Arm A has no stable key: each attempt looks like a new request."""
        return None
