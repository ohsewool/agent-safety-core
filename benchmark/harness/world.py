"""A payment world that can be made to fail in specific, repeatable ways.

Every arm of the ablation runs against this same world, so a difference in
results is a difference between the arms and not between two test rigs.

The world models the one property that makes agent side effects hard: the
external system's state and the caller's knowledge of it are not the same thing.
A charge can succeed and the caller still not know, which is exactly the case
that separates a system that suppresses retries from one that double-charges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Fault(Enum):
    """How a dispatch attempt fails, if it fails."""

    NONE = "none"
    TIMEOUT_AFTER_EFFECT = "timeout_after_effect"      # charged, response lost
    TIMEOUT_BEFORE_EFFECT = "timeout_before_effect"    # never charged
    CRASH_AFTER_EFFECT = "crash_after_effect"          # charged, caller died
    CRASH_BEFORE_EFFECT = "crash_before_effect"        # not charged, caller died
    PROCESSOR_ERROR = "processor_error"                # explicit failure
    RECONCILE_UNAVAILABLE = "reconcile_unavailable"    # cannot look up state


class DispatchInterrupted(Exception):
    """The caller lost the ability to observe this attempt."""

    def __init__(self, fault: Fault) -> None:
        super().__init__(fault.value)
        self.fault = fault


@dataclass
class Charge:
    charge_id: str
    intent_id: str
    amount: int
    idempotency_key: str | None


@dataclass
class PaymentWorld:
    """A processor that records every charge it actually performed.

    ``charges`` is ground truth — what the outside world did — and is what the
    benchmark measures.  What any arm *believes* happened is irrelevant to the
    duplicate-side-effect count.
    """

    charges: list[Charge] = field(default_factory=list)
    supports_idempotency: bool = False
    supports_lookup: bool = True
    _next_id: int = 0

    def charge(self, intent_id: str, amount: int, *, fault: Fault = Fault.NONE,
               idempotency_key: str | None = None) -> dict[str, Any]:
        if fault in (Fault.TIMEOUT_BEFORE_EFFECT, Fault.CRASH_BEFORE_EFFECT):
            raise DispatchInterrupted(fault)
        if fault is Fault.PROCESSOR_ERROR:
            return {"status": "failed", "reason": "insufficient_funds"}

        if self.supports_idempotency and idempotency_key is not None:
            existing = next(
                (charge for charge in self.charges if charge.idempotency_key == idempotency_key),
                None,
            )
            if existing is not None:
                # The processor deduplicates: the second attempt is not a charge.
                if fault in (Fault.TIMEOUT_AFTER_EFFECT, Fault.CRASH_AFTER_EFFECT):
                    raise DispatchInterrupted(fault)
                return {"status": "succeeded", "charge_id": existing.charge_id, "replayed": True}

        self._next_id += 1
        charge = Charge(f"ch_{self._next_id}", intent_id, amount, idempotency_key)
        self.charges.append(charge)

        if fault in (Fault.TIMEOUT_AFTER_EFFECT, Fault.CRASH_AFTER_EFFECT):
            raise DispatchInterrupted(fault)
        return {"status": "succeeded", "charge_id": charge.charge_id}

    def lookup(self, intent_id: str) -> dict[str, Any]:
        """Ask the processor what actually happened. May be unavailable."""
        if not self.supports_lookup:
            raise DispatchInterrupted(Fault.RECONCILE_UNAVAILABLE)
        matches = [charge for charge in self.charges if charge.intent_id == intent_id]
        if not matches:
            return {"status": "not_found"}
        return {"status": "succeeded", "charge_id": matches[0].charge_id,
                "count": len(matches)}

    def charge_count(self, intent_id: str) -> int:
        return sum(1 for charge in self.charges if charge.intent_id == intent_id)


@dataclass(frozen=True)
class Scenario:
    """One repeatable situation, applied identically to every arm."""

    name: str
    faults: tuple[Fault, ...]          # one per dispatch attempt, in order
    attempts: int = 1                  # how many times the agent tries
    concurrent: int = 1                # how many workers try at once
    mutate_arguments: bool = False     # tamper between approval and execution
    supports_idempotency: bool = False
    supports_lookup: bool = True
    should_complete: bool = True       # is finishing the work the correct outcome?

    def fault_for(self, attempt: int) -> Fault:
        if not self.faults:
            return Fault.NONE
        return self.faults[min(attempt, len(self.faults) - 1)]
