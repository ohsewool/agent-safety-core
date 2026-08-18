"""The failure situations every arm is measured against.

Drawn from the ten AP2 threat cases in the project plan, reduced to those that a
runtime (rather than the protocol or the processor) is responsible for.
"""

from __future__ import annotations

from benchmark.harness.world import Fault, Scenario

SCENARIOS = (
    Scenario(
        name="happy_path",
        faults=(Fault.NONE,),
    ),
    Scenario(
        name="timeout_after_effect",
        # The charge happened; the response was lost. The trap: retrying charges twice.
        faults=(Fault.TIMEOUT_AFTER_EFFECT, Fault.NONE),
        attempts=2,
    ),
    Scenario(
        name="timeout_before_effect",
        # Nothing happened. Retrying is correct here, so an arm that never retries
        # pays a cost in this scenario - that trade-off should be visible.
        faults=(Fault.TIMEOUT_BEFORE_EFFECT, Fault.NONE),
        attempts=2,
    ),
    Scenario(
        name="crash_after_effect",
        faults=(Fault.CRASH_AFTER_EFFECT, Fault.NONE),
        attempts=2,
    ),
    Scenario(
        name="repeated_uncertainty",
        faults=(Fault.TIMEOUT_AFTER_EFFECT, Fault.TIMEOUT_AFTER_EFFECT, Fault.NONE),
        attempts=3,
    ),
    Scenario(
        name="amount_escalation",
        # The approval was for one amount; execution asks for ten times more.
        faults=(Fault.NONE,),
        mutate_arguments=True,
        should_complete=False,   # the correct outcome is a refusal
    ),
    Scenario(
        name="processor_error",
        faults=(Fault.PROCESSOR_ERROR,),
        should_complete=False,   # the processor declined; no charge is correct
    ),
    Scenario(
        name="reconcile_unavailable",
        # Uncertain *and* unable to find out. The honest end state is unresolved.
        faults=(Fault.TIMEOUT_AFTER_EFFECT, Fault.NONE),
        attempts=2,
        supports_lookup=False,
    ),
    Scenario(
        name="idempotent_processor",
        # When the processor deduplicates, a stable key prevents the second charge.
        faults=(Fault.TIMEOUT_AFTER_EFFECT, Fault.NONE),
        attempts=2,
        supports_idempotency=True,
    ),
)
