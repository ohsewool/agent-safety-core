"""The ablation's claims, pinned as tests.

A benchmark whose numbers can drift silently is not evidence. These assert the
findings the report states, so a change in a mechanism either keeps the claim
true or fails here.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmark.arms.base import Arm  # noqa: E402
from benchmark.arms.variants import FullArm, LeasedArm, ScopeBoundArm, UncertaintyAwareArm  # noqa: E402
from benchmark.harness.world import Fault, PaymentWorld, Scenario  # noqa: E402
from benchmark.run import attribute, measure, run_all, totals  # noqa: E402


@pytest.fixture(scope="module")
def summary():
    return totals(run_all())


class TestWorldFidelity:
    """The world must be able to charge without the caller learning of it."""

    def test_timeout_after_effect_still_charges(self):
        world = PaymentWorld()
        with pytest.raises(Exception):
            world.charge("i", 100, fault=Fault.TIMEOUT_AFTER_EFFECT)
        assert world.charge_count("i") == 1

    def test_timeout_before_effect_does_not_charge(self):
        world = PaymentWorld()
        with pytest.raises(Exception):
            world.charge("i", 100, fault=Fault.TIMEOUT_BEFORE_EFFECT)
        assert world.charge_count("i") == 0

    def test_idempotent_processor_deduplicates_by_key(self):
        world = PaymentWorld(supports_idempotency=True)
        world.charge("i", 100, idempotency_key="k")
        world.charge("i", 100, idempotency_key="k")
        assert world.charge_count("i") == 1


class TestBaselineIsHonest:
    """Arm A must be a fair baseline: it fails for the reason we claim, not by design."""

    def test_baseline_succeeds_on_the_happy_path(self):
        result = measure(Arm, Scenario(name="ok", faults=(Fault.NONE,)))
        assert result.charges_performed == 1
        assert result.duplicate_side_effects == 0

    def test_baseline_double_charges_only_when_the_effect_was_unobserved(self):
        scenario = Scenario(name="lost", faults=(Fault.TIMEOUT_AFTER_EFFECT, Fault.NONE), attempts=2)
        assert measure(Arm, scenario).duplicate_side_effects == 1

    def test_baseline_does_not_double_charge_when_nothing_happened(self):
        scenario = Scenario(name="none", faults=(Fault.TIMEOUT_BEFORE_EFFECT, Fault.NONE), attempts=2)
        assert measure(Arm, scenario).duplicate_side_effects == 0


class TestMechanismClaims:
    def test_scope_binding_alone_stops_unauthorized_but_not_duplicates(self, summary):
        assert summary["B"]["unauthorized_side_effects"] == 0
        assert summary["B"]["duplicate_side_effects"] == summary["A"]["duplicate_side_effects"]

    def test_lease_alone_stops_duplicates_but_loses_legitimate_work(self, summary):
        """The trade-off the report names: never retrying is not free."""
        assert summary["C"]["duplicate_side_effects"] == 0
        assert summary["C"]["missed_completions"] > 0

    def test_reconciliation_stops_duplicates_without_losing_work(self, summary):
        """The distinguishing claim of arm D."""
        assert summary["D"]["duplicate_side_effects"] == 0
        assert summary["D"]["missed_completions"] == 0

    def test_only_the_full_combination_is_clean_on_every_harm_metric(self, summary):
        assert summary["E"]["duplicate_side_effects"] == 0
        assert summary["E"]["unauthorized_side_effects"] == 0
        assert summary["E"]["false_retries"] == 0
        assert summary["E"]["missed_completions"] == 0

    def test_unresolvable_case_is_reported_not_hidden(self, summary):
        """When the processor cannot be queried, the arms that admit it say so."""
        assert summary["D"]["unresolved"] >= 1
        assert summary["E"]["unresolved"] >= 1


class TestAttribution:
    def test_gains_are_credited_to_the_mechanism_that_produced_them(self, summary):
        attribution = attribute(summary)
        assert attribution["B"]["unauthorized_side_effects_prevented"] == 1
        assert attribution["C"]["duplicate_side_effects_prevented"] > 0
        assert attribution["D"]["duplicate_side_effects_prevented"] > 0
        assert attribution["B"]["duplicate_side_effects_prevented"] == 0

    def test_combination_effect_is_reported_separately(self, summary):
        """Gains beyond the best single mechanism must not be credited to a part."""
        attribution = attribute(summary)
        assert "combination_effect" in attribution["E"]

    def test_lease_cost_is_recorded_in_the_attribution(self, summary):
        assert attribute(summary)["C"]["completions_lost"] > 0


class TestReproducibility:
    def test_two_runs_produce_identical_measurements(self):
        first, second = run_all(), run_all()
        assert [m.__dict__ for m in first] == [m.__dict__ for m in second]

    def test_every_arm_meets_every_scenario(self):
        measurements = run_all()
        arms = {m.arm for m in measurements}
        scenarios = {m.scenario for m in measurements}
        assert len(measurements) == len(arms) * len(scenarios)
