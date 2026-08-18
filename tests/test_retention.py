"""Retention: a label that enforces nothing is worse than no label."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.retention import (
    DAY,
    DEFAULT_CLASSES,
    RetentionClass,
    RetentionError,
    RetentionSchedule,
)

CREATED = 1_000_000.0


class Clock:
    def __init__(self, now=CREATED):
        self.now = now

    def __call__(self):
        return self.now

    def advance_days(self, days):
        self.now += days * DAY


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def schedule(clock):
    return RetentionSchedule(clock=clock)


def decide(schedule, *, cls="standard", on_hold=False):
    return schedule.decide("p1", retention_class=cls, created_at=CREATED, on_hold=on_hold)


class TestClassDefinition:
    def test_a_class_must_state_why_it_exists(self):
        """A period nobody can justify is one nobody can defend."""
        with pytest.raises(RetentionError):
            RetentionClass("mystery", 90, "")

    def test_a_negative_period_is_refused(self):
        with pytest.raises(RetentionError):
            RetentionClass("negative", -1, "reason")

    def test_a_maximum_below_the_minimum_is_refused(self):
        with pytest.raises(RetentionError):
            RetentionClass("impossible", 90, "reason", maximum_days=30)

    def test_the_shipped_classes_are_all_justified(self):
        for rule in DEFAULT_CLASSES:
            assert rule.rationale, rule.name


class TestBeforeThePeriodElapses:
    def test_fresh_data_is_kept(self, schedule):
        decision = decide(schedule)
        assert decision.action == "keep"
        assert not decision.may_destroy

    def test_the_refusal_says_how_long_is_left(self, schedule):
        assert "days remain" in decide(schedule).reason

    def test_an_eager_cleanup_is_refused(self, schedule):
        """The point: a script cannot destroy evidence someone is still owed."""
        with pytest.raises(RetentionError):
            schedule.require_destroyable("p1", retention_class="standard",
                                         created_at=CREATED)

    def test_a_longer_class_keeps_data_longer(self, schedule, clock):
        clock.advance_days(100)
        assert decide(schedule, cls="standard").may_destroy
        assert not decide(schedule, cls="financial").may_destroy


class TestAfterThePeriodElapses:
    def test_elapsed_data_becomes_eligible_not_deleted(self, schedule, clock):
        """Eligibility is not deletion; deletion stays an act someone performs."""
        clock.advance_days(91)
        decision = decide(schedule)
        assert decision.action == "eligible"
        assert decision.may_destroy

    def test_a_capped_class_becomes_overdue(self, schedule, clock):
        clock.advance_days(400)
        assert decide(schedule).action == "overdue"

    def test_an_uncapped_class_never_becomes_overdue(self, schedule, clock):
        clock.advance_days(10_000)
        assert decide(schedule, cls="financial").action == "eligible"

    def test_transient_data_is_immediately_eligible(self, schedule):
        assert decide(schedule, cls="transient").may_destroy


class TestLegalHold:
    def test_a_hold_prevents_destruction_before_the_period_ends(self, schedule):
        assert decide(schedule, on_hold=True).action == "held"

    def test_a_hold_prevents_destruction_after_the_period_ends(self, schedule, clock):
        clock.advance_days(500)
        decision = decide(schedule, on_hold=True)
        assert decision.action == "held"
        assert not decision.may_destroy

    def test_the_conflict_is_reported_rather_than_resolved(self, schedule, clock):
        """'Must keep' versus 'must delete' is a question for a person."""
        clock.advance_days(500)
        assert "already elapsed" in decide(schedule, on_hold=True).reason

    def test_a_held_payload_cannot_be_forced(self, schedule, clock):
        clock.advance_days(500)
        with pytest.raises(RetentionError):
            schedule.require_destroyable("p1", retention_class="standard",
                                         created_at=CREATED, on_hold=True)


class TestUnknownClasses:
    def test_an_unknown_class_is_refused(self, schedule):
        with pytest.raises(RetentionError) as error:
            decide(schedule, cls="whatever")
        assert "unknown retention class" in str(error.value)

    def test_the_refusal_explains_why_that_matters(self, schedule):
        """Unclassified is not deletable: nobody has said how long to keep it."""
        with pytest.raises(RetentionError) as error:
            decide(schedule, cls="whatever")
        assert "not deletable" in str(error.value)

    def test_an_empty_schedule_is_refused(self, clock):
        with pytest.raises(RetentionError):
            RetentionSchedule([], clock=clock)


class TestSweeping:
    def test_a_sweep_decides_for_many_payloads(self, schedule, clock):
        clock.advance_days(91)
        decisions = schedule.sweep([
            {"payload_id": "a", "retention_class": "standard", "created_at": CREATED},
            {"payload_id": "b", "retention_class": "financial", "created_at": CREATED},
            {"payload_id": "c", "retention_class": "standard", "created_at": CREATED,
             "on_hold": True},
        ])
        assert [item.action for item in decisions] == ["eligible", "keep", "held"]

    def test_a_sweep_destroys_nothing(self, schedule, clock):
        """Destruction needs an actor in the log, so it is not a background job."""
        clock.advance_days(500)
        decisions = schedule.sweep([
            {"payload_id": "a", "retention_class": "standard", "created_at": CREATED},
        ])
        assert all(hasattr(item, "action") for item in decisions)
        assert not hasattr(schedule, "destroy")

    def test_overdue_payloads_are_surfaced(self, schedule, clock):
        clock.advance_days(400)
        overdue = schedule.overdue([
            {"payload_id": "a", "retention_class": "standard", "created_at": CREATED},
            {"payload_id": "b", "retention_class": "financial", "created_at": CREATED},
        ])
        assert [item.payload_id for item in overdue] == ["a"]

    def test_a_payload_without_a_class_falls_back_to_standard(self, schedule):
        decisions = schedule.sweep([{"payload_id": "a", "created_at": CREATED}])
        assert decisions[0].action == "keep"


class TestReviewability:
    def test_the_schedule_can_be_shown_to_a_reviewer(self, schedule):
        described = schedule.describe()
        assert {item["name"] for item in described} == {rule.name for rule in DEFAULT_CLASSES}
        assert all(item["rationale"] for item in described)

    def test_a_decision_reports_both_dates(self, schedule):
        decision = decide(schedule)
        assert decision.eligible_at > CREATED
        assert decision.due_at is not None  # standard caps retention

    def test_an_uncapped_class_reports_no_due_date(self, schedule):
        assert decide(schedule, cls="financial").due_at is None
