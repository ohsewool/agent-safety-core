"""Verification: settle an uncertain outcome by looking, not by asking again."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ledger import ExecutionLedger, UNKNOWN
from core.verification import (
    Observation,
    Postcondition,
    VerificationError,
    Verifier,
    postcondition,
)

SCOPE = "a" * 64


@pytest.fixture
def ledger(tmp_path):
    instance = ExecutionLedger(str(tmp_path / "ledger.db"))
    yield instance
    instance.close()


def uncertain_execution(ledger) -> str:
    """An execution that was dispatched and whose result was never observed."""
    execution_id = ledger.create(run_id="r", actor_id="agent", tool_id="crm",
                                 operation="activate", scope_digest=SCOPE)
    lease = ledger.approve(execution_id, approver_id="human",
                           scope_digest=SCOPE, ttl_seconds=60)
    ledger.claim_lease(lease, scope_digest=SCOPE)
    ledger.record_outcome(execution_id, state=UNKNOWN, evidence={"reason": "timeout"})
    return execution_id


def always(answer):
    return Postcondition(name=f"returns {answer}", check=lambda execution_id: answer)


def raises():
    def check(execution_id):
        raise ConnectionError("replica unreachable")
    return Postcondition(name="unreachable", check=check)


class TestObservation:
    def test_a_present_effect_is_satisfied(self):
        assert always(True).observe("e1").observation is Observation.SATISFIED

    def test_an_absent_effect_is_unsatisfied(self):
        assert always(False).observe("e1").observation is Observation.UNSATISFIED

    def test_no_answer_is_unobservable_not_absent(self):
        """The distinction the whole module exists for."""
        assert always(None).observe("e1").observation is Observation.UNOBSERVABLE

    def test_a_check_that_raises_is_unobservable_not_absent(self):
        result = raises().observe("e1")
        assert result.observation is Observation.UNOBSERVABLE
        assert "replica unreachable" in result.detail["error"]

    def test_only_conclusive_observations_report_conclusive(self):
        assert always(True).observe("e1").conclusive
        assert always(False).observe("e1").conclusive
        assert not always(None).observe("e1").conclusive

    def test_the_channel_is_carried_through(self):
        condition = Postcondition("replica check", lambda e: True, channel="replica")
        assert condition.observe("e1").channel == "replica"


class TestSettling:
    def test_a_satisfied_postcondition_settles_as_succeeded(self, ledger):
        execution_id = uncertain_execution(ledger)
        verifier = Verifier(ledger)
        assert verifier.settle(execution_id, [always(True)],
                               reconciler_id="reconciler-1") == "SUCCEEDED"
        assert ledger.get(execution_id).state == "SUCCEEDED"

    def test_an_unsatisfied_postcondition_settles_as_failed(self, ledger):
        execution_id = uncertain_execution(ledger)
        verifier = Verifier(ledger)
        assert verifier.settle(execution_id, [always(False)],
                               reconciler_id="reconciler-1") == "FAILED"

    def test_an_unobservable_check_leaves_it_unresolved(self, ledger):
        """Not knowing is recorded as not knowing."""
        execution_id = uncertain_execution(ledger)
        verifier = Verifier(ledger)
        assert verifier.settle(execution_id, [raises()],
                               reconciler_id="reconciler-1") == "PERMANENTLY_UNRESOLVED"

    def test_the_evidence_names_the_channel_and_the_observation(self, ledger):
        execution_id = uncertain_execution(ledger)
        Verifier(ledger).settle(
            execution_id,
            [Postcondition("customer active", lambda e: True, channel="replica")],
            reconciler_id="reconciler-1",
        )
        last = ledger.events(execution_id)[-1]
        assert last["detail"]["channel"] == "replica"
        assert last["detail"]["observation"] == "satisfied"
        assert last["detail"]["reconciler_id"] == "reconciler-1"

    def test_verification_applies_only_to_unknown_executions(self, ledger):
        execution_id = ledger.create(run_id="r", actor_id="a", tool_id="t",
                                     operation="o", scope_digest=SCOPE)
        with pytest.raises(VerificationError):
            Verifier(ledger).settle(execution_id, [always(True)], reconciler_id="r1")

    def test_an_unknown_execution_id_is_refused(self, ledger):
        with pytest.raises(VerificationError):
            Verifier(ledger).settle("missing", [always(True)], reconciler_id="r1")


class TestMultipleChannels:
    def test_a_cheap_check_can_answer_before_an_expensive_one(self, ledger):
        calls = []

        def local(execution_id):
            calls.append("local")
            return True

        def remote(execution_id):
            calls.append("remote")
            return True

        Verifier(ledger).verify("e1", [Postcondition("local", local),
                                       Postcondition("remote", remote)])
        assert "local" in calls

    def test_any_channel_reporting_presence_wins(self, ledger):
        """A false 'it did not happen' is what produces a duplicate charge."""
        result = Verifier(ledger).verify("e1", [always(False), always(True)])
        assert result.observation is Observation.SATISFIED

    def test_an_unobservable_channel_does_not_mask_a_conclusive_one(self, ledger):
        result = Verifier(ledger).verify("e1", [raises(), always(False)])
        assert result.observation is Observation.UNSATISFIED

    def test_all_channels_failing_is_unobservable(self, ledger):
        result = Verifier(ledger).verify("e1", [raises(), always(None)])
        assert result.observation is Observation.UNOBSERVABLE
        assert result.detail["attempted"] == ["unreachable", "returns None"]

    def test_no_postconditions_is_unobservable_rather_than_an_error(self, ledger):
        assert Verifier(ledger).verify("e1", []).observation is Observation.UNOBSERVABLE


class TestRetrySafety:
    def test_a_retry_is_safe_only_when_the_effect_is_absent(self, ledger):
        verifier = Verifier(ledger)
        assert verifier.retry_is_safe("e1", [always(False)])

    def test_a_retry_is_not_safe_when_the_effect_is_present(self, ledger):
        assert not Verifier(ledger).retry_is_safe("e1", [always(True)])

    def test_an_unobservable_check_is_not_permission_to_retry(self, ledger):
        """Precisely the state in which retrying duplicates the action."""
        assert not Verifier(ledger).retry_is_safe("e1", [raises()])

    def test_no_postconditions_is_not_permission_to_retry(self, ledger):
        assert not Verifier(ledger).retry_is_safe("e1", [])


class TestDecoratorForm:
    def test_a_decorated_check_becomes_a_postcondition(self):
        @postcondition("file exists", channel="filesystem")
        def file_written(execution_id: str) -> bool | None:
            return True

        assert isinstance(file_written, Postcondition)
        assert file_written.name == "file exists"
        assert file_written.observe("e1").channel == "filesystem"


class TestIndependenceFromTheFailedChannel:
    def test_verification_succeeds_when_the_processor_lookup_would_not(self, ledger):
        """The case reconcile() cannot handle: the processor itself is down.

        The response never arrived and asking the processor again would fail too,
        but a replica can still say the customer is active.
        """
        execution_id = uncertain_execution(ledger)

        def processor_lookup(execution_id):
            raise ConnectionError("processor is down")

        replica = Postcondition("customer is active on the replica",
                                lambda e: True, channel="replica")

        with pytest.raises(ConnectionError):
            processor_lookup(execution_id)

        assert Verifier(ledger).settle(execution_id, [replica],
                                       reconciler_id="reconciler-1") == "SUCCEEDED"
