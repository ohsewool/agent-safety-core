"""The adapter: existing tools gain the core's rules without being rewritten."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters.guarded_tool import (
    ApprovalRequired,
    GuardContext,
    GuardError,
    LeaseRefused,
    OutcomeUnknown,
    ToolGuard,
)
from core.access import AccessControl, AccessDenied, Principal, Role
from core.ledger import ExecutionLedger
from core.scope import PolicyBinding

POLICY = PolicyBinding.from_document("tools", "1", {"write": "require_approval"})
CONTEXT = {"code_revision": "abc123", "tool_version": "1.0.0",
           "execution_identity": "svc", "working_directory": "/srv"}


class Effects:
    """Ground truth: what the wrapped tool actually did."""

    def __init__(self, *, fail=False):
        self.calls = []
        self.fail = fail

    def write(self, path, content):
        self.calls.append((path, content))
        if self.fail:
            raise ConnectionError("lost after sending")
        return f"wrote {path}"

    def read(self, path):
        self.calls.append(("read", path))
        return "contents"


@pytest.fixture
def access():
    return AccessControl([
        Principal.with_roles("agent-1", Role.OPERATOR),
        Principal.with_roles("human-1", Role.APPROVER),
    ])


@pytest.fixture
def guard(tmp_path, access):
    ledger = ExecutionLedger(str(tmp_path / "ledger.db"))
    yield ToolGuard(ledger, access=access, context=GuardContext(
        run_id="run-1", actor_id="agent-1", policy=POLICY, context=CONTEXT,
    ))
    ledger.close()


def approve_for(guard, execution_id, *args, tool_id="fs", operation="write", **kwargs):
    digest = guard.scope_digest_for(tool_id, operation, *args, **kwargs)
    return guard.approve(execution_id, approver_id="human-1", requester_id="agent-1",
                         scope_digest=digest)


class TestConsequentialCalls:
    def test_an_unapproved_call_is_held_and_has_no_effect(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        assert error.value.execution_id
        assert effects.calls == []

    def test_an_approved_call_runs_exactly_once(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        lease = approve_for(guard, error.value.execution_id, "/tmp/a", "x")

        assert write("/tmp/a", "x", _lease=lease) == "wrote /tmp/a"
        assert effects.calls == [("/tmp/a", "x")]

    def test_a_spent_lease_cannot_run_it_again(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        lease = approve_for(guard, error.value.execution_id, "/tmp/a", "x")
        write("/tmp/a", "x", _lease=lease)
        with pytest.raises(LeaseRefused):
            write("/tmp/a", "x", _lease=lease)
        assert len(effects.calls) == 1

    def test_changed_arguments_cannot_use_the_approval(self, guard):
        """Approving a write to /tmp/a does not approve a write to /etc/passwd."""
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        lease = approve_for(guard, error.value.execution_id, "/tmp/a", "x")
        with pytest.raises(LeaseRefused):
            write("/etc/passwd", "x", _lease=lease)
        assert effects.calls == []

    def test_keyword_and_positional_forms_are_distinct_calls(self, guard):
        """They are not the same invocation, and the digest must not pretend otherwise."""
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        lease = approve_for(guard, error.value.execution_id, "/tmp/a", "x")
        with pytest.raises(LeaseRefused):
            write(path="/tmp/a", content="x", _lease=lease)

    def test_the_lease_keyword_never_reaches_the_tool(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        lease = approve_for(guard, error.value.execution_id, "/tmp/a", "x")
        write("/tmp/a", "x", _lease=lease)  # would TypeError if forwarded


class TestHarmlessCalls:
    def test_a_non_consequential_tool_runs_without_approval(self, guard):
        """Gating a read trains people to approve without looking."""
        effects = Effects()
        read = guard.guarded(effects.read, tool_id="fs", operation="read",
                             consequential=False)
        assert read("/tmp/a") == "contents"
        assert effects.calls == [("read", "/tmp/a")]


class TestUncertainty:
    def test_a_tool_that_fails_mid_call_is_unknown_not_failed(self, guard):
        effects = Effects(fail=True)
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as held:
            write("/tmp/a", "x")
        lease = approve_for(guard, held.value.execution_id, "/tmp/a", "x")

        with pytest.raises(OutcomeUnknown) as error:
            write("/tmp/a", "x", _lease=lease)
        assert guard._ledger.get(error.value.execution_id).state == "UNKNOWN"

    def test_uncertainty_raises_rather_than_returning_a_falsy_value(self, guard):
        """`if not result:` after a timeout would silently call it a failure."""
        effects = Effects(fail=True)
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as held:
            write("/tmp/a", "x")
        lease = approve_for(guard, held.value.execution_id, "/tmp/a", "x")
        with pytest.raises(OutcomeUnknown):
            write("/tmp/a", "x", _lease=lease)

    def test_unbindable_arguments_are_refused_before_anything_runs(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(GuardError):
            write("/tmp/a", float("nan"))
        assert effects.calls == []


class TestAuthorisation:
    def test_self_approval_is_refused(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        digest = guard.scope_digest_for("fs", "write", "/tmp/a", "x")
        with pytest.raises(AccessDenied):
            guard.approve(error.value.execution_id, approver_id="agent-1",
                          requester_id="agent-1", scope_digest=digest)

    def test_an_actor_without_dispatch_cannot_run_a_guarded_tool(self, tmp_path, access):
        ledger = ExecutionLedger(str(tmp_path / "l.db"))
        try:
            observer = ToolGuard(ledger, access=access, context=GuardContext(
                run_id="run-1", actor_id="human-1", policy=POLICY, context=CONTEXT,
            ))
            effects = Effects()
            write = observer.guarded(effects.write, tool_id="fs", operation="write")
            with pytest.raises(AccessDenied):
                write("/tmp/a", "x")
        finally:
            ledger.close()


class TestWrapperBehaviour:
    def test_the_wrapper_keeps_the_original_identity(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        assert write.__name__ == "write"
        assert write.tool_id == "fs"
        assert write.consequential is True

    def test_the_operation_defaults_to_the_function_name(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs")
        with pytest.raises(ApprovalRequired):
            write("/tmp/a", "x")
        events = guard._ledger.events()
        assert events[0]["detail"]["operation"] == "write"

    def test_the_full_sequence_is_recorded(self, guard):
        effects = Effects()
        write = guard.guarded(effects.write, tool_id="fs", operation="write")
        with pytest.raises(ApprovalRequired) as error:
            write("/tmp/a", "x")
        execution_id = error.value.execution_id
        lease = approve_for(guard, execution_id, "/tmp/a", "x")
        write("/tmp/a", "x", _lease=lease)
        kinds = [event["kind"] for event in guard._ledger.events(execution_id)]
        assert kinds == ["created", "approved", "lease_claimed", "outcome"]
