"""Putting the core in front of an existing tool without rewriting the agent.

The core's guarantees are worth little if adopting them means restructuring an
agent that already works. This adapter is the smallest surface that still keeps
the ordering intact: wrap the function that causes the side effect, and the
propose/approve/claim/record sequence happens around it.

    charge = guarded(charge_customer, tool_id="payments", consequential=True)
    charge(amount=1000, payee="m1")     # raises ApprovalRequired, nothing charged
    charge(amount=1000, payee="m1", _lease=lease)   # charges exactly once

What the wrapper will not do is make the unsafe thing convenient. There is no
auto-approve option, no retry helper, and a lost response raises rather than
returning a falsy value, because a caller who writes `if not result:` after a
timeout has just decided that an uncertain charge failed.

Arguments are canonicalised before they are bound, so the same call made twice
produces the same digest and a call with a changed argument does not.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from core.access import AccessControl, Permission
from core.canonical import CanonicalizationError
from core.ledger import FAILED, SUCCEEDED, UNKNOWN, ExecutionLedger
from core.scope import ContextSpec, ExecutionScope, PolicyBinding, ScopeError

LEASE_KEYWORD = "_lease"


class GuardError(RuntimeError):
    """Base class for refusals raised by the adapter."""


class ApprovalRequired(GuardError):
    """The call was held. Nothing was executed."""

    def __init__(self, execution_id: str, tool_id: str) -> None:
        super().__init__(
            f"{tool_id} requires approval; execution {execution_id} is awaiting a decision"
        )
        self.execution_id = execution_id
        self.tool_id = tool_id


class LeaseRefused(GuardError):
    """The lease could not be claimed, so the tool was not called."""


class OutcomeUnknown(GuardError):
    """The tool was called and the result could not be observed."""

    def __init__(self, execution_id: str, reason: str) -> None:
        super().__init__(f"outcome unknown for {execution_id}: {reason}")
        self.execution_id = execution_id


@dataclass(frozen=True)
class GuardContext:
    """The identity and environment every guarded call is bound to."""

    run_id: str
    actor_id: str
    policy: PolicyBinding
    context: Mapping[str, Any]
    context_spec: ContextSpec = ContextSpec()


class ToolGuard:
    """Wraps callables so that consequential ones run under the core's rules."""

    def __init__(self, ledger: ExecutionLedger, *, access: AccessControl,
                 context: GuardContext) -> None:
        self._ledger = ledger
        self._access = access
        self._context = context

    def _scope(self, tool_id: str, operation: str, arguments: Mapping[str, Any]) -> str:
        scope = ExecutionScope(
            run_id=self._context.run_id,
            actor_id=self._context.actor_id,
            tool_id=tool_id,
            operation=operation,
            arguments=dict(arguments),
            policy=self._context.policy,
            context=dict(self._context.context),
            context_spec=self._context.context_spec,
        )
        return scope.digest()

    def guarded(self, function: Callable[..., Any], *, tool_id: str,
                operation: str | None = None, consequential: bool = True) -> Callable[..., Any]:
        """Return a wrapper that runs ``function`` under the execution model.

        A non-consequential tool is recorded but not gated: reading a file does
        not need a human, and making it need one trains people to approve
        without looking.
        """
        resolved_operation = operation or getattr(function, "__name__", "call")

        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            lease_id = kwargs.pop(LEASE_KEYWORD, None)
            bindable = {"args": list(args), "kwargs": dict(kwargs)}

            try:
                scope_digest = self._scope(tool_id, resolved_operation, bindable)
            except (ScopeError, CanonicalizationError) as error:
                raise GuardError(f"call cannot be bound to an approval: {error}") from error

            if not consequential:
                return function(*args, **kwargs)

            if lease_id is None:
                self._access.require(self._context.actor_id, Permission.EXECUTION_PROPOSE)
                execution_id = self._ledger.create(
                    run_id=self._context.run_id, actor_id=self._context.actor_id,
                    tool_id=tool_id, operation=resolved_operation,
                    scope_digest=scope_digest,
                )
                raise ApprovalRequired(execution_id, tool_id)

            self._access.require(self._context.actor_id, Permission.EXECUTION_DISPATCH)
            execution_id = self._ledger.claim_lease(lease_id, scope_digest=scope_digest)
            if execution_id is None:
                raise LeaseRefused(
                    f"{tool_id}: lease is spent, expired, revoked, or bound to a different call"
                )

            try:
                result = function(*args, **kwargs)
            except Exception as error:
                # The tool was entered. Whether it took effect is not knowable
                # here, so it is recorded as unknown rather than as a failure.
                self._ledger.record_outcome(
                    execution_id, state=UNKNOWN,
                    evidence={"reason": str(error), "tool_id": tool_id},
                )
                raise OutcomeUnknown(execution_id, str(error)) from error

            self._ledger.record_outcome(
                execution_id, state=SUCCEEDED, evidence={"tool_id": tool_id}
            )
            return result

        wrapper.tool_id = tool_id  # type: ignore[attr-defined]
        wrapper.consequential = consequential  # type: ignore[attr-defined]
        return wrapper

    def approve(self, execution_id: str, *, approver_id: str, requester_id: str,
                scope_digest: str, ttl_seconds: float = 300.0) -> str:
        """Approve a held call. Separate from the wrapper on purpose.

        Approval belongs to a person and a different process; putting it on the
        same object the agent calls would make self-approval a one-line change.
        """
        self._access.require_approval_separation(
            approver_id=approver_id, requester_id=requester_id
        )
        return self._ledger.approve(
            execution_id, approver_id=approver_id,
            scope_digest=scope_digest, ttl_seconds=ttl_seconds,
        )

    def scope_digest_for(self, tool_id: str, operation: str, *args: Any, **kwargs: Any) -> str:
        """Recompute the digest an approver must bind to."""
        return self._scope(tool_id, operation, {"args": list(args), "kwargs": dict(kwargs)})
