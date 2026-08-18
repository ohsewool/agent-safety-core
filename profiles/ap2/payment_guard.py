"""The payment vertical, running on the real core rather than a simulation.

The ablation in `benchmark/` argues that scope binding, single-use leases, and
explicit UNKNOWN each prevent a different harm. It argues this with purpose-built
arms, which is the right way to isolate a mechanism but leaves an obvious
objection open: those arms are not the system.

This module closes that gap. It drives a payment through the actual ledger,
scope binder, and canonicaliser, so the properties the benchmark measured are
demonstrated by the code that would ship rather than by a model of it.

The order is the part that matters, and it is the same order ADR-002 argues for:

    propose  →  approve (binds the exact charge)  →  claim lease (durable)
             →  charge the processor  →  record the outcome

The lease is consumed and committed *before* the processor is called. That is
what makes "at most one dispatch per lease" provable: a crash after the commit
leaves an execution in DISPATCHING, which recovery reclassifies as UNKNOWN
rather than retrying, because the money may already have moved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from core.access import AccessControl, Permission
from core.ledger import DISPATCHING, FAILED, SUCCEEDED, UNKNOWN, ExecutionLedger
from core.scope import ContextSpec, ExecutionScope, PolicyBinding, resolve_opaque

PAYMENT_CONTEXT = ContextSpec(fields=("code_revision", "tool_version", "execution_identity"))


class PaymentRefused(RuntimeError):
    """The guard declined to dispatch. No charge was attempted."""


class OutcomeUncertain(RuntimeError):
    """The charge was dispatched and its result could not be observed."""

    def __init__(self, execution_id: str, reason: str) -> None:
        super().__init__(f"outcome unknown for {execution_id}: {reason}")
        self.execution_id = execution_id


@dataclass(frozen=True)
class ChargeIntent:
    """What the agent wants to do, in the terms an approval binds to."""

    run_id: str
    actor_id: str
    payee_id: str
    amount: int
    currency: str

    def scope(self, *, policy: PolicyBinding, context: Mapping[str, Any]) -> ExecutionScope:
        return ExecutionScope(
            run_id=self.run_id,
            actor_id=self.actor_id,
            tool_id="payments",
            operation="charge",
            arguments={"amount": self.amount, "currency": self.currency},
            resources=(resolve_opaque("payee", self.payee_id),),
            policy=policy,
            context=dict(context),
            context_spec=PAYMENT_CONTEXT,
        )


class PaymentGuard:
    """Runs a charge under the core's execution model.

    ``processor`` is any callable that performs the charge and returns a mapping
    with a ``status``; ``lookup`` answers what actually happened for an intent
    and is what turns an UNKNOWN into a final state. A processor without a lookup
    is accepted, and the consequence is stated rather than hidden: such an
    execution can only ever terminate as PERMANENTLY_UNRESOLVED.
    """

    def __init__(
        self,
        ledger: ExecutionLedger,
        *,
        access: AccessControl,
        policy: PolicyBinding,
        context: Mapping[str, Any],
        processor: Callable[..., Mapping[str, Any]],
        lookup: Callable[[str], Mapping[str, Any]] | None = None,
    ) -> None:
        self._ledger = ledger
        self._access = access
        self._policy = policy
        self._context = dict(context)
        self._processor = processor
        self._lookup = lookup

    # -- the three steps a human or operator takes ---------------------------

    def propose(self, intent: ChargeIntent) -> str:
        self._access.require(intent.actor_id, Permission.EXECUTION_PROPOSE)
        return self._ledger.create(
            run_id=intent.run_id, actor_id=intent.actor_id,
            tool_id="payments", operation="charge",
            scope_digest=intent.scope(policy=self._policy, context=self._context).digest(),
        )

    def approve(self, execution_id: str, intent: ChargeIntent, *, approver_id: str,
                ttl_seconds: float = 300.0) -> str:
        """Bind an approval to this exact charge. A different charge cannot use it."""
        self._access.require_approval_separation(
            approver_id=approver_id, requester_id=intent.actor_id
        )
        return self._ledger.approve(
            execution_id, approver_id=approver_id,
            scope_digest=intent.scope(policy=self._policy, context=self._context).digest(),
            ttl_seconds=ttl_seconds,
        )

    def dispatch(self, lease_id: str, intent: ChargeIntent, *, actor_id: str) -> dict[str, Any]:
        """Claim the lease, then charge. Never the other way round."""
        self._access.require(actor_id, Permission.EXECUTION_DISPATCH)

        # Recomputed now, not reused from approval time: if the amount, payee, or
        # bound context changed since, this no longer matches and the lease is
        # refused rather than spent.
        scope_digest = intent.scope(policy=self._policy, context=self._context).digest()
        execution_id = self._ledger.claim_lease(lease_id, scope_digest=scope_digest)
        if execution_id is None:
            raise PaymentRefused(
                "lease is unusable: spent, expired, revoked, or bound to a different charge"
            )

        try:
            response = self._processor(
                intent_id=execution_id, amount=intent.amount,
                currency=intent.currency, payee_id=intent.payee_id,
                idempotency_key=execution_id,
            )
        except Exception as error:  # the processor was called; the result is unknown
            self._ledger.record_outcome(
                execution_id, state=UNKNOWN,
                evidence={"reason": str(error), "stage": "dispatch"},
            )
            raise OutcomeUncertain(execution_id, str(error)) from error

        state = SUCCEEDED if response.get("status") == "succeeded" else FAILED
        self._ledger.record_outcome(
            execution_id, state=state,
            evidence={"status": response.get("status"),
                      "charge_id": response.get("charge_id")},
        )
        return {"execution_id": execution_id, **dict(response)}

    # -- resolving what was left uncertain -----------------------------------

    def reconcile(self, execution_id: str, *, reconciler_id: str) -> str:
        """Ask the processor what happened, then record a final state.

        Without a lookup the honest answer is that it cannot be established, and
        the execution terminates as PERMANENTLY_UNRESOLVED rather than being
        guessed at or quietly retried.
        """
        self._access.require(reconciler_id, Permission.EXECUTION_RECONCILE)
        record = self._ledger.get(execution_id)
        if record is None or record.state != UNKNOWN:
            raise PaymentRefused("reconciliation applies only to an UNKNOWN execution")

        if self._lookup is None:
            self._ledger.reconcile(
                execution_id, new_state="PERMANENTLY_UNRESOLVED",
                reconciler_id=reconciler_id,
                evidence={"reason": "the processor offers no way to look up this charge"},
            )
            return "PERMANENTLY_UNRESOLVED"

        try:
            observed = self._lookup(execution_id)
        except Exception as error:
            self._ledger.reconcile(
                execution_id, new_state="PERMANENTLY_UNRESOLVED",
                reconciler_id=reconciler_id,
                evidence={"reason": f"lookup failed: {error}"},
            )
            return "PERMANENTLY_UNRESOLVED"

        state = SUCCEEDED if observed.get("status") == "succeeded" else FAILED
        self._ledger.reconcile(
            execution_id, new_state=state, reconciler_id=reconciler_id,
            evidence={"external_lookup": dict(observed)},
        )
        return state

    def recover(self) -> tuple[str, ...]:
        """After a restart, mark anything caught mid-dispatch as UNKNOWN."""
        return self._ledger.recover_interrupted()

    def state_of(self, execution_id: str) -> str | None:
        record = self._ledger.get(execution_id)
        return record.state if record else None
