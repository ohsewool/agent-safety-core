"""Resolving an uncertain outcome by looking at the world, not by asking again.

`reconcile()` in the ledger settles an UNKNOWN by querying the system that
performed the action. That works when the processor is healthy and the response
merely got lost, and it fails in the case most worth handling: the processor is
the thing that broke, so the lookup travels the same broken path as the response
did and returns nothing useful.

A postcondition is a different channel. Instead of asking "did you do it?", it
asks "is the world in the state that doing it would have produced?" — is the
customer active, does the file exist with this content, is the balance reduced.
That question can often be answered from a replica, a cache, or a different
service entirely, so it survives the failure that made the outcome uncertain.

The ordering matters and is the point:

    UNKNOWN  →  verify postcondition  →  satisfied?  →  SUCCEEDED (no retry)
                                      →  unsatisfied? →  retry is now safe
                                      →  unobservable? →  PERMANENTLY_UNRESOLVED

Retrying without this check is how one action becomes two. Retrying *after* it,
when the postcondition says the effect never landed, is safe and is the reason
the caution does not cost completed work.

Grounded in Verified Tool Calls Improve LLM Agent Reliability Under Non-Atomic
Failures (arXiv:2608.02645), whose measured result is that verification rather
than retry policy is what reduces duplicate actions. Its stated limits apply
here too: postconditions are written by hand, and a verifier that misreads the
world is believed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from .ledger import FAILED, PERMANENTLY_UNRESOLVED, SUCCEEDED, UNKNOWN, ExecutionLedger


class Observation(str, Enum):
    """What a postcondition check concluded."""

    SATISFIED = "satisfied"        # the effect is present; it happened
    UNSATISFIED = "unsatisfied"    # the effect is absent; it did not happen
    UNOBSERVABLE = "unobservable"  # the check itself could not be performed


@dataclass(frozen=True)
class PostconditionResult:
    """One observation, with the evidence that produced it."""

    observation: Observation
    detail: Mapping[str, Any]
    channel: str = "postcondition"

    @property
    def conclusive(self) -> bool:
        return self.observation is not Observation.UNOBSERVABLE


@dataclass(frozen=True)
class Postcondition:
    """A named check on the world, independent of the tool's own reply.

    ``check`` receives the execution id and returns True, False, or None, where
    None means the check could not be made. The distinction between False and
    None is the whole value: "it did not happen" permits a retry, "I could not
    tell" does not.
    """

    name: str
    check: Callable[[str], bool | None]
    channel: str = "postcondition"

    def observe(self, execution_id: str) -> PostconditionResult:
        try:
            outcome = self.check(execution_id)
        except Exception as error:
            return PostconditionResult(
                Observation.UNOBSERVABLE,
                {"postcondition": self.name, "error": str(error)},
                self.channel,
            )
        if outcome is None:
            return PostconditionResult(
                Observation.UNOBSERVABLE,
                {"postcondition": self.name, "reason": "check returned no answer"},
                self.channel,
            )
        return PostconditionResult(
            Observation.SATISFIED if outcome else Observation.UNSATISFIED,
            {"postcondition": self.name},
            self.channel,
        )


class VerificationError(RuntimeError):
    """Raised when verification is attempted on an execution that does not want it."""


class Verifier:
    """Settles UNKNOWN executions by observing effects rather than asking again.

    Several postconditions may be supplied for one execution. They are consulted
    in order and the first conclusive answer wins, which lets a cheap local check
    run before an expensive remote one. Disagreement is not averaged: if any
    check says the effect is present, the effect is present, because a false
    "it did not happen" is what produces a duplicate.
    """

    def __init__(self, ledger: ExecutionLedger) -> None:
        self._ledger = ledger

    def verify(self, execution_id: str, postconditions: list[Postcondition]) -> PostconditionResult:
        """Observe without recording. Used to decide whether a retry is safe."""
        results = [condition.observe(execution_id) for condition in postconditions]
        satisfied = [item for item in results if item.observation is Observation.SATISFIED]
        if satisfied:
            return satisfied[0]
        unsatisfied = [item for item in results if item.observation is Observation.UNSATISFIED]
        if unsatisfied:
            return unsatisfied[0]
        return PostconditionResult(
            Observation.UNOBSERVABLE,
            {"attempted": [condition.name for condition in postconditions]},
        )

    def settle(self, execution_id: str, postconditions: list[Postcondition], *,
               reconciler_id: str) -> str:
        """Verify an UNKNOWN execution and record the state it establishes."""
        record = self._ledger.get(execution_id)
        if record is None:
            raise VerificationError(f"unknown execution: {execution_id}")
        if record.state != UNKNOWN:
            raise VerificationError(
                f"verification applies to UNKNOWN executions; this one is {record.state}"
            )

        result = self.verify(execution_id, postconditions)
        if result.observation is Observation.SATISFIED:
            new_state = SUCCEEDED
        elif result.observation is Observation.UNSATISFIED:
            new_state = FAILED
        else:
            new_state = PERMANENTLY_UNRESOLVED

        self._ledger.reconcile(
            execution_id, new_state=new_state, reconciler_id=reconciler_id,
            evidence={"channel": result.channel, "observation": result.observation.value,
                      **dict(result.detail)},
        )
        return new_state

    def retry_is_safe(self, execution_id: str, postconditions: list[Postcondition]) -> bool:
        """May this action be attempted again?

        Only when the world says the effect is absent. An unobservable check is
        not permission — that is precisely the state in which a retry duplicates.
        """
        return self.verify(execution_id, postconditions).observation is Observation.UNSATISFIED


def postcondition(name: str, *, channel: str = "postcondition"):
    """Decorator form, for defining checks next to the tool they belong to.

        @postcondition("customer is active", channel="replica")
        def customer_activated(execution_id: str) -> bool | None:
            ...
    """
    def wrap(function: Callable[[str], bool | None]) -> Postcondition:
        return Postcondition(name=name, check=function, channel=channel)
    return wrap
