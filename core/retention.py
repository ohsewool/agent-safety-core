"""How long something is kept, and who decides when that stops being true.

`retention_class` was a label on a payload and nothing enforced it. A label that
enforces nothing is worse than no label: it reads like a control in an audit and
behaves like a comment.

Three rules, each answering a question that comes up in practice:

how long
    A class states a period. Nothing is deleted before it elapses, so an
    over-eager cleanup script cannot destroy evidence someone is still entitled
    to.

when it may go
    Reaching the end of a period makes a payload *eligible*, not deleted.
    Deletion stays an act someone performs and the log records, because "the
    system deleted it automatically" is not an answer an auditor accepts.

when it may not
    A legal hold outranks the schedule in both directions: held data is not
    destroyed even when expired, and the conflict is reported rather than
    resolved. "We were required to keep it" and "we were required to delete it"
    is a question for a person.

Time is injected rather than read from the clock so schedules are testable
exactly, and because a retention decision that silently depends on system time
is a retention decision that changes when the clock is wrong.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

DAY = 86400.0


class RetentionError(RuntimeError):
    """Raised when a retention rule is unknown or a decision contradicts one."""


@dataclass(frozen=True)
class RetentionClass:
    """A named period, with the reason it exists.

    ``minimum_days`` is a floor, not a target: it is the period during which
    deletion is refused. ``rationale`` is required because a retention period
    nobody can justify is one nobody can defend when it is questioned.
    """

    name: str
    minimum_days: float
    rationale: str
    maximum_days: float | None = None

    def __post_init__(self) -> None:
        if self.minimum_days < 0:
            raise RetentionError(f"{self.name}: a retention period cannot be negative")
        if not self.rationale:
            raise RetentionError(f"{self.name}: a retention class needs a stated reason")
        if self.maximum_days is not None and self.maximum_days < self.minimum_days:
            raise RetentionError(
                f"{self.name}: maximum retention is shorter than the minimum"
            )

    def eligible_at(self, created_at: float) -> float:
        return created_at + self.minimum_days * DAY

    def due_at(self, created_at: float) -> float | None:
        """When deletion becomes overdue, for classes that cap how long data is kept."""
        if self.maximum_days is None:
            return None
        return created_at + self.maximum_days * DAY


DEFAULT_CLASSES: tuple[RetentionClass, ...] = (
    RetentionClass("transient", 0, "운영 디버깅용. 보존 의무 없음", maximum_days=7),
    RetentionClass("standard", 90, "일반 실행 증적. 분쟁 제기 기간을 감안", maximum_days=365),
    RetentionClass("financial", 1825, "결제 관련 기록. 상법상 장부 보존 기간 참고"),
    RetentionClass("legal_hold_candidate", 2555, "분쟁 가능성이 확인된 기록"),
)


@dataclass(frozen=True)
class RetentionDecision:
    """Whether a payload may be destroyed now, and why."""

    payload_id: str
    action: str          # keep | eligible | overdue | held
    reason: str
    eligible_at: float
    due_at: float | None = None

    @property
    def may_destroy(self) -> bool:
        return self.action in {"eligible", "overdue"}


class RetentionSchedule:
    """Applies retention classes to payloads, and refuses to be talked out of it."""

    def __init__(self, classes: Iterable[RetentionClass] = DEFAULT_CLASSES,
                 *, clock: Callable[[], float] | None = None) -> None:
        self._classes = {item.name: item for item in classes}
        if not self._classes:
            raise RetentionError("a schedule needs at least one retention class")
        self._clock = clock or (lambda: __import__("time").time())

    def get(self, name: str) -> RetentionClass:
        rule = self._classes.get(name)
        if rule is None:
            raise RetentionError(
                f"unknown retention class: {name}. An unclassified payload is not "
                "deletable, because nobody has said how long it must be kept."
            )
        return rule

    def decide(self, payload_id: str, *, retention_class: str, created_at: float,
               on_hold: bool = False, now: float | None = None) -> RetentionDecision:
        """`now` lets the caller supply the clock that produced `created_at`.

        Without it this schedule reads its own clock, and `created_at` comes from
        whoever stored the payload. Two clocks answering one question is the
        shape this project keeps finding, and here it fails open: a store given a
        test clock and a schedule left on wall time compared a timestamp of 1000
        against 2026, concluded the period had long elapsed, and allowed a
        payload under a **ten-year** class to be destroyed at once. Measured
        2026-08-22.

        In production both default to `time.time()` and agree, so the failure
        only appears where time is controlled - tests, replays, a frozen-clock
        deployment. That is precisely where a retention control gets exercised.
        """
        rule = self.get(retention_class)
        eligible_at = rule.eligible_at(created_at)
        due_at = rule.due_at(created_at)
        now = self._clock() if now is None else now

        if on_hold:
            # Reported in both directions: a hold that outlives the schedule is a
            # conflict a person has to resolve, not one the system resolves.
            reason = (
                "legal hold is in force; the retention period has already elapsed"
                if now >= eligible_at else
                "legal hold is in force"
            )
            return RetentionDecision(payload_id, "held", reason, eligible_at, due_at)

        if now < eligible_at:
            remaining = (eligible_at - now) / DAY
            return RetentionDecision(
                payload_id, "keep",
                f"{remaining:.1f} days remain of the {rule.name} retention period",
                eligible_at, due_at,
            )
        if due_at is not None and now >= due_at:
            return RetentionDecision(
                payload_id, "overdue",
                f"{rule.name} caps retention and that limit has passed",
                eligible_at, due_at,
            )
        return RetentionDecision(
            payload_id, "eligible",
            f"the {rule.name} retention period has elapsed",
            eligible_at, due_at,
        )

    def sweep(self, payloads: Iterable[Mapping[str, Any]],
              *, now: float | None = None) -> tuple[RetentionDecision, ...]:
        """Decide for many payloads. Returns decisions; destroys nothing.

        Deliberately not a deleter. A sweep that deleted would make destruction a
        background job, and destruction is an act that needs an actor in the log.

        `created_at` arrives from the caller, so `now` should too. Without it this
        compares someone else's timestamps against this schedule's own clock, and
        the two have no relationship. `destroy` had the same hole and it failed
        open: a payload under a **ten-year** class was reported `eligible` the
        moment it was written, because a `created_at` of 1000.0 sits far behind
        wall time. Measured 2026-08-22, here and in `PayloadStore.destroy`.
        """
        return tuple(
            self.decide(
                item["payload_id"],
                retention_class=item.get("retention_class", "standard"),
                created_at=item["created_at"],
                on_hold=bool(item.get("on_hold")),
                now=now,
            )
            for item in payloads
        )

    def require_destroyable(self, payload_id: str, *, retention_class: str,
                            created_at: float, on_hold: bool = False,
                            now: float | None = None) -> RetentionDecision:
        """Raise unless this payload may be destroyed right now."""
        decision = self.decide(payload_id, retention_class=retention_class,
                               created_at=created_at, on_hold=on_hold, now=now)
        if not decision.may_destroy:
            raise RetentionError(f"{payload_id} may not be destroyed: {decision.reason}")
        return decision

    def overdue(self, payloads: Iterable[Mapping[str, Any]],
                *, now: float | None = None) -> tuple[RetentionDecision, ...]:
        """Payloads kept past their maximum — the failure a schedule should surface."""
        return tuple(item for item in self.sweep(payloads, now=now)
                     if item.action == "overdue")

    def describe(self) -> list[dict[str, Any]]:
        """The schedule as a reviewer sees it."""
        return [
            {"name": rule.name, "minimum_days": rule.minimum_days,
             "maximum_days": rule.maximum_days, "rationale": rule.rationale}
            for rule in sorted(self._classes.values(), key=lambda item: item.name)
        ]
