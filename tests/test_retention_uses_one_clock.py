"""보존 판단에 시계가 둘이었다.

`PayloadStore`는 `clock`을 받고 `RetentionSchedule`도 **자기 clock**을 받는다.
`created_at`은 store의 시계에서 나오고, "지금"은 schedule의 시계에서 나왔다.
**서로 다른 시계에서 나온 두 시각을 빼는 것은 아무 뜻이 없다.**

2026-08-22에 쟀다. store에만 테스트 시계(1000.0)를 주고 schedule은 기본값(벽시계)으로
두면, **10년 보존 클래스의 payload가 즉시 파기됐다** — 1000과 2026년의 초를 비교해
"기간이 한참 지났다"고 판단한다. 열려 있는 방향으로 실패한다.

프로덕션에서는 둘 다 `time.time()`이라 일치한다. 그래서 이 실패는 **시간을 통제하는
곳에서만** 나타난다 — 테스트, 재현, 시계를 고정한 배포. 하필 보존 통제를 실제로
시험하는 자리다.

`destroy`가 이제 자기 시계를 `now=`로 넘긴다. `created_at`을 만든 시계가 판단도 한다.

**내가 이 API에서 네 번 틀리고 나서야 여기 도달했다.** `minimum_seconds`라는 없는
인자, `destroy`의 필수 인자 둘 누락, 참조 대신 문자열 전달, 그리고 시계를 하나만 준 것.
마지막 것이 진짜 결함이었고 앞의 셋은 내 실수였다 — 구분하지 못했으면 셋 중 하나를
결함으로 적었을 것이다.
"""

from __future__ import annotations

import pytest

from core.payload import PayloadStore
from core.retention import RetentionClass, RetentionSchedule


class Clock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def store_with(tmp_path, *, minimum_days: float, schedule_clock=None, store_clock=None):
    schedule = RetentionSchedule(
        (RetentionClass("standard", minimum_days, "시험을 위한 보존 기간"),),
        clock=schedule_clock) if schedule_clock else RetentionSchedule(
        (RetentionClass("standard", minimum_days, "시험을 위한 보존 기간"),))
    return PayloadStore(tmp_path, schedule=schedule, clock=store_clock)


class TestTheStoresClockDecides:
    def test_a_long_period_holds_even_when_only_the_store_has_a_clock(self, tmp_path):
        """이것이 결함이었다. schedule에 시계를 주지 않는 것은 자연스러운 호출이다 —
        만드는 것은 store이고, 시계는 store에 준다."""
        clock = Clock()
        store = store_with(tmp_path / "a", minimum_days=3650.0, store_clock=clock)
        reference = store.put({"secret": "x"}, retention_class="standard")
        with pytest.raises(Exception, match="may not be destroyed"):
            store.destroy(reference, requester="operator-1", reason="즉시")

    def test_it_becomes_destroyable_once_that_clock_moves_past_the_period(self, tmp_path):
        """전부 거절하는 통제는 통제가 아니라 고장이다."""
        clock = Clock()
        store = store_with(tmp_path / "b", minimum_days=1.0, store_clock=clock)
        reference = store.put({"secret": "x"}, retention_class="standard")
        clock.now += 86400 + 1
        assert store.destroy(reference, requester="operator-1", reason="기한 뒤")

    def test_both_clocks_agreeing_still_works(self, tmp_path):
        """예전에 통하던 호출 방식이 깨지면 안 된다."""
        clock = Clock()
        store = store_with(tmp_path / "c", minimum_days=1.0,
                           schedule_clock=clock, store_clock=clock)
        reference = store.put({"secret": "x"}, retention_class="standard")
        with pytest.raises(Exception, match="may not be destroyed"):
            store.destroy(reference, requester="operator-1", reason="기한 전")
        clock.now += 86400 + 1
        assert store.destroy(reference, requester="operator-1", reason="기한 뒤")


class TestSweepTakesTheCallersClockToo:
    """`destroy`만 고치면 절반이다. `pending_retention()`이 만드는 것이 정확히
    `sweep()`의 입력이라, **의도된 사용법 자체가 두 시계를 섞는다**:

        schedule.sweep(store.pending_retention())

    `created_at`은 store에서, `now`는 schedule에서 온다. 10년 보존 payload가
    쓰이자마자 `eligible`로 나온다.
    """

    def test_sweep_accepts_a_now(self, tmp_path):
        schedule = RetentionSchedule(
            (RetentionClass("standard", 3650.0, "10년 보존"),))
        payloads = [{"payload_id": "p1", "retention_class": "standard",
                     "created_at": 1000.0}]
        assert schedule.sweep(payloads, now=1000.0)[0].action == "keep"

    def test_without_now_it_still_reads_its_own_clock(self, tmp_path):
        """기본 동작은 그대로다 — 기존 호출자를 깨뜨리지 않는다."""
        schedule = RetentionSchedule(
            (RetentionClass("standard", 0.0, "보존 없음"),))
        payloads = [{"payload_id": "p1", "retention_class": "standard",
                     "created_at": 0.0}]
        assert schedule.sweep(payloads)[0].action == "eligible"

    def test_overdue_threads_it_as_well(self):
        """`overdue`는 `sweep`을 부른다. 한쪽만 고치면 다른 쪽으로 같은 구멍이 남는다."""
        schedule = RetentionSchedule(
            (RetentionClass("capped", 0.0, "짧게", maximum_days=1.0),))
        payloads = [{"payload_id": "p1", "retention_class": "capped",
                     "created_at": 1000.0}]
        assert schedule.overdue(payloads, now=1000.0) == ()
        assert len(schedule.overdue(payloads, now=1000.0 + 86400 * 2)) == 1

    def test_the_store_offers_the_call_that_cannot_be_got_wrong(self, tmp_path):
        clock = Clock()
        store = store_with(tmp_path / "s", minimum_days=3650.0, store_clock=clock)
        store.put({"secret": "x"}, retention_class="standard")
        assert store.retention_status()[0].action == "keep"
        clock.now += 3650 * 86400 + 1
        assert store.retention_status()[0].action == "eligible"

    def test_the_easy_wrong_call_is_still_possible_and_that_is_why_the_method_exists(
            self, tmp_path):
        """손으로 `now`를 넘기는 것도 되지만 **기억해야 한다**. 기억에 기대는 통제가
        잊히는 통제다 — 그래서 시계를 가진 쪽이 부르는 길을 뒀다."""
        clock = Clock()
        store = store_with(tmp_path / "t", minimum_days=3650.0, store_clock=clock)
        store.put({"secret": "x"}, retention_class="standard")
        assert store._schedule.sweep(store.pending_retention())[0].action == "eligible"

    def test_a_store_without_a_schedule_says_so(self, tmp_path):
        """조용히 빈 결과를 주면 "보존 대상 없음"으로 읽힌다."""
        store = PayloadStore(tmp_path / "u")
        with pytest.raises(Exception, match="no retention schedule"):
            store.retention_status()


class TestWithoutAScheduleNothingChanges:
    """schedule이 없으면 예전처럼 동작한다 — 보존을 **명시적 선택**으로 두는 설계다."""

    def test_destruction_is_immediate(self, tmp_path):
        store = PayloadStore(tmp_path / "d")
        reference = store.put({"secret": "y"}, retention_class="standard")
        assert store.destroy(reference, requester="operator-1", reason="schedule 없음")


class TestTheDecisionStillAsksWhoAndWhy:
    def test_destroy_requires_a_requester_and_a_reason(self, tmp_path):
        """누가 왜 지웠는지 없는 파기는 기록이 아니다. 시계를 고치다 이걸 잃으면 안 된다."""
        store = PayloadStore(tmp_path / "e")
        reference = store.put({"secret": "z"})
        with pytest.raises(TypeError):
            store.destroy(reference)


class TestTheChecksAreNotVacuous:
    def test_the_period_is_actually_long(self, tmp_path):
        """3650일이 0일로 읽히면 위 첫 검사는 아무것도 확인하지 않는다."""
        rule = RetentionClass("standard", 3650.0, "10년")
        assert rule.eligible_at(0.0) > 3600 * 24 * 3000

    def test_a_shorter_period_is_distinguishable(self, tmp_path):
        clock = Clock()
        store = store_with(tmp_path / "f", minimum_days=0.0, store_clock=clock)
        reference = store.put({"secret": "x"}, retention_class="standard")
        assert store.destroy(reference, requester="operator-1", reason="보존 0일")

    def test_the_store_passes_its_own_clock(self):
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "core" / "payload.py").read_text(
            encoding="utf-8")
        # 처음엔 첫 `)`까지 잘랐는데 그것은 `self._retention.get(...)`의 괄호였다.
        # 이 파일에서 다섯 번째 파싱 실수라, 짧게 자르지 않고 넉넉한 창을 본다.
        start = source.index("require_destroyable(")
        body = source[start:start + 900]
        assert "now=self._clock()" in body
        assert "created_at=created_at" in body
