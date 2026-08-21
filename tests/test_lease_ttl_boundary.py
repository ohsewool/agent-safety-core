"""lease는 정확히 언제 만료되는가, 그리고 만료하지 **않는** lease를 만들 수 있는가.

`test_expired_lease_is_refused_and_marked`는 이미 만료된 lease가 거절되는지 본다
(ttl 10초, 11초 뒤). 그 사이의 순간은 아무도 정하지 않았고, 더 나쁜 것은 **만료가
아예 없는 lease를 만들 수 있었다**는 것이다.

2026-08-22에 쟀다.

`ttl_seconds=float("nan")`
    `now + nan`은 `nan`이고, SQLite는 그것을 NULL로 저장한다. 이 스키마에서 NULL은
    **"만료 없음"**이다 — `claim_lease`의 만료 검사가 `expires_at is not None`으로
    시작한다. 1분짜리로 의도한 승인이 영원히 살았고, 행에는 이상하다는 표시가 없다.
    시뮬레이션한 30년 뒤에도 소비됐다.

`ttl_seconds=float("inf")`
    `now > inf`가 참이 되는 순간은 없다. 같은 결과다.

둘 다 만들기 어려운 값이 아니다. 설정에서 읽거나 나눗셈을 하거나 문자열을 파싱하면
다른 float과 똑같이 도착한다. **lease는 일회용이면서 시간 제한이 있는 것이고, 그중
절반만으로는 통제가 아니다.**

경계 자체도 정한다: `now > expires_at`이므로 **정확히 만료 시각까지는 유효**하다.
60초 TTL은 t+60에 쓸 수 있고 t+60.001에는 못 쓴다. 그 판단이 옳은지가 아니라
**정해져 있고 검사가 있는지**가 요점이다 — `>=`로 바꾸면 조용히 동작이 바뀌고
지금까지는 아무 테스트도 울지 않았다.

이 파일은 `modelmate`의 한도 경계를 재던 회차에서 나왔다. 거기서는 전부 정확했다
(행 50 통과·51 거절, 열 5 통과·6 거절, 프로젝트 2개 통과·3번째 거절). 같은 질문을
여기 들고 오니 나왔다.
"""

from __future__ import annotations

import math

import pytest

from core.ledger import EXPIRED, ExecutionLedger, LedgerError

SCOPE = "d" * 64
START = 1000.0


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def ledger(tmp_path):
    clock = Clock()
    instance = ExecutionLedger(str(tmp_path / "ttl.db"), clock=clock)
    instance.clock = clock
    try:
        yield instance
    finally:
        instance.close()


def approved(instance, ttl):
    execution_id = instance.create(run_id="r", actor_id="agent", tool_id="t",
                                   operation="op", scope_digest=SCOPE)
    return execution_id, instance.approve(execution_id, approver_id="human",
                                          scope_digest=SCOPE, ttl_seconds=ttl)


class TestALeaseThatCannotExpireIsRefused:
    @pytest.mark.parametrize("ttl", [float("nan"), float("inf"), float("-inf")])
    def test_a_non_finite_ttl_is_refused(self, ledger, ttl):
        execution_id = ledger.create(run_id="r", actor_id="agent", tool_id="t",
                                     operation="op", scope_digest=SCOPE)
        with pytest.raises(LedgerError, match="finite"):
            ledger.approve(execution_id, approver_id="human", scope_digest=SCOPE,
                           ttl_seconds=ttl)

    def test_the_execution_stays_approvable_after_a_refused_ttl(self, ledger):
        """거절이 실행을 망가뜨리면, 오타 한 번이 그 실행을 영영 승인 못 하게 만든다."""
        execution_id = ledger.create(run_id="r", actor_id="agent", tool_id="t",
                                     operation="op", scope_digest=SCOPE)
        with pytest.raises(LedgerError):
            ledger.approve(execution_id, approver_id="human", scope_digest=SCOPE,
                           ttl_seconds=float("nan"))
        lease = ledger.approve(execution_id, approver_id="human", scope_digest=SCOPE,
                               ttl_seconds=60)
        assert ledger.claim_lease(lease, scope_digest=SCOPE) == execution_id

    @pytest.mark.parametrize("ttl", [0, 0.0, -1, -0.001])
    def test_a_non_positive_ttl_is_refused(self, ledger, ttl):
        execution_id = ledger.create(run_id="r", actor_id="agent", tool_id="t",
                                     operation="op", scope_digest=SCOPE)
        with pytest.raises(LedgerError, match="greater than zero"):
            ledger.approve(execution_id, approver_id="human", scope_digest=SCOPE,
                           ttl_seconds=ttl)

    @pytest.mark.parametrize("ttl", ["60", None, True, [60]])
    def test_a_non_number_is_refused(self, ledger, ttl):
        """`True`는 `int`의 하위형이라 숫자 검사를 그냥 통과한다 — 1초짜리 lease가
        되어 조용히 만료된다. 이 저장소가 이미 한 번 만난 함정이다
        (`NetworkConstraint`의 포트 검사가 `bool`을 따로 배제한다)."""
        execution_id = ledger.create(run_id="r", actor_id="agent", tool_id="t",
                                     operation="op", scope_digest=SCOPE)
        with pytest.raises(LedgerError, match="number"):
            ledger.approve(execution_id, approver_id="human", scope_digest=SCOPE,
                           ttl_seconds=ttl)


class TestTheExpiryInstantIsDecided:
    """`now > expires_at`. 정확히 만료 시각까지는 유효하다."""

    def test_just_before_expiry_it_is_claimable(self, ledger):
        execution_id, lease = approved(ledger, 60)
        ledger.clock.now = START + 59.999
        assert ledger.claim_lease(lease, scope_digest=SCOPE) == execution_id

    def test_exactly_at_expiry_it_is_still_claimable(self, ledger):
        execution_id, lease = approved(ledger, 60)
        ledger.clock.now = START + 60
        assert ledger.claim_lease(lease, scope_digest=SCOPE) == execution_id

    def test_just_after_expiry_it_is_refused_and_marked(self, ledger):
        execution_id, lease = approved(ledger, 60)
        ledger.clock.now = START + 60.001
        assert ledger.claim_lease(lease, scope_digest=SCOPE) is None
        assert ledger.get(execution_id).state == EXPIRED

    def test_the_refusal_says_why(self, ledger):
        execution_id, lease = approved(ledger, 60)
        ledger.clock.now = START + 61
        ledger.claim_lease(lease, scope_digest=SCOPE)
        # `events()`는 `detail`을 이미 파싱해서 준다. 처음에 문자열로 보고
        # `in`으로 찾다가 실패했다 - 실패 메시지가 `[{'reason': 'lease_expired'}]`라고
        # 알려줬다.
        reasons = [event["detail"].get("reason") for event in ledger.events(execution_id)
                   if event["kind"] == "claim_refused"]
        assert "lease_expired" in reasons, reasons


class TestTheStoredExpiryIsUsable:
    def test_a_valid_ttl_records_a_finite_expiry(self, ledger):
        execution_id, _ = approved(ledger, 60)
        expires_at = ledger.get(execution_id).expires_at
        assert expires_at is not None
        assert math.isfinite(expires_at)
        assert expires_at == START + 60

    def test_no_approval_can_leave_expiry_null(self, ledger):
        """NULL은 이 스키마에서 "만료 없음"이다. `create`가 NULL로 넣는 것은
        아직 승인되지 않았다는 뜻이고, `approve`를 지나면 값이 있어야 한다."""
        execution_id = ledger.create(run_id="r", actor_id="agent", tool_id="t",
                                     operation="op", scope_digest=SCOPE)
        assert ledger.get(execution_id).expires_at is None
        ledger.approve(execution_id, approver_id="human", scope_digest=SCOPE, ttl_seconds=1)
        assert ledger.get(execution_id).expires_at is not None


class TestTheseChecksAreNotVacuous:
    def test_a_normal_ttl_still_works(self, ledger):
        """전부 거절하는 검증은 전부 거절하는 것으로도 통과한다."""
        execution_id, lease = approved(ledger, 60)
        assert ledger.claim_lease(lease, scope_digest=SCOPE) == execution_id

    def test_the_null_expiry_branch_really_means_forever(self, ledger):
        """이 결함이 왜 결함이었는지를 고정한다. `expires_at`이 NULL이면
        `claim_lease`는 시간을 보지 않는다 — 그 분기가 사라지면 위 검증은
        막고 있던 것이 없어진다."""
        execution_id, lease = approved(ledger, 60)
        ledger._connection.execute(
            "UPDATE executions SET expires_at=NULL WHERE execution_id=?", (execution_id,))
        ledger.clock.now = START + 10 ** 9
        assert ledger.claim_lease(lease, scope_digest=SCOPE) == execution_id, (
            "NULL 만료가 이제 거절된다면 좋은 변화지만, 위 docstring과 "
            "`approve`의 설명이 함께 바뀌어야 한다."
        )

    def test_the_guarded_tool_default_is_a_usable_ttl(self):
        """어댑터가 기본값으로 넘기는 값이 새 검증에 걸리면 배선이 통째로 죽는다."""
        import inspect

        from adapters.guarded_tool import ToolGuard

        # `ToolGuard.request`가 아니라 `ToolGuard.approve`가 TTL을 들고 있다.
        # 승인은 사람의 몫이라 에이전트가 부르는 래퍼와 일부러 떨어뜨려 뒀다.
        default = inspect.signature(ToolGuard.approve).parameters["ttl_seconds"].default
        assert isinstance(default, (int, float)) and not isinstance(default, bool)
        assert math.isfinite(default) and default > 0
