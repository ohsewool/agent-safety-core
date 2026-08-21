"""대문자 하나로 자기 요청을 자기가 승인할 수 있었다.

권한 분리 검사 둘 — `self-approval refused`, `self-reconciliation refused` — 은
호출자가 준 문자열을 `==`로 비교했다. **에이전트는 자기 `approver_id`를 스스로
고른다.** 그래서 통제 전체가 철자에 달려 있었다.

2026-08-22, `actor_id="agent-1"`인 실행에 대해 측정한 결과다.

===========================  ==========
`approver_id`                결과
===========================  ==========
``"agent-1"``                거절
``"Agent-1"``                **승인됨**
``"AGENT-1"``                **승인됨**
``" agent-1"``               **승인됨**
``"agent-1\\n"``              **승인됨**
``"agent\\u20111"``           **승인됨**
===========================  ==========

첫 줄 말고는 전부 같은 주체가 모자만 바꿔 쓴 것이다.

정규화(NFKC → strip → casefold)는 그 자체로 안전한 방향이다 — 거절을 **넓힐 수만
있고 좁힐 수는 없다.** 그것만으로는 부족하다: **NFKC는 `\\u2011`(non-breaking
hyphen)을 ASCII `-`로 접지 않는다.** 유사 문자는 비교에는 다른 주체이고 읽는
사람에게는 같은 주체다. 그래서 문자 집합도 제한한다 — `mcp-gateway`의
`_valid_identifier`가 이미 하고 있던 방식이다.

대가는 주체 식별자가 ASCII여야 한다는 것이다. 원장에서 기계 대 기계의 신원에는
맞는 거래다. 사람이 읽는 이름은 비교에 쓰이지 않는 곳에 있어야 한다.

같은 회차에 `modelmate`에서 같은 형태를 찾았다: 가입의 중복 검사(대소문자 구분)와
관리자 판정(소문자 비교)이 달라서, `ADMIN@modelmate.local`로 가입하면 관리자
계정이 하나 더 만들어졌다. **한 질문에 두 개의 동일성 기준.**
"""

from __future__ import annotations

import pytest

from core.ledger import UNKNOWN, ExecutionLedger, LedgerError, normalize_principal

SCOPE = "d" * 64
SPELLINGS = ["Agent-1", "AGENT-1", " agent-1", "agent-1 ", "agent-1\n", "\tagent-1"]


@pytest.fixture
def ledger(tmp_path):
    instance = ExecutionLedger(str(tmp_path / "principal.db"))
    try:
        yield instance
    finally:
        instance.close()


def requested(instance, actor="agent-1"):
    return instance.create(run_id="run", actor_id=actor, tool_id="tool",
                           operation="write", scope_digest=SCOPE)


class TestSelfApprovalSurvivesRespelling:
    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_the_requester_cannot_approve_under_another_spelling(self, ledger, spelling):
        execution_id = requested(ledger)
        with pytest.raises(LedgerError, match="self-approval"):
            ledger.approve(execution_id, approver_id=spelling, scope_digest=SCOPE,
                           ttl_seconds=60)

    def test_a_look_alike_character_is_refused_outright(self, ledger):
        """NFKC는 `\\u2011`을 ASCII 하이픈으로 접지 않는다. 정규화만으로는
        이것이 **다른 주체**로 통과한다 — 문자 집합 제한이 막는 부분이다."""
        execution_id = requested(ledger)
        with pytest.raises(LedgerError, match="may only contain"):
            ledger.approve(execution_id, approver_id="agent‑1", scope_digest=SCOPE,
                           ttl_seconds=60)

    def test_a_genuinely_different_principal_still_approves(self, ledger):
        """대조. 전부 거절하는 검사로도 위 검사들은 통과한다."""
        execution_id = requested(ledger)
        assert ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE,
                              ttl_seconds=60)

    def test_the_requester_spelt_differently_is_still_refused_after_a_valid_one_fails(
            self, ledger):
        """거절이 실행을 망가뜨리지 않는지. 오타 한 번이 그 실행을 영영 승인 못 하게
        만들면 안 된다."""
        execution_id = requested(ledger)
        with pytest.raises(LedgerError):
            ledger.approve(execution_id, approver_id="AGENT-1", scope_digest=SCOPE,
                           ttl_seconds=60)
        assert ledger.approve(execution_id, approver_id="Human-1", scope_digest=SCOPE,
                              ttl_seconds=60)


class TestSelfReconciliationSurvivesRespelling:
    """UNKNOWN을 남긴 주체가 그 결과를 스스로 선언할 수 없다. 같은 우회가 있었다."""

    def unknown_execution(self, ledger):
        execution_id = requested(ledger)
        lease = ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE,
                               ttl_seconds=60)
        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state=UNKNOWN, evidence={"reason": "timeout"})
        return execution_id

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_the_actor_cannot_reconcile_under_another_spelling(self, ledger, spelling):
        execution_id = self.unknown_execution(ledger)
        with pytest.raises(LedgerError, match="self-reconciliation"):
            ledger.reconcile(execution_id, new_state="SUCCEEDED", reconciler_id=spelling,
                             evidence={"note": "it worked, trust me"})

    def test_someone_else_can_reconcile(self, ledger):
        execution_id = self.unknown_execution(ledger)
        ledger.reconcile(execution_id, new_state="SUCCEEDED", reconciler_id="Operator-1",
                         evidence={"note": "checked the downstream system"})
        assert ledger.get(execution_id).state == "SUCCEEDED"


class TestTheLedgerStoresOneSpelling:
    def test_the_actor_is_recorded_normalised(self, ledger):
        execution_id = requested(ledger, actor="  Agent-1  ")
        assert ledger.get(execution_id).actor_id == "agent-1"

    def test_two_spellings_are_the_same_principal(self, ledger):
        first = ledger.get(requested(ledger, actor="AGENT-1")).actor_id
        second = ledger.get(requested(ledger, actor="agent-1")).actor_id
        assert first == second


class TestTheNormaliserItself:
    @pytest.mark.parametrize("value,expected", [
        ("Agent-1", "agent-1"),
        ("  AGENT-1  ", "agent-1"),
        ("agent-1\n", "agent-1"),
        ("ＡＧＥＮＴ-1", "agent-1"),          # 전각 - NFKC가 접는다
        ("human@example.com", "human@example.com"),
    ])
    def test_it_folds_what_it_should(self, value, expected):
        assert normalize_principal(value, field="actor_id") == expected

    @pytest.mark.parametrize("value", ["", "   ", "\n", "\t"])
    def test_an_empty_principal_is_refused(self, value):
        with pytest.raises(LedgerError, match="must not be empty"):
            normalize_principal(value, field="actor_id")

    @pytest.mark.parametrize("value", [None, 1, True, ["agent-1"]])
    def test_a_non_string_is_refused(self, value):
        with pytest.raises(LedgerError, match="must be a string"):
            normalize_principal(value, field="actor_id")

    @pytest.mark.parametrize("value", ["agent‑1", "agent 1", "agent/1", "에이전트-1",
                                       "agent\x001"])
    def test_characters_outside_the_set_are_refused(self, value):
        with pytest.raises(LedgerError, match="may only contain"):
            normalize_principal(value, field="actor_id")

    def test_the_message_names_the_field(self, ledger):
        """어느 인자가 문제인지 말하지 않으면 부르는 쪽은 넷 중 무엇인지 모른다."""
        with pytest.raises(LedgerError, match="approver_id"):
            normalize_principal("", field="approver_id")


class TestTheseChecksAreNotVacuous:
    def test_normalising_is_not_the_identity(self):
        """정규화가 입력을 그대로 돌려주면 위 검사 대부분이 통과하면서 아무것도
        하지 않는다."""
        assert normalize_principal("AGENT-1", field="actor_id") != "AGENT-1"

    def test_the_ordinary_identifiers_this_repository_uses_still_pass(self):
        """새 검사가 기존 식별자를 거절하면 배선이 통째로 죽는다."""
        for value in ("agent-1", "human-1", "reconciler-1", "operator-1", "r1", "a", "h"):
            assert normalize_principal(value, field="actor_id") == value

    def test_normalisation_can_only_broaden_the_refusal(self, ledger):
        """접은 결과가 서로 다르면 원래 문자열도 달랐다 — 그러니 이 변경으로
        예전에 거절되던 것이 승인되는 일은 없다."""
        execution_id = requested(ledger, actor="agent-1")
        assert ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE,
                              ttl_seconds=60)
