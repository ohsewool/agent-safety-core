"""거절당한 시도가 원장에 남는가.

`claim_lease`는 거절할 때마다 `claim_refused` 이벤트를 쓴다. `approve`와
`reconcile`은 아무것도 쓰지 않았다. **같은 종류의 거절인데 한쪽만 기록됐고, 왜
다른지는 어디에도 없었다.**

이유는 구조에 있었다. `_transaction`은 예외가 나면 ROLLBACK한다. `claim_lease`는
이벤트를 쓰고 **`return None`**으로 빠져나가 살아남았고, 나머지 둘은 `raise`로
빠져나가 이벤트가 거절과 함께 사라졌다.

2026-08-22에 쟀다. 자기승인 5회 + 범위 불일치 3회, **총 8번의 거절 뒤에도 이벤트는
`created` 하나뿐**이었다. 바로 앞 회차에 시연한 자기승인 우회 탐색
(`Agent-1`·`" agent-1"`·`agent\\u20111`)도 그러니 아무 흔적을 남기지 않았을 것이다.
**거절당한 시도야말로 기록이 존재하는 이유다** — 통제가 막았다는 사실은 통제가
막을 일이 있었다는 뜻이기도 하다.

같은 회차에 `modelmate`에서 반대쪽 절반을 찾았다: 거기서는 실패가 전부 기록되고
**성공한 권한 상승**이 하나도 기록되지 않았다. 두 저장소가 같은 표의 반대편을
비워두고 있었다.

**고치다 한 번 크게 틀렸다.** 거절을 기록하려고 검사와 쓰기를 두 트랜잭션으로
쪼갰고, 그 순간 동시 승인 원자성이 깨졌다 — 두 워커가 각자 검사를 통과해 둘 다
승인한다. 두 회차 전에 쓴 `test_concurrent_approvals_issue_exactly_one`이 2를 세면서
잡아냈다. 지금은 검사와 쓰기가 한 트랜잭션 안에 있고, **거절 기록만 밖에서** 한다 —
그쪽은 원자적일 필요가 없다.
"""

from __future__ import annotations

import pytest

from core.ledger import UNKNOWN, ExecutionLedger, LedgerError

SCOPE = "d" * 64
OTHER_SCOPE = "e" * 64


@pytest.fixture
def ledger(tmp_path):
    instance = ExecutionLedger(str(tmp_path / "evidence.db"))
    try:
        yield instance
    finally:
        instance.close()


def requested(instance, actor="agent-1"):
    return instance.create(run_id="run", actor_id=actor, tool_id="tool",
                           operation="write", scope_digest=SCOPE)


def kinds(instance, execution_id):
    return [event["kind"] for event in instance.events(execution_id)]


def reasons(instance, execution_id, kind):
    return [event["detail"].get("reason") for event in instance.events(execution_id)
            if event["kind"] == kind]


class TestARefusedApprovalIsRecorded:
    def test_self_approval_leaves_an_event(self, ledger):
        execution_id = requested(ledger)
        with pytest.raises(LedgerError, match="self-approval"):
            ledger.approve(execution_id, approver_id="agent-1", scope_digest=SCOPE,
                           ttl_seconds=60)
        assert reasons(ledger, execution_id, "approve_refused") == ["self_approval"]

    def test_a_scope_mismatch_leaves_an_event(self, ledger):
        execution_id = requested(ledger)
        with pytest.raises(LedgerError, match="scope digest"):
            ledger.approve(execution_id, approver_id="human-1", scope_digest=OTHER_SCOPE,
                           ttl_seconds=60)
        assert reasons(ledger, execution_id, "approve_refused") == ["scope_mismatch"]

    def test_approving_twice_leaves_an_event(self, ledger):
        execution_id = requested(ledger)
        ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE, ttl_seconds=60)
        with pytest.raises(LedgerError, match="cannot approve from state"):
            ledger.approve(execution_id, approver_id="human-2", scope_digest=SCOPE,
                           ttl_seconds=60)
        assert reasons(ledger, execution_id, "approve_refused") == ["wrong_state"]

    def test_every_attempt_is_counted(self, ledger):
        """한 번만 남기면 탐색과 오타를 구별할 수 없다. 여덟 번 두드렸으면
        여덟 줄이어야 한다."""
        execution_id = requested(ledger)
        for _ in range(8):
            with pytest.raises(LedgerError):
                ledger.approve(execution_id, approver_id="agent-1", scope_digest=SCOPE,
                               ttl_seconds=60)
        assert kinds(ledger, execution_id).count("approve_refused") == 8

    def test_the_event_names_who_tried(self, ledger):
        """누가 시도했는지 없으면 그 줄은 조사에 쓸 수 없다."""
        execution_id = requested(ledger)
        with pytest.raises(LedgerError):
            ledger.approve(execution_id, approver_id="agent-1", scope_digest=SCOPE,
                           ttl_seconds=60)
        event = next(e for e in ledger.events(execution_id) if e["kind"] == "approve_refused")
        assert event["detail"]["approver_id"] == "agent-1"

    def test_a_refusal_does_not_change_the_state(self, ledger):
        """기록하려고 상태를 건드리면 거절이 승인의 흔적을 남긴다."""
        execution_id = requested(ledger)
        with pytest.raises(LedgerError):
            ledger.approve(execution_id, approver_id="agent-1", scope_digest=SCOPE,
                           ttl_seconds=60)
        assert ledger.get(execution_id).state == "CREATED"
        assert ledger.get(execution_id).lease_id is None


class TestARefusedReconciliationIsRecorded:
    def unknown_execution(self, ledger):
        execution_id = requested(ledger)
        lease = ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE,
                               ttl_seconds=60)
        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state=UNKNOWN, evidence={"reason": "timeout"})
        return execution_id

    def test_self_reconciliation_leaves_an_event(self, ledger):
        execution_id = self.unknown_execution(ledger)
        with pytest.raises(LedgerError, match="self-reconciliation"):
            ledger.reconcile(execution_id, new_state="SUCCEEDED", reconciler_id="agent-1",
                             evidence={"note": "it worked, trust me"})
        assert reasons(ledger, execution_id, "reconcile_refused") == ["self_reconciliation"]

    def test_reconciling_a_settled_execution_leaves_an_event(self, ledger):
        execution_id = requested(ledger)
        with pytest.raises(LedgerError, match="UNKNOWN execution"):
            ledger.reconcile(execution_id, new_state="SUCCEEDED", reconciler_id="operator-1",
                             evidence={})
        assert reasons(ledger, execution_id, "reconcile_refused") == ["wrong_state"]

    def test_the_state_is_unchanged(self, ledger):
        execution_id = self.unknown_execution(ledger)
        with pytest.raises(LedgerError):
            ledger.reconcile(execution_id, new_state="SUCCEEDED", reconciler_id="agent-1",
                             evidence={})
        assert ledger.get(execution_id).state == UNKNOWN


class TestTheAtomicitySurvivedTheChange:
    """거절을 기록하려고 검사와 쓰기를 쪼갰다가 동시 승인 원자성을 깨뜨렸다.
    두 회차 전 테스트가 잡았고, 여기서도 다시 못박는다."""

    def test_the_check_and_the_write_share_one_transaction(self):
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "core" / "ledger.py").read_text(
            encoding="utf-8")
        body = source[source.index("    def approve("):source.index("    def claim_lease(")]
        assert body.count("with self._transaction()") == 1, (
            "approve가 트랜잭션을 둘 이상 연다 — 검사와 쓰기가 갈라지면 동시 승인이 "
            "둘 다 통과한다."
        )

    def test_a_successful_approval_still_works(self, ledger):
        execution_id = requested(ledger)
        lease = ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE,
                               ttl_seconds=60)
        assert ledger.claim_lease(lease, scope_digest=SCOPE) == execution_id


class TestTheseChecksAreNotVacuous:
    def test_a_successful_approval_records_approved_not_refused(self, ledger):
        """전부 거절로 기록하면 위 검사들이 통과하면서 신호가 사라진다."""
        execution_id = requested(ledger)
        ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE, ttl_seconds=60)
        assert "approved" in kinds(ledger, execution_id)
        assert "approve_refused" not in kinds(ledger, execution_id)

    def test_an_unknown_execution_raises_without_an_event(self, ledger):
        """실행이 없으면 이벤트를 붙일 곳도 없다 — `events.execution_id`는 FK다.
        그 경우까지 기록하려 들면 외래키 위반으로 부르는 쪽이 죽는다."""
        with pytest.raises(LedgerError, match="unknown execution"):
            ledger.approve("nope", approver_id="human-1", scope_digest=SCOPE, ttl_seconds=60)

    def test_claim_refused_still_works(self, ledger):
        """원래 기록하던 쪽이 그대로인지. 이번 변경이 그것을 건드렸다면 여기서 걸린다."""
        execution_id = requested(ledger)
        lease = ledger.approve(execution_id, approver_id="human-1", scope_digest=SCOPE,
                               ttl_seconds=60)
        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.claim_lease(lease, scope_digest=SCOPE)
        assert "claim_refused" in kinds(ledger, execution_id)

    def test_the_exported_journal_carries_the_refusals(self, ledger, tmp_path):
        """이벤트가 원장에만 있고 내보낸 저널에 없으면, 밖에서 보는 사람에게는
        여전히 없는 것이다."""
        from core.export import export_ledger

        execution_id = requested(ledger)
        with pytest.raises(LedgerError):
            ledger.approve(execution_id, approver_id="agent-1", scope_digest=SCOPE,
                           ttl_seconds=60)
        path = tmp_path / "journal.jsonl"
        export_ledger(ledger, path)
        assert "approve_refused" in path.read_text(encoding="utf-8")
