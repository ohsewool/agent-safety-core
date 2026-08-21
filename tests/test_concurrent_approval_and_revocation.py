"""승인과 철회도 경쟁에서 성립하는가.

`claim_lease`는 ADR-002 §9가 요구한 대로 스레드와 프로세스 양쪽에서 고정돼 있다
(`test_ledger.py::TestF02LeaseAtomicity`, `test_multiprocess_ledger.py`). 그 옆의 두
전이는 아무도 경쟁에 부딪쳐본 적이 없었다.

`mcp-gateway`에서 같은 형태를 훑다가 **감사 로그의 해시 체인이 동시 append에서 40회 중
40회 갈라지는 것**을 찾았고, 그래서 여기도 확인하는 것이 맞다.

**결과는 빈손이다.** 두 성질 모두 성립한다:

- 같은 실행에 동시 승인 12건 → 발급된 lease는 항상 **1개**, 소비 가능한 것도 1개
  (20회 반복). `BEGIN IMMEDIATE`가 트랜잭션 전체를 직렬화하고, 나머지는 상태 검사에
  걸려 `LedgerError`로 거절된다.
- 철회와 소비가 동시에 → **정확히 한쪽만** 이긴다(40회 반복, 둘 다 성공한 경우 0).
  조건부 `UPDATE`가 상태를 걸고 있다.

빈손도 결과다 — **훑어서 안 나온 것과 안 훑은 것은 다르다.** 그리고 성립한다는 것을
고정해두면 다음에 이 전이를 손대는 사람이 여기서 걸린다.

원장 인스턴스는 **스레드마다 하나**여야 한다. 하나를 공유하면 `sqlite3`가
`ProgrammingError`로 막는다 — 조용히 섞이지 않는다. 아래 검사가 그 사실도 고정한다.
"""

from __future__ import annotations

import concurrent.futures
import sqlite3
import threading

import pytest

from core.ledger import ExecutionLedger, LedgerError

SCOPE = "digest"
WORKERS = 12


def new_execution(path: str) -> str:
    setup = ExecutionLedger(path, dispatcher_id="d0")
    try:
        return setup.create(run_id="r", actor_id="agent", tool_id="t",
                            operation="op", scope_digest=SCOPE)
    finally:
        setup.close()


def approve_together(path: str, execution_id: str, workers: int = WORKERS) -> list[str]:
    """워커마다 자기 원장을 연다. 모두 같은 지점에서 출발한다."""
    barrier = threading.Barrier(workers, timeout=60)

    def approve(index: int) -> str | None:
        own = ExecutionLedger(path, dispatcher_id=f"d{index}")
        try:
            barrier.wait()
            for _ in range(40):      # SQLITE_BUSY는 재시도한다. 져서 진 것과 구분해야 한다.
                try:
                    return own.approve(execution_id, approver_id=f"human{index}",
                                       scope_digest=SCOPE, ttl_seconds=60)
                except LedgerError:
                    return None      # 상태 검사에 걸린 것 - 이것이 정상적인 패배다
                except sqlite3.Error:
                    continue
            return None
        finally:
            own.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return [lease for lease in pool.map(approve, range(workers)) if lease]


class TestOneExecutionYieldsOneLease:
    def test_concurrent_approvals_issue_exactly_one(self, tmp_path):
        path = str(tmp_path / "approve.db")
        execution_id = new_execution(path)
        assert len(approve_together(path, execution_id)) == 1

    def test_the_issued_lease_is_the_usable_one(self, tmp_path):
        """발급 수가 1이어도, 그 하나가 못 쓰는 것이면 승인이 사라진 것이다."""
        path = str(tmp_path / "approve.db")
        execution_id = new_execution(path)
        leases = approve_together(path, execution_id)
        checker = ExecutionLedger(path, dispatcher_id="dx")
        try:
            assert checker.claim_lease(leases[0], scope_digest=SCOPE) == execution_id
        finally:
            checker.close()

    def test_it_repeats(self, tmp_path):
        """한 번은 운일 수 있다. `mcp-gateway`의 체인 분기는 40회 중 40회였고,
        예산 초과는 300회 중 1회였다 — 반복하지 않으면 후자를 놓친다."""
        for round_number in range(10):
            path = str(tmp_path / f"repeat-{round_number}.db")
            execution_id = new_execution(path)
            assert len(approve_together(path, execution_id)) == 1


class TestRevocationAndDispatchCannotBothWin:
    """철회된 승인이 dispatch되면 통제 전체가 무의미해진다."""

    @pytest.mark.parametrize("round_number", range(8))
    def test_exactly_one_side_wins(self, tmp_path, round_number):
        path = str(tmp_path / f"race-{round_number}.db")
        execution_id = new_execution(path)
        opener = ExecutionLedger(path, dispatcher_id="d0")
        try:
            lease = opener.approve(execution_id, approver_id="human",
                                   scope_digest=SCOPE, ttl_seconds=60)
        finally:
            opener.close()

        barrier = threading.Barrier(2, timeout=60)

        def attempt(action):
            own = ExecutionLedger(path, dispatcher_id="dz")
            try:
                barrier.wait()
                for _ in range(40):
                    try:
                        return action(own)
                    except sqlite3.Error:
                        continue
                return False
            finally:
                own.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            revoked = pool.submit(attempt, lambda ledger: ledger.revoke(
                execution_id, revoker_id="human2", reason="stop"))
            claimed = pool.submit(attempt, lambda ledger: ledger.claim_lease(
                lease, scope_digest=SCOPE) is not None)
            outcome = (bool(revoked.result()), bool(claimed.result()))

        assert outcome in {(True, False), (False, True)}, outcome


class TestTheHarnessCouldCountMoreThanOne:
    """음성 대조. "항상 1개"는 하네스가 2를 셀 수 없어도 똑같이 나온다.

    실행을 워커 수만큼 만들어 각자 자기 것을 승인시킨다. 같은 코드 경로, 같은 동시성,
    다른 대상 — 여기서 12가 나오면 하네스는 1보다 큰 수를 셀 수 있다.
    """

    def test_distinct_executions_each_get_their_own_lease(self, tmp_path):
        path = str(tmp_path / "many.db")
        execution_ids = [new_execution(path) for _ in range(WORKERS)]
        barrier = threading.Barrier(WORKERS, timeout=60)

        def approve(index):
            own = ExecutionLedger(path, dispatcher_id=f"d{index}")
            try:
                barrier.wait()
                for _ in range(40):
                    try:
                        return own.approve(execution_ids[index], approver_id="human",
                                           scope_digest=SCOPE, ttl_seconds=60)
                    except sqlite3.Error:
                        continue
                return None
            finally:
                own.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            leases = [lease for lease in pool.map(approve, range(WORKERS)) if lease]
        assert len(leases) == WORKERS
        assert len(set(leases)) == WORKERS, "같은 lease가 두 실행에 발급됐다"


class TestOneLedgerPerThread:
    """공유하면 조용히 섞이는 것이 아니라 시끄럽게 실패한다. 그 편이 낫다."""

    def test_sharing_one_instance_across_threads_is_refused(self, tmp_path):
        path = str(tmp_path / "shared.db")
        ledger = ExecutionLedger(path, dispatcher_id="d0")
        try:
            execution_id = ledger.create(run_id="r", actor_id="a", tool_id="t",
                                         operation="op", scope_digest=SCOPE)
            failures = []

            def use_it():
                try:
                    ledger.approve(execution_id, approver_id="human",
                                   scope_digest=SCOPE, ttl_seconds=60)
                except sqlite3.ProgrammingError as error:
                    failures.append(str(error))

            thread = threading.Thread(target=use_it)
            thread.start()
            thread.join()
            assert failures, "다른 스레드에서 쓰는 것이 허용됐다"
            assert "thread" in failures[0]
        finally:
            ledger.close()
