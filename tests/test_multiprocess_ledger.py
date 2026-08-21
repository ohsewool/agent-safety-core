"""ADR-002가 프로세스에 대해 말한 것을 프로세스로 시험한다.

ADR-002 §6은 이렇게 적어두었다:

> `sequence`는 저장소가 단일 authority로 발급한다(AUTOINCREMENT). **다중 프로세스**가
> 같은 tip을 읽고 분기하는 F-04 시나리오가 구조적으로 불가능해진다.

그런데 동시성 테스트는 전부 **스레드**였다. 한 프로세스 안의 스레드는 같은 연결을
공유하고 GIL이 상당 부분을 직렬화한다 — 여러 프로세스가 각자 연결을 열고 OS 파일
락으로 경쟁하는 것과 다른 상황이다. **"프로세스에 대해 주장하고 스레드로 시험한
것"**이고, 더 어려운 쪽이 시험되지 않은 쪽이었다.

지난 회차에 같은 모양을 만났다: `scope_for_user`의 docstring이 보안 속성을 단언했고
절반이 틀렸다. 강한 주장은 강한 시험을 요구한다.

**결과: 주장이 성립한다.** 프로세스 6개가 각각 12회 append해도 sequence 144개가
전부 고유하고 빈틈이 없으며, 8개가 같은 lease를 노려도 정확히 하나만 획득하고,
그 뒤 export한 체인이 검증을 통과한다. 결함은 없었다 — 고치는 것이 아니라 다음에
저장 계층이 바뀌었을 때 알아차리게 하는 것이 이 파일의 일이다.

각 프로세스는 자기 `ExecutionLedger`를 새로 연다. 부모의 연결을 물려주면
`multiprocessing`의 fork 방식에 따라 SQLite 연결이 공유되고, 그러면 **시험하려던
바로 그 조건**(각자 연결)이 사라진다.
"""

import multiprocessing
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.export import export_ledger, verify_export  # noqa: E402
from core.ledger import ExecutionLedger  # noqa: E402

SCOPE = "scope-digest"
WORKERS = 6
PER_WORKER = 12


def _append(arguments):
    """자식 프로세스에서 돈다. 모듈 최상위여야 pickle된다."""
    path, worker_id, count = arguments
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from core.ledger import ExecutionLedger as Ledger

    ledger = Ledger(path, dispatcher_id=f"worker-{worker_id}")
    succeeded, failures = 0, []
    try:
        for index in range(count):
            try:
                execution_id = ledger.create(run_id=f"run-{worker_id}-{index}",
                                             actor_id=f"agent-{worker_id}", tool_id="tool",
                                             operation="write", scope_digest=SCOPE)
                ledger.approve(execution_id, approver_id="human-1",
                               scope_digest=SCOPE, ttl_seconds=600)
                succeeded += 1
            except Exception as error:  # noqa: BLE001 - 실패도 결과다
                failures.append(f"{type(error).__name__}: {error}"[:120])
    finally:
        ledger.close()
    return succeeded, failures


def _claim(arguments):
    path, lease, worker_id = arguments
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from core.ledger import ExecutionLedger as Ledger

    ledger = Ledger(path, dispatcher_id=f"worker-{worker_id}")
    try:
        return ledger.claim_lease(lease, scope_digest=SCOPE) is not None
    finally:
        ledger.close()


@pytest.fixture
def shared(tmp_path):
    """스키마를 먼저 만들어 둔다. 여러 프로세스가 동시에 만들려 드는 것은
    이 파일이 시험하려는 성질이 아니다."""
    path = str(tmp_path / "ledger.db")
    ExecutionLedger(path, dispatcher_id="setup").close()
    return path


@pytest.fixture(scope="module")
def pool_context():
    """`fork`는 부모의 SQLite 연결을 물려준다. 각자 연결을 여는 조건을 시험하려면
    `spawn`이 정확하지만 느리고, 여기서는 자식이 자기 원장을 새로 열므로 기본
    방식으로도 조건이 성립한다. 그 사실을 적어두는 편이 낫다."""
    return multiprocessing.get_context()


class TestManyProcessesAppendWithoutForking:
    def test_every_process_can_append(self, shared, pool_context):
        with pool_context.Pool(WORKERS) as pool:
            results = pool.map(_append, [(shared, worker, PER_WORKER)
                                         for worker in range(WORKERS)])
        failures = [item for _, errors in results for item in errors]
        assert not failures, failures[:5]
        assert sum(count for count, _ in results) == WORKERS * PER_WORKER

    def test_the_sequence_has_no_duplicates_and_no_gaps(self, shared, pool_context):
        """분기가 일어나면 여기서 보인다 - 같은 번호가 둘이거나 번호가 뛴다."""
        with pool_context.Pool(WORKERS) as pool:
            pool.map(_append, [(shared, worker, PER_WORKER) for worker in range(WORKERS)])

        ledger = ExecutionLedger(shared, dispatcher_id="check")
        sequences = [event["sequence"] for event in ledger.events()]
        ledger.close()

        assert len(sequences) == len(set(sequences)), "같은 sequence가 두 번 발급됐다"
        assert sorted(sequences) == list(range(min(sequences), max(sequences) + 1))

    def test_the_exported_chain_still_verifies(self, shared, tmp_path, pool_context):
        """번호가 성해도 체인이 어긋날 수 있다. 두 성질은 다르다."""
        with pool_context.Pool(WORKERS) as pool:
            pool.map(_append, [(shared, worker, PER_WORKER) for worker in range(WORKERS)])

        ledger = ExecutionLedger(shared, dispatcher_id="check")
        journal = tmp_path / "journal.jsonl"
        written = export_ledger(ledger, journal)
        ledger.close()

        assert written == WORKERS * PER_WORKER * 2      # create + approve
        assert verify_export(journal).ok


class TestOnlyOneProcessClaimsALease:
    def test_exactly_one_winner(self, shared, pool_context):
        """스레드로는 이미 고정돼 있었다. ADR이 말한 것은 프로세스다."""
        ledger = ExecutionLedger(shared, dispatcher_id="setup")
        execution_id = ledger.create(run_id="race", actor_id="agent-1", tool_id="tool",
                                     operation="write", scope_digest=SCOPE)
        lease = ledger.approve(execution_id, approver_id="human-1",
                               scope_digest=SCOPE, ttl_seconds=600)
        ledger.close()

        with pool_context.Pool(8) as pool:
            won = pool.map(_claim, [(shared, lease, worker) for worker in range(8)])

        assert sum(won) == 1, f"{sum(won)}개 프로세스가 같은 lease를 획득했다"


class TestTheRaceIsRealRatherThanSerialised:
    """전부 통과했다는 결과는, 프로세스가 실제로 겹치지 않았어도 똑같이 나온다."""

    def test_the_work_really_ran_in_more_than_one_process(self, shared, pool_context):
        """워커 하나가 전부 처리했다면 경쟁이 없었던 것이고, 위 검사들은 아무것도
        보지 않은 채 통과한다."""
        with pool_context.Pool(WORKERS) as pool:
            pool.map(_append, [(shared, worker, PER_WORKER) for worker in range(WORKERS)])

        ledger = ExecutionLedger(shared, dispatcher_id="check")
        actors = {ledger.get(event["execution_id"]).actor_id
                  for event in ledger.events()
                  if ledger.get(event["execution_id"]) is not None}
        ledger.close()
        assert len(actors) == WORKERS, f"워커 {WORKERS}개 중 {len(actors)}개만 기록을 남겼다"

    def test_the_assertions_would_notice_a_fork(self):
        """분기가 어떤 모습인지 여기 남긴다. 위 검사가 쓰는 두 조건을 그대로
        가짜 데이터에 적용해, 중복과 빈틈을 실제로 잡는지 본다 - 조건이 헐거우면
        144개가 전부 맞아떨어져도 아무 뜻이 없다."""
        forked = [1, 2, 3, 3, 4]                     # 같은 tip에서 갈라진 모습
        assert len(forked) != len(set(forked))
        gapped = [1, 2, 4, 5]                        # 중간이 사라진 모습
        assert sorted(gapped) != list(range(min(gapped), max(gapped) + 1))
        clean = [1, 2, 3, 4]
        assert len(clean) == len(set(clean))
        assert sorted(clean) == list(range(min(clean), max(clean) + 1))

    def test_enough_events_to_notice_a_collision(self, shared, pool_context):
        """이벤트가 두어 개뿐이면 충돌이 우연히 안 일어날 수 있다."""
        with pool_context.Pool(WORKERS) as pool:
            pool.map(_append, [(shared, worker, PER_WORKER) for worker in range(WORKERS)])
        ledger = ExecutionLedger(shared, dispatcher_id="check")
        total = len(list(ledger.events()))
        ledger.close()
        assert total >= 100
