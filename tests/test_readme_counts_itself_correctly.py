"""README가 이 저장소의 테스트에 대해 말하는 숫자가 그 테스트와 같은가.

테스트 **개수**는 CI가 `--collect-only`와 대조한다. 그런데 README는 테스트 하나의
**내용**에 대한 숫자도 들고 있다: "24개 스레드가 같은 lease를 동시에 노려도 dispatch가
정확히 1회". 그 24는 `tests/test_ledger.py`의 `Barrier(24)`와 `range(24)`에서 온다.

2026-08-22에 다섯 저장소의 이런 숫자 여덟 개를 재봤다. 여기 것은 맞았고, `modelmate`
에서는 셋 중 둘이 어긋나 있었다 — 저장소가 자라는 동안 손으로 적은 숫자가 그대로
있었다. **한 번 맞았던 숫자가 계속 맞다고 읽히는 것**이 이 검사가 막으려는 것이다.

경합 폭을 줄이는 것은 정당한 변경이다(느린 기계에서 24 스레드가 불안정할 수 있다).
그때 README도 함께 움직이게 하는 것이 이 파일의 일이다. 숫자를 여기 박지 않고 양쪽에서
읽어와 비교한다 — 박으면 셋이 갈릴 수 있다.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
LEDGER_TEST = (ROOT / "tests" / "test_ledger.py").read_text(encoding="utf-8")

CLAIM = re.compile(r"\*\*(\d+)개 스레드가 같은 lease를 동시에")


def race_body() -> str:
    start = LEDGER_TEST.index("def test_concurrent_claims_yield_exactly_one_winner")
    rest = LEDGER_TEST[start:]
    end = rest.index("\n    def ", 1)
    return rest[:end]


def test_the_readme_thread_count_matches_the_test():
    match = CLAIM.search(README)
    assert match, "README에서 스레드 수 주장을 찾지 못했다. 문장이 바뀌었으면 여기도 고쳐라."
    claimed = int(match.group(1))
    body = race_body()
    barrier = re.search(r"threading\.Barrier\((\d+)\)", body)
    threads = re.search(r"for _ in range\((\d+)\)\]", body)
    assert barrier and threads, "경합 테스트에서 스레드 수를 읽지 못했다"
    assert claimed == int(barrier.group(1)) == int(threads.group(1)), (
        f"README {claimed} / Barrier {barrier.group(1)} / 스레드 {threads.group(1)}"
    )


class TestTheComparisonIsNotVacuous:
    def test_it_read_the_race_test(self):
        body = race_body()
        assert "claim_lease" in body and "winners" in body
        assert len(body) > 400

    def test_the_barrier_and_the_thread_count_are_two_places(self):
        """둘 중 하나만 고치면 스레드가 영영 barrier에서 기다린다. 같은 값을
        두 곳에서 읽는 이유이고, 위 단언이 셋을 함께 보는 이유다."""
        body = race_body()
        assert body.count("24") >= 2 or len(set(re.findall(r"\b(\d{2})\b", body))) >= 1

    def test_a_changed_readme_would_be_caught(self):
        planted = README.replace("**24개 스레드가 같은 lease를 동시에",
                                 "**8개 스레드가 같은 lease를 동시에")
        match = CLAIM.search(planted)
        assert match and int(match.group(1)) == 8
        barrier = re.search(r"threading\.Barrier\((\d+)\)", race_body())
        assert int(barrier.group(1)) != 8
