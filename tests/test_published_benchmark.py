"""The table in benchmark/README.md must equal what the benchmark produces.

`test_benchmark.py` pins the argument - B stops unauthorised effects and not
duplicates, C stops duplicates and loses legitimate work, D loses none, F
resolves what E cannot. That is the right thing to assert, because it is the
claim; a table of counts could change for reasons that leave every one of those
statements true.

But the published table also contains literal numbers, and nothing compared
them against a run. Add a scenario to the catalogue and arm A's duplicate count
moves from 6 to 7 while the relational tests stay green and the README quietly
becomes wrong. That is the same drift this project already had twice in its
test counts, which is why CI compares those too - a number kept by hand is a
number that rots.

The table is parsed from the README rather than regenerated into it. Writing it
automatically would make the file always agree with the code and stop being
evidence of anything; the point is that a human published a number and it is
still true.
"""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmark.run import run_all, totals  # noqa: E402

README = ROOT / "benchmark" / "README.md"
COLUMNS = ("duplicate_side_effects", "unauthorized_side_effects",
           "false_retries", "unresolved", "missed_completions")
ROW = re.compile(r"^\|\s*(?:\*\*)?([A-F])(?:\*\*)?\s*\|((?:\s*(?:\*\*)?\d+(?:\*\*)?\s*\|){5})\s*$",
                 re.MULTILINE)


@pytest.fixture(scope="module")
def produced():
    return totals(run_all())


@pytest.fixture(scope="module")
def published():
    """The totals table as a person reading the README would understand it."""
    text = README.read_text(encoding="utf-8")
    # 제목이 아니라 표 헤더를 기준으로 찾는다. README는 `## Findings`이고
    # `benchmark/run.py`가 만드는 리포트는 `## Totals across all scenarios`라,
    # 제목에 기대면 어느 한쪽을 못 읽는다 - 첫 판이 그랬다.
    header = "| arm | duplicate | unauthorized | false retries | unresolved | work left undone |"
    assert header in text, "totals 표 헤더를 찾지 못했다 — 열이 바뀌었나?"
    rows = {}
    for match in ROW.finditer(text.split(header, 1)[1]):
        cells = [int(re.sub(r"\D", "", cell)) for cell in match.group(2).split("|") if cell.strip()]
        rows[match.group(1)] = dict(zip(COLUMNS, cells))
    return rows


class TestThePublishedTableIsStillTrue:
    def test_every_arm_is_published(self, produced, published):
        """실행이 내놓는 arm과 표의 행이 같아야 한다. arm을 하나 더 만들고
        표에 안 적으면, 나머지가 전부 맞아도 독자는 그 arm을 모른다."""
        assert set(published) == set(produced)

    def test_every_published_number_matches_a_real_run(self, produced, published):
        wrong = {
            f"{arm}.{column}": (published[arm][column], produced[arm][column])
            for arm in sorted(published) for column in COLUMNS
            if published[arm][column] != produced[arm][column]
        }
        assert not wrong, (
            "benchmark/README.md의 표가 실제 실행과 다르다 (published, produced): "
            f"{wrong}. `python3 benchmark/run.py`로 다시 만들어 확인하라."
        )

    def test_the_headline_zero_is_the_one_that_is_published(self, produced, published):
        """F의 unresolved 0은 이 저장소가 내세우는 숫자다. 표에서 굵게 표시돼
        있어 파싱이 조용히 놓치기 쉬웠고, 그래서 따로 확인한다."""
        assert published["F"]["unresolved"] == 0
        assert produced["F"]["unresolved"] == 0


class TestTheComparisonIsNotVacuous:
    """표가 일치한다는 결과는, 표를 읽지 못했어도 똑같이 나온다."""

    def test_the_table_was_actually_parsed(self, published):
        assert len(published) == 6, f"읽어낸 행이 {len(published)}개뿐이다"
        assert all(len(row) == len(COLUMNS) for row in published.values())

    def test_the_numbers_are_not_all_zero(self, published):
        """전부 0인 표는 어떤 실행과도 비교되지 않은 것처럼 통과할 수 있다."""
        assert sum(sum(row.values()) for row in published.values()) > 0

    def test_a_changed_number_would_be_noticed(self, produced, published):
        tampered = {arm: dict(row) for arm, row in published.items()}
        tampered["A"]["duplicate_side_effects"] += 1
        differs = [column for column in COLUMNS
                   if tampered["A"][column] != produced["A"][column]]
        assert differs == ["duplicate_side_effects"]

    def test_the_run_produced_something_to_compare_against(self, produced):
        assert len(produced) == 6
        assert sum(produced["A"].values()) > 0
