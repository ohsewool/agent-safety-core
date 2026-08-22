"""A document naming a file is a claim, and a checkable one.

In the sibling repository `modelmate`, `backend/main_parts/*.py` was renamed to
`*.part` and eighteen references across four documents kept pointing at the old
names for two months. Nobody clicked them, so nobody knew. The same shape is
worth pinning here rather than waiting to find out.

Two things are counted, both of which say "go here and it exists":

  - a relative markdown link, `[name](docs/X.md)`
  - a backticked path with an extension, `` `core/ledger.py` ``

A bare filename in prose is a reference, not a path, and is not counted. A first
version of this check counted those too and reported 161 of 740 references
missing across the repositories, which meant nothing - JSON-RPC method names
like `tools/call` and MIME types like `text/csv` were being read as paths
because they contain a slash. A checker that is wrong produces conclusions that
are wrong.

A document may declare itself a record of a past state with
`<!-- historical: when -->` on any line, and then it is skipped: its paths were
right when written, and silently updating them would make a stale document look
maintained. Stale-by-declaration is a record; stale-by-accident is a defect.
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", "archive"}

LINK = re.compile(r"\[[^\]]*\]\((?!https?:|#|mailto:)([^)\s]+)\)")
EXTENSIONS = "py|md|toml|yml|yaml|json|jsonl|csv|part|txt|cfg|sh|js|css|pkl|db"
BACKTICK = re.compile(rf"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.(?:{EXTENSIONS}))`")
# **선언**과 **언급**은 다르다.
#
# 예전 정규식은 `<!--\s*historical:`을 파일 어디에서든 찾았다. 그래서 이 관례를
# **설명하는 문장**이 있는 문서가 통째로 면제됐다. `modelmate`에서 실제로 그 일이
# 벌어졌다(2026-08-22): README 349줄의 "…은 각자 `<!-- historical: -->`로 선언돼
# 있다"는 한 문장이 **가장 많이 읽히는 문서를 모든 검사에서 빼버렸고**, 두 회차
# 동안 아무도 몰랐다. 다시 넣자마자 가려져 있던 죽은 링크 둘이 나왔다.
#
# 여기 문서들은 지금 그 상태가 아니다 — 재봤고, 언급만으로 면제된 문서는 없다.
# 장치가 같으므로 미리 고친다. 진짜 선언은 **줄 시작에, 문서 앞쪽에** 있다.
HISTORICAL = re.compile(r"^\s*<!--\s*historical:", re.MULTILINE)
DECLARATION_WITHIN_LINES = 15


def declared_historical(text: str) -> bool:
    """문서 앞쪽에 줄 시작으로 놓인 선언만 인정한다."""
    head = "\n".join(text.splitlines()[:DECLARATION_WITHIN_LINES])
    return bool(HISTORICAL.search(head))



def documents():
    """The documents this repository ships, asked of git rather than the disk.

    `rglob` found the sibling repositories that CI checks out under
    `.sibling/`, so the number of parametrised cases changed depending on which
    job was running - and the README-count check caught it as 225 collected
    against 216 claimed. A test whose count depends on what else happens to be
    on disk is a test that cannot be counted.

    Falling back to a walk when git is unavailable, with nested checkouts
    pruned: a directory holding its own `.git` belongs to another repository
    and its documents are not this one's claims.
    """
    try:
        listed = subprocess.run(["git", "ls-files", "*.md", "**/*.md"], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        if listed.returncode == 0 and listed.stdout.strip():
            return sorted(
                ROOT / name for name in set(listed.stdout.split())
                if not SKIP_DIRECTORIES & set(Path(name).parts) and (ROOT / name).exists()
            )
    except (OSError, subprocess.SubprocessError):
        pass
    found = []
    for path in sorted(ROOT.rglob("*.md")):
        parts = path.relative_to(ROOT).parts
        if SKIP_DIRECTORIES & set(parts):
            continue
        if any((ROOT.joinpath(*parts[:i]) / ".git").exists() for i in range(1, len(parts))):
            continue
        found.append(path)
    return found


# **무엇이 면제됐는지 이름으로 둔다.**
#
# 지금까지 이 검사들의 공허 가드는 **하한선**이었다(`>= 3`, `>= 20`). 하한선은
# 문서 하나가 조용히 빠지는 것을 잡지 못한다 — `modelmate`에서 README가 산문 한
# 줄로 면제됐을 때 살아 있는 문서 수는 21에서 20으로 줄었고, 가드는 `>= 20`이었다.
# **두 회차 동안 초록불이었다.**
#
# 면제는 드물고 의도적이다. 그러니 목록으로 적어둘 수 있고, 적어두면 늘어나는
# 것도 줄어드는 것도 걸린다. 진짜 기록을 새로 선언하면 여기 한 줄 추가하는 것이
# **그 면제를 의도했다는 증거**다.
DECLARED_RECORDS = frozenset({})


def declared_documents() -> set:
    return {path for path in documents()
            if declared_historical(path.read_text(encoding="utf-8", errors="replace"))}


def references(text):
    for pattern in (LINK, BACKTICK):
        for match in pattern.finditer(text):
            reference = match.group(1).split("#")[0].strip()
            if reference and not reference.endswith("/"):
                yield reference


def missing_in(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if declared_historical(text):
        return []
    return [reference for reference in dict.fromkeys(references(text))
            if not (ROOT / reference).exists() and not (path.parent / reference).exists()]


def test_every_path_a_document_names_is_there():
    """한 문서에 테스트 하나가 아니라, 한 성질에 테스트 하나다.

    처음에는 문서마다 파라미터를 걸었다 - 어느 문서가 걸렸는지 pytest가 이름으로
    알려주니까. 그러면 문서를 하나 더 쓸 때마다 테스트 수가 늘어난다. 검사하는
    성질은 그대로인데. 이 저장소들은 README가 주장하는 테스트 수를 CI가 실제
    수집 개수와 대조하는데, **그 숫자가 뜻을 가지려면 내가 먼저 부풀리지 말아야
    한다.** 다섯 저장소에서 119개가 그렇게 늘어 있었다.

    어느 문서인지는 실패 메시지가 말한다. 파라미터 이름이 해주던 일이고, 그것
    때문에 개수를 왜곡할 이유는 없다.
    """
    offenders = []
    for path in documents():
        for reference in missing_in(path):
            offenders.append(f"{path.relative_to(ROOT)} → {reference}")
    assert not offenders, (
        "없는 곳을 가리키는 참조:\n  " + "\n  ".join(offenders)
        + "\n현재 안내라면 경로를 고치고, 과거 기록이라면 <!-- historical: 시점 -->으로 선언하라."
    )


class TestTheCheckIsNotVacuous:
    """Every document passing proves nothing if the check finds no paths, or
    if it cannot fail."""

    def test_it_looked_at_some_documents(self):
        assert len(documents()) >= 3

    def test_it_found_paths_to_check(self):
        found = sum(len(list(references(p.read_text(encoding="utf-8", errors="replace"))))
                    for p in documents())
        assert found >= 5, f"only {found} path references were found to check"

    def test_it_catches_a_path_that_is_not_there(self, tmp_path):
        doc = tmp_path / "d.md"
        doc.write_text("[gone](docs/does-not-exist.md) and `src/nowhere/absent.py`",
                       encoding="utf-8")
        assert len(missing_in(doc)) == 2

    def test_it_honours_a_historical_declaration(self, tmp_path):
        doc = tmp_path / "d.md"
        doc.write_text("<!-- historical: 2020 -->\n[gone](docs/does-not-exist.md)",
                       encoding="utf-8")
        assert missing_in(doc) == []

    def test_it_does_not_read_prose_filenames_as_paths(self, tmp_path):
        """`ledger.py` names a file; it does not claim a location. Counting
        those is what made the first version useless."""
        doc = tmp_path / "d.md"
        doc.write_text("`ledger.py`, `tools/call`, `text/csv`, `9/10`", encoding="utf-8")
        assert missing_in(doc) == []

    def test_it_passes_a_path_that_is_there(self, tmp_path):
        doc = tmp_path / "d.md"
        doc.write_text("[readme](README.md)", encoding="utf-8")
        assert missing_in(doc) == []


def test_no_document_is_exempt():
    """이 저장소에는 기록으로 선언된 문서가 없다. **비어 있음도 결과다** —
    어떤 문서가 조용히 검사 밖으로 나가면 여기서 걸린다. 하한선 가드로는
    보이지 않는 변화다(`modelmate`에서 README가 그렇게 빠졌다).
    """
    actual = {str(path.relative_to(ROOT)) for path in declared_documents()}
    assert actual == set(DECLARED_RECORDS), (
        f"면제된 문서가 생겼다: {sorted(actual)}\n"
        "의도한 기록이면 DECLARED_RECORDS에 넣어라. 아니면 산문 언급이 선언으로 "
        "읽힌 것이다."
    )


class TestAMentionIsNotADeclaration:
    """관례를 **설명하는 문장**이 문서를 면제시키면 안 된다.

    `modelmate`에서 그 일이 벌어졌다(2026-08-22). 정규식 사본이 파일마다 있으므로
    대조도 파일마다 있어야 한다 — 여기서 느슨하게 되돌려도 다른 파일의 대조는
    아무 말을 하지 않는다.
    """

    def test_a_prose_mention_does_not_exempt(self):
        assert not declared_historical(
            "# 제목\n\n관례는 `<!-- historical: 시점 -->`으로 적는다.\n")

    def test_a_real_declaration_exempts(self):
        assert declared_historical("# 제목\n<!-- historical: 2026-06 -->\n본문\n")

    def test_a_declaration_far_down_does_not_count(self):
        """문서 끝에 붙인 표시는 선언이 아니다 — 읽는 사람은 앞을 보고 판단한다."""
        assert not declared_historical("# 제목\n" + "본문\n" * 40
                                       + "<!-- historical: 2026-06 -->\n")
