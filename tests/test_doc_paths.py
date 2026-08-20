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
HISTORICAL = re.compile(r"<!--\s*historical:")


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


def references(text):
    for pattern in (LINK, BACKTICK):
        for match in pattern.finditer(text):
            reference = match.group(1).split("#")[0].strip()
            if reference and not reference.endswith("/"):
                yield reference


def missing_in(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if HISTORICAL.search(text):
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
