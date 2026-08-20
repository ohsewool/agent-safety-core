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
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", "archive"}

LINK = re.compile(r"\[[^\]]*\]\((?!https?:|#|mailto:)([^)\s]+)\)")
EXTENSIONS = "py|md|toml|yml|yaml|json|jsonl|csv|part|txt|cfg|sh|js|css|pkl|db"
BACKTICK = re.compile(rf"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.(?:{EXTENSIONS}))`")
HISTORICAL = re.compile(r"<!--\s*historical:")


def documents():
    return [
        path for path in sorted(ROOT.rglob("*.md"))
        if not SKIP_DIRECTORIES & set(path.relative_to(ROOT).parts)
    ]


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


@pytest.mark.parametrize("path", documents(), ids=lambda p: str(p.relative_to(ROOT)))
def test_every_path_a_document_names_is_there(path):
    assert missing_in(path) == []


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
