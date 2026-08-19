"""A directory named `core` must not be able to replace this one.

`core`, `adapters` and `profiles` are the three top-level names this
distribution installs, and all three are names a project could plausibly have a
directory called. Shipped without `__init__.py` they were namespace packages,
and namespace portions *merge* rather than compete: a `core/` directory in the
working directory joined the same package and, being earlier on `sys.path`,
won.

That is not a style question here. It was demonstrated with a `core/ledger.py`
holding an `ExecutionLedger` whose `approve()` returned unconditionally, and it
was imported in preference to the real one - by a library whose entire premise
is that approvals are enforced. Nothing warned; `import core.ledger` simply
returned something else.

Adding `__init__.py` makes each a regular package, and the import system stops
at the first regular package on the path instead of merging portions.

These tests run in subprocesses from a scratch directory, because the property
is about how the interpreter resolves a name from somewhere else - asserting it
inside a session that has already imported `core` would test nothing.
"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = ("core", "adapters", "profiles")

DECOY = """\
class ExecutionLedger:
    def approve(self, *args, **kwargs):
        return "approved-without-asking"
"""


def run_from(directory: Path, code: str) -> subprocess.CompletedProcess:
    """Run `code` with `directory` as the working directory and ROOT importable.

    ROOT goes on PYTHONPATH rather than being installed, so this reproduces the
    ordinary case - the interpreter finds the working directory first and this
    package second - without depending on how the suite's environment happens
    to have been installed.
    """
    return subprocess.run([sys.executable, "-c", code], cwd=directory,
                          env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"},
                          capture_output=True, text=True)


class TestTheShippedPackagesAreRegular:
    @pytest.mark.parametrize("name", SHIPPED)
    def test_each_has_an_init(self, name):
        assert (ROOT / name / "__init__.py").exists(), (
            f"{name} would be a namespace package, which merges with any "
            f"directory of the same name earlier on sys.path"
        )

    @pytest.mark.parametrize("name", SHIPPED)
    def test_each_reports_a_file(self, name):
        """`__file__ is None` is how a namespace package presents itself."""
        result = run_from(ROOT, f"import {name}; print({name}.__file__)")
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() not in ("", "None")

    def test_the_list_here_matches_what_is_packaged(self, ):
        """A fourth shipped package added later would otherwise be exempt from
        every test in this file without anyone noticing."""
        configured = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        include = configured.split("include = [", 1)[1].split("]", 1)[0]
        packaged = {part.strip().strip('"\'').rstrip("*") for part in include.split(",")}
        assert packaged == set(SHIPPED)


class TestALocalDirectoryDoesNotWin:
    @pytest.fixture
    def decoy(self, tmp_path):
        """A working directory holding its own `core/ledger.py`."""
        (tmp_path / "core").mkdir()
        (tmp_path / "core" / "ledger.py").write_text(DECOY, encoding="utf-8")
        return tmp_path

    def test_the_real_ledger_is_imported(self, decoy):
        result = run_from(decoy, "import core.ledger; print(core.ledger.__file__)")
        assert result.returncode == 0, result.stderr
        assert Path(result.stdout.strip()) == ROOT / "core" / "ledger.py"

    def test_the_decoy_approve_is_not_reachable(self, decoy):
        """The consequence, stated as the thing that would actually go wrong."""
        result = run_from(decoy, "from core.ledger import ExecutionLedger\n"
                                 "print(ExecutionLedger.approve.__qualname__)")
        assert result.returncode == 0, result.stderr
        assert "approved-without-asking" not in result.stdout

    def test_the_decoy_is_genuinely_first_on_the_path(self, decoy):
        """Pins the premise. If the working directory were not searched first
        this test would pass while demonstrating nothing - which is how a
        vacuous check of exactly this kind would look."""
        result = run_from(decoy, "import sys, pathlib\n"
                                 "print(pathlib.Path(sys.path[0]).resolve())")
        assert Path(result.stdout.strip()) == decoy.resolve()

    def test_a_module_this_package_does_not_have_still_comes_from_the_decoy(self, decoy):
        """The rule is "a regular package wins", not "the working directory is
        ignored". A name `core` genuinely does not provide is still the user's
        to define - and if that stopped working, this fix would have broken
        something rather than only hardened it.

        With `core` a regular package, `core.extra` is looked up inside it and
        not found, which is the correct outcome and the price of the fix.
        """
        (decoy / "core" / "extra.py").write_text("VALUE = 1\n", encoding="utf-8")
        result = run_from(decoy, "import core.extra")
        assert result.returncode != 0
        assert "ModuleNotFoundError" in result.stderr
