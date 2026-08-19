"""jsonschema is optional, and this checks that rather than assuming it.

`test_event_record.py` guards its import, so the schema tests skip when the
package is absent. The rest of the core has no business needing it: signing,
the ledger, scope binding and retention are all standard library plus
cryptography.

Worth running rather than reasoning about. The same check in mcp-gateway found a
test importing its sibling unguarded and three deciding availability from one
machine's absolute path - so the fact that this one is clean is a measurement,
not an inference from the other result.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_the_core_does_not_import_jsonschema_at_module_level():
    """A validation library is a test dependency here, not a runtime one."""
    offenders = [
        path.name for path in sorted((ROOT / "core").glob("*.py"))
        if "jsonschema" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, f"jsonschema reached production code in {offenders}"


@pytest.mark.slow
def test_the_suite_skips_rather_than_errors_without_it():
    """ModuleNotFoundError, because that is what a missing module raises.

    Simulating it with a bare ImportError produces collection errors that belong
    to the harness rather than the suite - already mistaken for a finding once
    this week.
    """
    script = textwrap.dedent('''
        import sys
        from importlib.abc import MetaPathFinder

        class Absent(MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] == "jsonschema":
                    raise ModuleNotFoundError(f"No module named {name!r}", name=name)
                return None

        sys.meta_path.insert(0, Absent())
        import pytest
        sys.exit(pytest.main(["tests/", "-q", "-p", "no:cacheprovider",
                              "-m", "not slow"]))
    ''')
    finished = subprocess.run([sys.executable, "-c", script], cwd=ROOT,
                              capture_output=True, text=True, timeout=600)
    assert finished.returncode == 0, finished.stdout[-2000:]
    assert "skipped" in finished.stdout, "nothing skipped; jsonschema was still reachable"


def test_cryptography_is_required_rather_than_optional():
    """Stated, because the distinction matters to whoever installs this.

    Checkpoints are signed and payloads encrypted; without cryptography the core
    cannot do either, so it is a dependency and not a nicety. Declaring it
    optional would invite a deployment that silently cannot sign.
    """
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "cryptography" in requirements
    assert any("cryptography" in path.read_text(encoding="utf-8")
               for path in (ROOT / "core").glob("*.py"))
