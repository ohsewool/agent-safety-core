"""Self-consistent is not the same as representing the ledger.

`verify_export` checks a journal against itself: the hash chain holds and the
sequences advance. Only that was checkable, so a journal exported before more
executions happened still passed - and "the export verifies" read as "this is
the record" while meaning "this file does not contradict itself".

ADR-002 makes the SQLite ledger the system of record and the journal an export
of it. An export nobody can compare against the record is a document with a hash
chain on it.

Two mechanisms that could disagree with no check that they agree - the same
shape found twice in modelmate, where the leakage checker and the evaluation
gate contradicted each other.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.export import export_ledger, reconcile_with_ledger, verify_export
from core.ledger import ExecutionLedger

SCOPE = "scope-digest"


@pytest.fixture
def ledger(tmp_path):
    item = ExecutionLedger(str(tmp_path / "core.db"), dispatcher_id="worker-1")
    yield item
    item.close()


def approved(ledger, actor="agent-1"):
    execution_id = ledger.create(run_id="run", actor_id=actor, tool_id="tool",
                                 operation="write", scope_digest=SCOPE)
    lease = ledger.approve(execution_id, approver_id="human-1",
                           scope_digest=SCOPE, ttl_seconds=600)
    return execution_id, lease


class TestAFreshExportMatches:
    def test_it_reconciles(self, ledger, tmp_path):
        approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        assert reconcile_with_ledger(journal, ledger).ok

    def test_it_still_passes_chain_verification(self, ledger, tmp_path):
        """Reconciliation is an additional check, not a replacement."""
        approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        assert verify_export(journal).ok

    def test_an_empty_ledger_exports_and_reconciles(self, ledger, tmp_path):
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        assert reconcile_with_ledger(journal, ledger).ok


class TestAStaleExportIsCaught:
    """The failure this file exists for."""

    def test_a_journal_exported_before_later_events_no_longer_matches(self, ledger, tmp_path):
        execution_id, lease = approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)

        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state="SUCCEEDED", evidence={"ok": True})

        assert not reconcile_with_ledger(journal, ledger).ok

    def test_the_chain_check_still_passes_on_that_stale_journal(self, ledger, tmp_path):
        """Which is precisely why the chain check was not enough.

        Nothing is wrong with the file. It is simply not the record any more,
        and only one of these two questions was being asked.
        """
        execution_id, lease = approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)

        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.record_outcome(execution_id, state="SUCCEEDED", evidence={})

        assert verify_export(journal).ok
        assert not reconcile_with_ledger(journal, ledger).ok

    def test_the_missing_events_are_named(self, ledger, tmp_path):
        execution_id, lease = approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        ledger.claim_lease(lease, scope_digest=SCOPE)

        kinds = {v.kind for v in reconcile_with_ledger(journal, ledger).violations}
        assert kinds == {"missing_from_export"}


class TestAnInventedRecordIsCaught:
    def test_a_record_the_ledger_never_held_is_reported(self, ledger, tmp_path):
        """The other direction, and it needs a different response.

        "Someone showed you a stale copy" and "someone added a record that was
        never in the ledger" are different events, so they are reported with
        different wording rather than as one count.
        """
        first = ExecutionLedger(str(tmp_path / "other.db"), dispatcher_id="worker-2")
        approved(first, actor="agent-2")
        journal = tmp_path / "journal.jsonl"
        export_ledger(first, journal)
        first.close()

        kinds = {v.kind for v in reconcile_with_ledger(journal, ledger).violations}
        assert "absent_from_ledger" in kinds

    def test_the_two_directions_are_worded_differently(self, ledger, tmp_path):
        execution_id, lease = approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        ledger.claim_lease(lease, scope_digest=SCOPE)

        kinds = {v.kind for v in reconcile_with_ledger(journal, ledger).violations}
        assert kinds == {"missing_from_export"}, "a stale copy is not an invented record"


class TestTheReportStaysImmutable:
    def test_reconciliation_does_not_mutate_the_verification_report(self, ledger, tmp_path):
        """A verdict that can be edited in place is a verdict, not a record."""
        approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)

        plain = verify_export(journal)
        reconciled = reconcile_with_ledger(journal, ledger)
        assert plain.violations == ()
        assert reconciled is not plain


class TestEachViolationSaysWhichKind:
    """A malformed line, a broken chain and a stale copy are not
    interchangeable: one is a corrupt file, one is tampering, one is an intact
    record someone is showing late. Distinguishing them meant matching on the
    sentence - including in the tests above, which is the signal that made this
    worth doing.
    """

    def _journal(self, ledger, tmp_path):
        approved(ledger)
        path = tmp_path / "journal.jsonl"
        export_ledger(ledger, path)
        return path

    def test_an_unreadable_line_is_named(self, ledger, tmp_path):
        journal = self._journal(ledger, tmp_path)
        journal.write_text("{ not json\n", encoding="utf-8")
        assert verify_export(journal).violations[0].kind == "malformed_line"

    def test_a_record_without_integrity_is_named(self, ledger, tmp_path):
        journal = self._journal(ledger, tmp_path)
        journal.write_text('{"sequence": 1}\n', encoding="utf-8")
        assert verify_export(journal).violations[0].kind == "missing_integrity"

    def test_a_tampered_record_is_named(self, ledger, tmp_path):
        import json

        journal = self._journal(ledger, tmp_path)
        lines = [line for line in journal.read_text(encoding="utf-8").splitlines() if line]
        first = json.loads(lines[0])
        first["actor_id"] = "someone-else"
        journal.write_text(json.dumps(first) + "\n", encoding="utf-8")

        kinds = {v.kind for v in verify_export(journal).violations}
        assert "content_modified" in kinds

    def test_a_clean_export_has_no_violations_to_classify(self, ledger, tmp_path):
        journal = self._journal(ledger, tmp_path)
        assert verify_export(journal).violations == ()

    def test_nothing_falls_through_unclassified(self, ledger, tmp_path):
        """Every violation this module raises is named. An `unclassified` here
        would mean a new failure mode arrived without anyone deciding what it
        is."""
        import json

        journal = self._journal(ledger, tmp_path)
        lines = [line for line in journal.read_text(encoding="utf-8").splitlines() if line]
        journal.write_text(lines[-1] + "\n", encoding="utf-8")   # chain now starts mid-way

        for violation in verify_export(journal).violations:
            assert violation.kind != "unclassified", violation.reason
