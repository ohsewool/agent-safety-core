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

        reasons = " ".join(v.reason for v in reconcile_with_ledger(journal, ledger).violations)
        assert "absent from the export" in reasons


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

        reasons = " ".join(v.reason for v in reconcile_with_ledger(journal, ledger).violations)
        assert "not present in the ledger" in reasons

    def test_the_two_directions_are_worded_differently(self, ledger, tmp_path):
        execution_id, lease = approved(ledger)
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        ledger.claim_lease(lease, scope_digest=SCOPE)

        stale = " ".join(v.reason for v in reconcile_with_ledger(journal, ledger).violations)
        assert "absent from the export" in stale
        assert "not present in the ledger" not in stale


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
