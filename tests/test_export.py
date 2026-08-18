"""Export + verification: an auditor must be able to check the record alone."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.export import (  # noqa: E402
    GENESIS_HASH,
    export_ledger,
    main,
    verify_export,
)
from core.ledger import ExecutionLedger, SUCCEEDED, UNKNOWN  # noqa: E402

SCOPE = "a" * 64


@pytest.fixture
def populated(tmp_path):
    ledger = ExecutionLedger(str(tmp_path / "ledger.db"))
    for index in range(3):
        execution_id = ledger.create(
            run_id="run-1", actor_id="agent-1", tool_id="payments",
            operation="transfer", scope_digest=SCOPE,
        )
        lease = ledger.approve(execution_id, approver_id="human-1",
                               scope_digest=SCOPE, ttl_seconds=60)
        ledger.claim_lease(lease, scope_digest=SCOPE)
        ledger.record_outcome(
            execution_id,
            state=SUCCEEDED if index else UNKNOWN,
            evidence={"index": index},
        )
    yield ledger, tmp_path
    ledger.close()


def read_lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def write_lines(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestExport:
    def test_every_ledger_event_is_exported_in_order(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        written = export_ledger(ledger, journal)
        assert written == len(ledger.events())
        sequences = [json.loads(line)["sequence"] for line in read_lines(journal)]
        assert sequences == sorted(sequences)

    def test_first_record_starts_from_genesis(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        first = json.loads(read_lines(journal)[0])
        assert first["integrity"]["previous_hash"] == GENESIS_HASH

    def test_a_clean_export_verifies(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        report = verify_export(journal)
        assert report.ok
        assert "OK" in report.summary()

    def test_exports_of_the_same_ledger_are_identical(self, populated):
        """Determinism: two auditors must derive the same chain."""
        ledger, tmp_path = populated
        first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
        export_ledger(ledger, first)
        export_ledger(ledger, second)
        assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


class TestTamperDetection:
    def test_edited_content_is_reported_with_its_line(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        lines = read_lines(journal)
        record = json.loads(lines[2])
        record["detail"]["index"] = 999
        lines[2] = json.dumps(record, ensure_ascii=False, sort_keys=True)
        write_lines(journal, lines)

        report = verify_export(journal)
        assert not report.ok
        assert any(violation.line == 3 for violation in report.violations)
        assert any("modified" in violation.reason for violation in report.violations)

    def test_deleted_record_breaks_the_chain(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        lines = read_lines(journal)
        write_lines(journal, lines[:2] + lines[3:])
        report = verify_export(journal)
        assert not report.ok
        assert any("chain is broken" in violation.reason for violation in report.violations)

    def test_reordered_records_break_the_chain(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        lines = read_lines(journal)
        lines[1], lines[2] = lines[2], lines[1]
        write_lines(journal, lines)
        assert not verify_export(journal).ok

    def test_inserted_record_breaks_the_chain(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        lines = read_lines(journal)
        forged = json.loads(lines[1])
        forged["detail"] = {"forged": True}
        write_lines(journal, lines[:2] + [json.dumps(forged, sort_keys=True)] + lines[2:])
        assert not verify_export(journal).ok

    def test_stripped_integrity_block_is_reported(self, populated):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        lines = read_lines(journal)
        record = json.loads(lines[0])
        record.pop("integrity")
        lines[0] = json.dumps(record, sort_keys=True)
        write_lines(journal, lines)
        report = verify_export(journal)
        assert any("integrity" in violation.reason for violation in report.violations)

    def test_truncation_is_not_detectable_from_the_file_alone(self, populated):
        """The honest limit: a truthful prefix still verifies (ADR-002 §7)."""
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        lines = read_lines(journal)
        write_lines(journal, lines[:4])
        assert verify_export(journal).ok  # documents the gap M3 must close


class TestVerifierCli:
    def test_cli_reports_success(self, populated, capsys):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        assert main(["verify", str(journal)]) == 0
        assert "OK" in capsys.readouterr().out

    def test_cli_reports_failure_with_nonzero_exit(self, populated, capsys):
        ledger, tmp_path = populated
        journal = tmp_path / "journal.jsonl"
        export_ledger(ledger, journal)
        lines = read_lines(journal)
        write_lines(journal, lines[:1] + lines[2:])
        assert main(["verify", str(journal)]) == 1
        assert "FAILED" in capsys.readouterr().out
