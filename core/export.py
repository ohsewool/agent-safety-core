"""Evidence export: turn the ledger into a portable, verifiable record.

The ledger is the system of record, but it is a live database on one host.  An
auditor needs something they can carry away and check without trusting that host
or the software that produced it — so the export is a hash-chained JSONL file
plus a verifier that only needs the file itself.

What the chain proves and does not prove is worth stating plainly:

proves
    An exported record was not edited, reordered, or partially deleted after the
    fact — any of those break the chain at a specific line.

does not prove
    That the export is complete or current.  Someone who controls the host can
    export a truthful prefix and withhold the rest, and nothing inside the file
    reveals that.  Detecting *that* needs freshness anchored outside the host
    (ADR-002 §7), which is M3 work.

So this is tamper-evident, not tamper-proof, and the verifier reports exactly
which line failed rather than a bare pass/fail.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .canonical import dumps

GENESIS_HASH = "0" * 64


def _event_hash(body: Mapping[str, Any], previous_hash: str) -> str:
    return hashlib.sha256(
        previous_hash.encode("ascii") + dumps(body).encode("utf-8")
    ).hexdigest()


def seal(body: Mapping[str, Any], previous_hash: str) -> dict[str, Any]:
    """Attach chain integrity to one record."""
    record = dict(body)
    record["integrity"] = {
        "previous_hash": previous_hash,
        "event_hash": _event_hash(body, previous_hash),
    }
    return record


def chain(records: Iterable[Mapping[str, Any]], *, start: str = GENESIS_HASH) -> Iterator[dict[str, Any]]:
    """Seal a stream of records into a hash chain."""
    previous = start
    for body in records:
        sealed = seal(body, previous)
        previous = sealed["integrity"]["event_hash"]
        yield sealed


def export_ledger(ledger: Any, destination: Path | str) -> int:
    """Write every ledger event to a hash-chained JSONL file. Returns the count."""
    destination = Path(destination)
    written = 0
    with destination.open("w", encoding="utf-8") as handle:
        for sealed in chain(_bodies(ledger.events())):
            handle.write(json.dumps(sealed, ensure_ascii=False, sort_keys=True) + "\n")
            written += 1
    return written


def _bodies(events: Iterable[Mapping[str, Any]]) -> Iterator[dict[str, Any]]:
    for event in events:
        yield {
            "sequence": event["sequence"],
            "execution_id": event["execution_id"],
            "kind": event["kind"],
            "from_state": event["from_state"],
            "to_state": event["to_state"],
            "detail": event["detail"],
            "recorded_at": event["recorded_at"],
        }


@dataclass(frozen=True)
class Violation:
    """One thing wrong with an export, and which thing.

    `reason` is for a person. `kind` is for the code that has to decide what to
    do, because these failures are not interchangeable: a malformed line is a
    corrupt file, a broken chain is tampering, and a ledger event missing from
    the export is a stale copy of an intact record. Telling them apart used to
    mean matching on the sentence - including in this repository's own tests,
    which is the signal that made it worth fixing.
    """

    line: int
    reason: str
    detail: str = ""
    kind: str = "unclassified"


@dataclass(frozen=True)
class VerificationReport:
    records: int
    violations: tuple[Violation, ...]
    tip_hash: str

    @property
    def ok(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        if self.ok:
            return f"OK — {self.records} records, chain intact, tip {self.tip_hash[:12]}"
        lines = [f"FAILED — {len(self.violations)} violation(s) in {self.records} records"]
        lines.extend(
            f"  line {violation.line}: {violation.reason}"
            + (f" ({violation.detail})" if violation.detail else "")
            for violation in self.violations
        )
        return "\n".join(lines)


def verify_export(source: Path | str) -> VerificationReport:
    """Check an exported journal using only the file itself."""
    source = Path(source)
    violations: list[Violation] = []
    previous = GENESIS_HASH
    count = 0
    last_sequence: int | None = None

    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            violations.append(Violation(number, "record is not valid JSON", kind="malformed_line"))
            break  # the chain cannot continue past an unreadable record
        integrity = record.pop("integrity", None)
        if not isinstance(integrity, dict):
            violations.append(Violation(number, "record has no integrity block", kind="missing_integrity"))
            break
        if integrity.get("previous_hash") != previous:
            violations.append(
                Violation(number, "chain is broken",
                          "a record was inserted, removed, or reordered here",
                          kind="chain_broken")
            )
        expected = _event_hash(record, integrity.get("previous_hash", ""))
        # `event_hash` here, `record_hash` in mcp-gateway's audit log. The two
        # formats were described as readable by one verifier and were not: the
        # canonical form and the chaining are identical, only the field name
        # differs, so each verifier rejected the other's log as tampered. Both
        # names are accepted rather than one renamed, because renaming would
        # invalidate every log already written.
        found = integrity.get("event_hash", integrity.get("record_hash"))
        if found != expected:
            violations.append(Violation(number, "record content was modified", kind="content_modified"))
        sequence = record.get("sequence")
        if isinstance(sequence, int):
            if last_sequence is not None and sequence <= last_sequence:
                violations.append(
                    Violation(number, "sequence is not increasing",
                              f"{last_sequence} then {sequence}",
                              kind="sequence_regressed")
                )
            last_sequence = sequence
        previous = integrity.get("event_hash", integrity.get("record_hash", ""))

    return VerificationReport(count, tuple(violations), previous)


def reconcile_with_ledger(source: Path | str, ledger: Any) -> VerificationReport:
    """Check an export against the ledger it claims to represent.

    `verify_export` checks the journal against itself: the hash chain holds and
    sequences advance. That is a different property from representing the
    ledger, and only the first was checkable - so a journal exported before more
    executions happened still passed, and "the export verifies" quietly meant
    "the export is internally consistent" while reading as "this is the record".

    ADR-002 makes the SQLite ledger the system of record and the journal an
    export of it. An export nobody can compare against the record is a document
    with a hash chain, not evidence.

    Missing and extra records are reported separately. "Someone showed you a
    stale copy" and "someone added a record that was never in the ledger" call
    for different responses, and collapsing them into a count would leave the
    reader to guess which happened.
    """
    source = Path(source)
    report = verify_export(source)

    exported: list[dict[str, Any]] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                exported.append(json.loads(line))
            except json.JSONDecodeError:
                break        # verify_export already recorded this

    def key(record: Mapping[str, Any]) -> tuple:
        body = record.get("body", record)
        return (body.get("execution_id"), body.get("kind"), body.get("sequence"))

    in_journal = {key(record) for record in exported}
    in_ledger = {key(body) for body in _bodies(ledger.events())}

    extra_violations = [
        Violation(line=0, reason=f"ledger event absent from the export: {missing}",
                  kind="missing_from_export")
        for missing in sorted(in_ledger - in_journal, key=str)
    ] + [
        Violation(line=0, reason=f"export record not present in the ledger: {found}",
                  kind="absent_from_ledger")
        for found in sorted(in_journal - in_ledger, key=str)
    ]
    # The report is immutable, which is the right shape for a verdict - so a
    # new one is returned rather than the existing one edited.
    return replace(report, violations=tuple(report.violations) + tuple(extra_violations))


def main(argv: list[str] | None = None) -> int:
    """``python -m core.export verify <journal.jsonl>``"""
    import argparse

    parser = argparse.ArgumentParser(description="Verify an exported evidence journal.")
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("path")
    arguments = parser.parse_args(argv)

    report = verify_export(arguments.path)
    print(report.summary())
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
