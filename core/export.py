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
from dataclasses import dataclass
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
    line: int
    reason: str
    detail: str = ""


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
            violations.append(Violation(number, "record is not valid JSON"))
            break  # the chain cannot continue past an unreadable record
        integrity = record.pop("integrity", None)
        if not isinstance(integrity, dict):
            violations.append(Violation(number, "record has no integrity block"))
            break
        if integrity.get("previous_hash") != previous:
            violations.append(
                Violation(number, "chain is broken",
                          "a record was inserted, removed, or reordered here")
            )
        expected = _event_hash(record, integrity.get("previous_hash", ""))
        if integrity.get("event_hash") != expected:
            violations.append(Violation(number, "record content was modified"))
        sequence = record.get("sequence")
        if isinstance(sequence, int):
            if last_sequence is not None and sequence <= last_sequence:
                violations.append(
                    Violation(number, "sequence is not increasing",
                              f"{last_sequence} then {sequence}")
                )
            last_sequence = sequence
        previous = integrity.get("event_hash", "")

    return VerificationReport(count, tuple(violations), previous)


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
