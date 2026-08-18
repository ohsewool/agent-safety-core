"""M0 종료 조건 검증: 단일 도구 호출을 정규화 이벤트로 저장하고, 변조를 탐지한다."""

import json
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.event import GENESIS_HASH, append_event, verify_chain  # noqa: E402

jsonschema = pytest.importorskip("jsonschema")

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schema" / "event.schema.json").read_text()
)


def sample_tool_call(sequence: int) -> dict:
    return {
        "event_id": uuid.uuid4().hex,
        "run_id": "run-0001-demo",
        "sequence": sequence,
        "occurred_at": "2026-08-19T00:00:00Z",
        "actor": {"id": "agent-1", "type": "ai_agent"},
        "action": {"tool": "filesystem", "operation": "write", "arguments_hash": "ab" * 32},
        "execution": {"status": "proposed"},
    }


def test_recorded_event_matches_schema(tmp_path):
    journal = tmp_path / "journal.jsonl"
    sealed = append_event(journal, sample_tool_call(0))
    jsonschema.validate(sealed, SCHEMA)
    assert sealed["integrity"]["previous_hash"] == GENESIS_HASH


def test_chain_links_and_verifies(tmp_path):
    journal = tmp_path / "journal.jsonl"
    first = append_event(journal, sample_tool_call(0))
    second = append_event(journal, sample_tool_call(1))
    assert second["integrity"]["previous_hash"] == first["integrity"]["event_hash"]
    assert verify_chain(journal) == []


def test_tampered_body_is_detected(tmp_path):
    journal = tmp_path / "journal.jsonl"
    append_event(journal, sample_tool_call(0))
    append_event(journal, sample_tool_call(1))
    lines = journal.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["action"]["operation"] = "delete"
    lines[0] = json.dumps(tampered, ensure_ascii=False, sort_keys=True)
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("event_hash mismatch" in v for v in verify_chain(journal))


def test_deleted_event_is_detected(tmp_path):
    journal = tmp_path / "journal.jsonl"
    for i in range(3):
        append_event(journal, sample_tool_call(i))
    lines = journal.read_text(encoding="utf-8").splitlines()
    journal.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert any("previous_hash mismatch" in v for v in verify_chain(journal))


def test_unknown_outcome_is_first_class(tmp_path):
    journal = tmp_path / "journal.jsonl"
    event = sample_tool_call(0)
    event["execution"] = {"status": "unknown_outcome"}
    sealed = append_event(journal, event)
    jsonschema.validate(sealed, SCHEMA)
