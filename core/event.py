"""정규화 실행 이벤트: canonical 직렬화, 해시 체인, 변조 탐지.

Coordinator의 coordinator_security 프리미티브(canonical_json, sha256)를
범용 추출한 v0. 서명/외부 체크포인트는 M3 범위.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_event_hash(event: dict[str, Any], previous_hash: str) -> str:
    """integrity 필드를 제외한 이벤트 본문 + 직전 해시로 체인 해시를 만든다."""
    body = {k: v for k, v in event.items() if k != "integrity"}
    return sha256_hex(previous_hash.encode("ascii") + canonical_json(body))


def seal_event(event: dict[str, Any], previous_hash: str) -> dict[str, Any]:
    sealed = dict(event)
    sealed["integrity"] = {
        "previous_hash": previous_hash,
        "event_hash": compute_event_hash(event, previous_hash),
        "signature": None,
    }
    return sealed


def append_event(journal_path: Path, event: dict[str, Any]) -> dict[str, Any]:
    """이벤트를 봉인해 JSONL 저널 끝에 붙인다. 직전 이벤트의 해시에 연결된다."""
    previous_hash = GENESIS_HASH
    if journal_path.exists():
        lines = journal_path.read_text(encoding="utf-8").splitlines()
        if lines:
            previous_hash = json.loads(lines[-1])["integrity"]["event_hash"]
    sealed = seal_event(event, previous_hash)
    with journal_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(sealed, ensure_ascii=False, sort_keys=True) + "\n")
    return sealed


def verify_chain(journal_path: Path) -> list[str]:
    """저널 전체의 체인을 검증한다. 위반 사항 목록을 돌려준다 (빈 목록 = 정상)."""
    violations: list[str] = []
    previous_hash = GENESIS_HASH
    for lineno, line in enumerate(
        journal_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        event = json.loads(line)
        integrity = event.get("integrity", {})
        if integrity.get("previous_hash") != previous_hash:
            violations.append(f"line {lineno}: previous_hash mismatch")
        expected = compute_event_hash(event, integrity.get("previous_hash", ""))
        if integrity.get("event_hash") != expected:
            violations.append(f"line {lineno}: event_hash mismatch")
        previous_hash = integrity.get("event_hash", "")
    return violations
