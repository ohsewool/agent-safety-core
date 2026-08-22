"""거부 일곱 개가 한 번도 발동한 적이 없었다.

2026-08-22에 형제 저장소 `document-intelligence`에서 한 감사를 여기로 가져왔다.
문자열 메시지를 가진 `raise` **30개를 하나씩 `pass`로 바꾸고** 매번 스위트를 돌렸다.

    잡힘        23건
    안 잡힘      7건

일곱은 지워도 503개가 전부 통과한다. "표현할 수 없는 것은 거부한다"가 아니라
"거부한다고 적어뒀다"인 상태다 — 조건 하나가 뒤집혀 있어도 정상 입력만으로는 아무
차이가 없고, 이 저장소의 주장은 정확히 그 조건들 위에 서 있다.

일곱이 무엇인지 보면 왜 빠졌는지가 보인다.

* **키 종류 거부 둘** — Ed25519가 아닌 키로 서명하거나 검증하려는 경우. 테스트는
  항상 올바른 키를 만들어 쓴다.
* **없는 실행 둘** — `record_outcome`과 `reconcile`이 모르는 `execution_id`를 받는
  경우. 테스트는 항상 먼저 만들어 놓고 부른다.
* **URL 거부 하나** — 빈 문자열이나 문자열이 아닌 것.
* **witness 적합성 검사 둘** — `assert_conforms`는 **다른 구현을 검사하는 도구**다.
  스위트는 올바른 구현만 넘겼으므로, 그 도구가 위반을 잡는지는 한 번도 확인되지
  않았다. **검사기를 검사하지 않으면 그것도 주장일 뿐이다.**

마지막 둘이 이 감사의 값이다. 나머지 다섯은 "안 써본 입력"이지만, 저것은
**틀린 witness를 통과시키는 검사기**가 될 수 있었고 아무도 몰랐을 것이다.
"""

from __future__ import annotations

import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from core.checkpoint import CheckpointError, Checkpoint, Signer, verify_signature
from core.ledger import ExecutionLedger, LedgerError
from core.scope import ScopeError, resolve_url
from core.witness import FileWitness, WitnessError, assert_conforms


class TestOnlyEd25519Keys:
    """서명 알고리즘을 바꾸는 것은 위조 비용을 바꾸는 일이다. RSA 키가 조용히
    받아들여지면 체크포인트는 이 저장소가 말하는 그 물건이 아니다."""

    def test_signing_refuses_a_non_ed25519_key(self):
        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(CheckpointError, match="requires an Ed25519 key"):
            Signer.from_pem(pem)

    def test_verification_refuses_a_non_ed25519_public_key(self):
        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(
        ).public_bytes(encoding=serialization.Encoding.PEM,
                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
        signer = Signer(ed25519.Ed25519PrivateKey.generate())
        checkpoint = signer.sign(Checkpoint(log_id="l", sequence=1, journal_tip_hash="tip",
                                            previous_checkpoint_hash="", signed_at=1.0))
        with pytest.raises(CheckpointError, match="requires an Ed25519 public key"):
            verify_signature(checkpoint, pem)

    def test_an_ed25519_key_still_works(self):
        """거부만 확인하면 전부 거부하는 구현도 통과한다."""
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption())
        signer = Signer.from_pem(pem)
        checkpoint = signer.sign(Checkpoint(log_id="l", sequence=1, journal_tip_hash="tip",
                                            previous_checkpoint_hash="", signed_at=1.0))
        public = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        assert verify_signature(checkpoint, public)


class TestAnUnknownExecutionIsRefused:
    """모르는 `execution_id`에 결과를 적는 것은 **없던 실행을 만들어내는 일**이다.
    조용히 넘어가면 원장에 근거 없는 종결이 생기고, 그것이 이 저장소가 막으려는 것의
    반대다."""

    def test_recording_an_outcome_for_one(self, tmp_path):
        ledger = ExecutionLedger(str(tmp_path / "l.db"))
        try:
            with pytest.raises(LedgerError, match="unknown execution"):
                ledger.record_outcome("no-such-execution", state="SUCCEEDED", evidence={})
        finally:
            ledger.close()

    def test_reconciling_one(self, tmp_path):
        ledger = ExecutionLedger(str(tmp_path / "l.db"))
        try:
            with pytest.raises(LedgerError, match="requires an UNKNOWN execution"):
                ledger.reconcile("no-such-execution", new_state="SUCCEEDED",
                                 reconciler_id="human:ops", evidence={})
        finally:
            ledger.close()


class TestAUrlResourceNeedsAString:
    @pytest.mark.parametrize("raw", ["", None, 42, b"https://example.test"])
    def test_it_is_refused(self, raw):
        with pytest.raises(ScopeError, match="non-empty string"):
            resolve_url(raw)

    def test_a_real_url_resolves(self):
        assert resolve_url("https://example.test/a/b") is not None


class TestTheConformanceCheckerActuallyChecks:
    """`assert_conforms`는 **배포가 실제로 들고 온 witness**를 검사하라고 있는
    도구다. 스위트는 올바른 구현만 넘겼으므로, 이 도구가 위반을 잡는지는 한 번도
    확인된 적이 없다 — **검사기를 검사하지 않으면 그것도 주장일 뿐이다.**"""

    def test_a_conforming_witness_passes(self, tmp_path):
        assert_conforms(FileWitness(tmp_path / "w.jsonl"), log_id="scratch")

    def test_a_witness_whose_latest_sequence_lies_is_caught(self, tmp_path):
        class Frozen(FileWitness):
            def latest_sequence(self, log_id):   # 발행해도 움직이지 않는다
                return None

        with pytest.raises(WitnessError, match="latest_sequence did not reflect"):
            assert_conforms(Frozen(tmp_path / "w.jsonl"), log_id="scratch")

    def test_a_witness_that_returns_the_wrong_digest_is_caught(self, tmp_path):
        class Wrong(FileWitness):
            def digest_at(self, log_id, sequence):
                return "not-the-digest"

        with pytest.raises(WitnessError, match="digest_at did not return"):
            assert_conforms(Wrong(tmp_path / "w.jsonl"), log_id="scratch")

    def test_a_witness_whose_counter_stalls_after_the_second_publish_is_caught(self, tmp_path):
        """첫 발행만 반영하고 그 뒤로 멈추는 구현. 첫 검사만 있으면 통과한다 —
        그래서 두 번째 발행 뒤에도 확인하는 줄이 따로 있고, 그 줄이 이 감사에서
        발동한 적 없는 일곱 중 하나였다."""
        class StallsAfterOne(FileWitness):
            def latest_sequence(self, log_id):
                seen = super().latest_sequence(log_id)
                return None if seen is None else min(seen, 1)

        with pytest.raises(WitnessError, match="latest_sequence did not advance"):
            assert_conforms(StallsAfterOne(tmp_path / "w.jsonl"), log_id="scratch")
