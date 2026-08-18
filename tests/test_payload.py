"""Erasure must not break the chain, and the chain must not block erasure (F-13)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.export import chain, verify_export  # noqa: E402
from core.payload import PayloadError, PayloadStore, redact  # noqa: E402

SENSITIVE = {"card_number": "4111111111111111", "note": "customer refund",
             "customer": {"email": "person@example.test"}}


@pytest.fixture
def store(tmp_path):
    return PayloadStore(tmp_path / "payloads")


class TestSeparation:
    def test_the_record_carries_a_digest_not_the_value(self, store):
        reference = store.put(SENSITIVE)
        record = reference.as_dict()
        serialized = str(record)
        assert "4111111111111111" not in serialized
        assert "person@example.test" not in serialized
        assert len(record["payload_digest"]) == 64

    def test_the_value_round_trips_while_it_exists(self, store):
        reference = store.put(SENSITIVE)
        assert store.get(reference) == SENSITIVE

    def test_stored_bytes_are_not_readable_without_the_key(self, store, tmp_path):
        reference = store.put(SENSITIVE)
        blob = (tmp_path / "payloads" / "blobs" / reference.payload_id).read_bytes()
        assert b"4111111111111111" not in blob

    def test_a_swapped_payload_is_detected_by_its_digest(self, store):
        reference = store.put(SENSITIVE)
        other = store.put({"card_number": "5555444433332222"})
        # Point the first reference at the second payload's bytes.
        forged = type(reference)(
            payload_id=other.payload_id,
            payload_digest=reference.payload_digest,
            classification=reference.classification,
            retention_class=reference.retention_class,
        )
        with pytest.raises(PayloadError):
            store.get(forged)

    def test_unknown_classification_is_refused(self, store):
        with pytest.raises(PayloadError):
            store.put(SENSITIVE, classification="top-secret-ish")


class TestDestruction:
    def test_destroying_removes_the_value(self, store):
        reference = store.put(SENSITIVE)
        store.destroy(reference, requester="dpo", reason="retention expired")
        assert not store.exists(reference.payload_id)
        with pytest.raises(PayloadError):
            store.get(reference)

    def test_destruction_returns_an_event_to_append(self, store):
        reference = store.put(SENSITIVE)
        event = store.destroy(reference, requester="dpo", reason="subject request")
        assert event["kind"] == "payload_destroyed"
        assert event["payload_digest"] == reference.payload_digest
        assert event["requester"] == "dpo"
        assert "card_number" not in str(event)

    def test_destroying_twice_is_an_error(self, store):
        reference = store.put(SENSITIVE)
        store.destroy(reference, requester="dpo", reason="expired")
        with pytest.raises(PayloadError):
            store.destroy(reference, requester="dpo", reason="expired")

    def test_erasure_leaves_the_chain_verifiable(self, store, tmp_path):
        """The point of the whole design: deletion must not invalidate evidence."""
        reference = store.put(SENSITIVE)
        records = [
            {"sequence": 1, "kind": "created", "payload": reference.as_dict()},
            {"sequence": 2, "kind": "approved", "payload": None},
        ]
        journal = tmp_path / "journal.jsonl"
        import json

        with journal.open("w", encoding="utf-8") as handle:
            for sealed in chain(records):
                handle.write(json.dumps(sealed, ensure_ascii=False, sort_keys=True) + "\n")
        assert verify_export(journal).ok

        store.destroy(reference, requester="dpo", reason="retention expired")

        # The journal is untouched by erasure and still verifies.
        assert verify_export(journal).ok
        # And the audit trail still shows the record existed, with its digest.
        first = json.loads(journal.read_text(encoding="utf-8").splitlines()[0])
        assert first["payload"]["payload_digest"] == reference.payload_digest


class TestLegalHold:
    def test_a_hold_blocks_destruction(self, store):
        reference = store.put(SENSITIVE)
        store.place_hold(reference.payload_id)
        with pytest.raises(PayloadError):
            store.destroy(reference, requester="dpo", reason="retention expired")
        assert store.exists(reference.payload_id)

    def test_releasing_a_hold_allows_destruction(self, store):
        reference = store.put(SENSITIVE)
        store.place_hold(reference.payload_id)
        store.release_hold(reference.payload_id)
        store.destroy(reference, requester="dpo", reason="hold lifted")
        assert not store.exists(reference.payload_id)


class TestInlineRedaction:
    def test_named_fields_are_replaced_and_reported(self):
        redacted, removed = redact(SENSITIVE, secret_keys=("card_number",))
        assert redacted["card_number"] == "[redacted]"
        assert removed == ("card_number",)
        assert redacted["note"] == "customer refund"

    def test_nested_fields_are_reached(self):
        redacted, removed = redact(SENSITIVE, secret_keys=("email",))
        assert redacted["customer"]["email"] == "[redacted]"
        assert removed == ("customer.email",)

    def test_redaction_does_not_mutate_the_input(self):
        original = dict(SENSITIVE)
        redact(SENSITIVE, secret_keys=("card_number",))
        assert SENSITIVE == original


class TestAuthenticatedEncryption:
    """AES-GCM gives guarantees a keystream cipher cannot: edits are detected."""

    def test_a_modified_blob_fails_to_decrypt_rather_than_yielding_other_data(self, store, tmp_path):
        reference = store.put(SENSITIVE)
        blob_path = tmp_path / "payloads" / "blobs" / reference.payload_id
        blob = bytearray(blob_path.read_bytes())
        blob[-1] ^= 0x01  # one bit
        blob_path.write_bytes(bytes(blob))
        with pytest.raises(PayloadError) as error:
            store.get(reference)
        assert "modified" in str(error.value)

    def test_a_blob_cannot_be_relabelled_as_another_record(self, store, tmp_path):
        """The payload id is associated data, so moving a blob breaks the tag."""
        first = store.put(SENSITIVE)
        second = store.put({"card_number": "5555444433332222"})
        blobs = tmp_path / "payloads" / "blobs"
        keys = tmp_path / "payloads" / "keys"
        # Give the second record the first record's bytes and key.
        (blobs / second.payload_id).write_bytes((blobs / first.payload_id).read_bytes())
        (keys / second.payload_id).write_bytes((keys / first.payload_id).read_bytes())
        with pytest.raises(PayloadError):
            store.get(second)

    def test_the_wrong_key_does_not_yield_plaintext(self, store, tmp_path):
        reference = store.put(SENSITIVE)
        (tmp_path / "payloads" / "keys" / reference.payload_id).write_bytes(b"\x00" * 32)
        with pytest.raises(PayloadError):
            store.get(reference)

    def test_a_truncated_blob_is_refused(self, store, tmp_path):
        reference = store.put(SENSITIVE)
        (tmp_path / "payloads" / "blobs" / reference.payload_id).write_bytes(b"\x00" * 4)
        with pytest.raises(PayloadError) as error:
            store.get(reference)
        assert "truncated" in str(error.value)

    def test_each_payload_gets_a_distinct_nonce(self, store, tmp_path):
        """Reusing a nonce under one key would be catastrophic for GCM."""
        blobs = tmp_path / "payloads" / "blobs"
        nonces = set()
        for _ in range(20):
            reference = store.put(SENSITIVE)
            nonces.add((blobs / reference.payload_id).read_bytes()[:12])
        assert len(nonces) == 20

    def test_identical_values_produce_different_ciphertexts(self, store, tmp_path):
        blobs = tmp_path / "payloads" / "blobs"
        first = store.put(SENSITIVE)
        second = store.put(SENSITIVE)
        assert (blobs / first.payload_id).read_bytes() != (blobs / second.payload_id).read_bytes()
