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


class TestRetentionEnforcement:
    """With a schedule supplied, retention_class stops being decoration."""

    @pytest.fixture
    def scheduled(self, tmp_path):
        from core.retention import DAY, RetentionSchedule

        class Clock:
            def __init__(self):
                self.now = 1_000_000.0

            def __call__(self):
                return self.now

            def advance_days(self, days):
                self.now += days * DAY

        clock = Clock()
        store = PayloadStore(tmp_path / "payloads",
                             schedule=RetentionSchedule(clock=clock), clock=clock)
        return store, clock

    def test_destruction_before_the_period_elapses_is_refused(self, scheduled):
        store, _ = scheduled
        reference = store.put(SENSITIVE, retention_class="standard")
        with pytest.raises(PayloadError) as error:
            store.destroy(reference, requester="dpo", reason="cleanup script")
        assert "may not be destroyed" in str(error.value)
        assert store.exists(reference.payload_id)

    def test_destruction_after_the_period_elapses_is_permitted(self, scheduled):
        store, clock = scheduled
        reference = store.put(SENSITIVE, retention_class="standard")
        clock.advance_days(91)
        store.destroy(reference, requester="dpo", reason="retention expired")
        assert not store.exists(reference.payload_id)

    def test_a_longer_class_is_held_longer(self, scheduled):
        store, clock = scheduled
        reference = store.put(SENSITIVE, retention_class="financial")
        clock.advance_days(91)
        with pytest.raises(PayloadError):
            store.destroy(reference, requester="dpo", reason="retention expired")

    def test_transient_data_can_go_immediately(self, scheduled):
        store, _ = scheduled
        reference = store.put(SENSITIVE, retention_class="transient")
        store.destroy(reference, requester="dpo", reason="no longer needed")
        assert not store.exists(reference.payload_id)

    def test_a_hold_still_outranks_an_elapsed_period(self, scheduled):
        store, clock = scheduled
        reference = store.put(SENSITIVE, retention_class="standard")
        store.place_hold(reference.payload_id)
        clock.advance_days(500)
        with pytest.raises(PayloadError) as error:
            store.destroy(reference, requester="dpo", reason="retention expired")
        assert "legal hold" in str(error.value)

    def test_a_sweep_sees_live_payloads_with_their_class(self, scheduled):
        store, _ = scheduled
        store.put(SENSITIVE, retention_class="financial")
        store.put(SENSITIVE, retention_class="transient")
        pending = store.pending_retention()
        assert {item["retention_class"] for item in pending} == {"financial", "transient"}

    def test_a_destroyed_payload_leaves_the_sweep(self, scheduled):
        store, _ = scheduled
        reference = store.put(SENSITIVE, retention_class="transient")
        store.destroy(reference, requester="dpo", reason="expired")
        assert store.pending_retention() == []

    def test_without_a_schedule_the_class_is_not_enforced(self, store):
        """Retention stays an explicit choice, not a default someone inherits."""
        reference = store.put(SENSITIVE, retention_class="financial")
        store.destroy(reference, requester="dpo", reason="no schedule configured")
        assert not store.exists(reference.payload_id)
