"""Anti-rollback: the attack that a valid signature does not stop (F-12)."""

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.checkpoint import (  # noqa: E402
    GENESIS_CHECKPOINT,
    Checkpoint,
    CheckpointError,
    Signer,
    Witness,
    create_checkpoint,
    journal_tip,
    load_checkpoint,
    save_checkpoint,
    verify_freshness,
    verify_signature,
)
from core.export import export_ledger, verify_export  # noqa: E402
from core.ledger import ExecutionLedger, SUCCEEDED  # noqa: E402

SCOPE = "a" * 64
LOG_ID = "ledger-1"


def add_execution(ledger, index: int) -> None:
    execution_id = ledger.create(
        run_id="run-1", actor_id="agent-1", tool_id="payments",
        operation="transfer", scope_digest=SCOPE,
    )
    lease = ledger.approve(execution_id, approver_id="human-1",
                           scope_digest=SCOPE, ttl_seconds=60)
    ledger.claim_lease(lease, scope_digest=SCOPE)
    ledger.record_outcome(execution_id, state=SUCCEEDED, evidence={"index": index})


@pytest.fixture
def world(tmp_path):
    """A ledger, its journal, a signer, and a witness — the full evidence path."""
    ledger = ExecutionLedger(str(tmp_path / "ledger.db"))
    signer = Signer.generate()
    witness = Witness(tmp_path / "witness.jsonl")
    journal = tmp_path / "journal.jsonl"

    add_execution(ledger, 0)
    export_ledger(ledger, journal)
    first = create_checkpoint(journal, log_id=LOG_ID, sequence=1, previous=None,
                              signer=signer, now=1000.0)
    witness.publish(first)

    yield {"ledger": ledger, "signer": signer, "witness": witness,
           "journal": journal, "checkpoint": first, "tmp": tmp_path}
    ledger.close()


class TestSigning:
    def test_a_signed_checkpoint_verifies(self, world):
        assert verify_signature(world["checkpoint"], world["signer"].public_key_pem())

    def test_an_edited_checkpoint_fails_verification(self, world):
        tampered = Checkpoint(
            **{**world["checkpoint"].__dict__, "journal_tip_hash": "f" * 64}
        )
        assert not verify_signature(tampered, world["signer"].public_key_pem())

    def test_another_key_cannot_vouch_for_it(self, world):
        assert not verify_signature(world["checkpoint"], Signer.generate().public_key_pem())

    def test_checkpoints_chain_to_their_predecessor(self, world):
        second = create_checkpoint(world["journal"], log_id=LOG_ID, sequence=2,
                                   previous=world["checkpoint"], signer=world["signer"],
                                   now=2000.0)
        assert second.previous_checkpoint_hash == world["checkpoint"].digest()
        assert world["checkpoint"].previous_checkpoint_hash == GENESIS_CHECKPOINT

    def test_checkpoints_survive_a_round_trip(self, world):
        path = world["tmp"] / "checkpoint.json"
        save_checkpoint(world["checkpoint"], path)
        assert load_checkpoint(path) == world["checkpoint"]


class TestFreshness:
    def test_current_state_verifies(self, world):
        report = verify_freshness(world["journal"], world["checkpoint"],
                                  public_key_pem=world["signer"].public_key_pem(),
                                  witness=world["witness"])
        assert report.ok, report.summary()

    def test_rollback_to_an_older_signed_state_is_detected(self, world):
        """The attack: restore an old journal *and* its genuine checkpoint."""
        archived_journal = world["tmp"] / "archive.jsonl"
        shutil.copy(world["journal"], archived_journal)
        archived_checkpoint = world["checkpoint"]

        # Time passes; the log advances and the witness is told.
        add_execution(world["ledger"], 1)
        export_ledger(world["ledger"], world["journal"])
        second = create_checkpoint(world["journal"], log_id=LOG_ID, sequence=2,
                                   previous=archived_checkpoint, signer=world["signer"],
                                   now=2000.0)
        world["witness"].publish(second)

        # The host presents the old pair. Every signature and hash is genuine.
        assert verify_signature(archived_checkpoint, world["signer"].public_key_pem())
        assert verify_export(archived_journal).ok

        report = verify_freshness(archived_journal, archived_checkpoint,
                                  public_key_pem=world["signer"].public_key_pem(),
                                  witness=world["witness"])
        assert not report.ok
        assert any("rollback" in note for note in report.notes)

    def test_unpublished_fork_is_detected(self, world):
        """A checkpoint the witness never saw cannot pass as current."""
        add_execution(world["ledger"], 1)
        export_ledger(world["ledger"], world["journal"])
        unpublished = create_checkpoint(world["journal"], log_id=LOG_ID, sequence=2,
                                        previous=world["checkpoint"],
                                        signer=world["signer"], now=2000.0)
        report = verify_freshness(world["journal"], unpublished,
                                  public_key_pem=world["signer"].public_key_pem(),
                                  witness=world["witness"])
        assert not report.ok
        assert any("fork" in note for note in report.notes)

    def test_divergent_checkpoint_at_the_same_sequence_is_detected(self, world):
        """Two valid histories at one sequence: the witness names which is real."""
        divergent = create_checkpoint(world["journal"], log_id=LOG_ID, sequence=1,
                                      previous=None, signer=world["signer"], now=9999.0)
        report = verify_freshness(world["journal"], divergent,
                                  public_key_pem=world["signer"].public_key_pem(),
                                  witness=world["witness"])
        assert not report.ok
        assert any("different checkpoint" in note for note in report.notes)

    def test_checkpoint_from_another_journal_is_rejected(self, world):
        other = world["tmp"] / "other.jsonl"
        other.write_text("", encoding="utf-8")
        report = verify_freshness(other, world["checkpoint"],
                                  public_key_pem=world["signer"].public_key_pem(),
                                  witness=world["witness"])
        assert not report.tip_matches

    def test_edited_journal_is_reported_even_with_a_valid_checkpoint(self, world):
        import json
        lines = world["journal"].read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["kind"] = "approved"          # rewrite history, keep the integrity block
        lines[0] = json.dumps(record, ensure_ascii=False, sort_keys=True)
        world["journal"].write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = verify_freshness(world["journal"], world["checkpoint"],
                                  public_key_pem=world["signer"].public_key_pem(),
                                  witness=world["witness"])
        assert not report.ok

    def test_unknown_log_is_not_treated_as_current(self, world):
        stranger = Checkpoint(**{**world["checkpoint"].__dict__, "log_id": "ledger-2"})
        signed = world["signer"].sign(stranger)
        report = verify_freshness(world["journal"], signed,
                                  public_key_pem=world["signer"].public_key_pem(),
                                  witness=world["witness"])
        assert not report.ok
        assert any("never seen" in note for note in report.notes)


class TestWitness:
    def test_witness_refuses_to_go_backwards(self, world):
        stale = create_checkpoint(world["journal"], log_id=LOG_ID, sequence=1,
                                  previous=None, signer=world["signer"], now=3000.0)
        with pytest.raises(CheckpointError):
            world["witness"].publish(stale)

    def test_witness_survives_a_restart(self, world):
        reopened = Witness(world["witness"].path)
        assert reopened.latest_sequence(LOG_ID) == 1

    def test_journal_tip_matches_the_last_record(self, world):
        import json
        last = json.loads(world["journal"].read_text(encoding="utf-8").splitlines()[-1])
        assert journal_tip(world["journal"]) == last["integrity"]["event_hash"]
