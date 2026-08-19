"""Freshness for the evidence chain (ADR-002 §7, finding F-12).

A hash chain proves that the records you are holding were not edited. It says
nothing about whether they are *all* of the records. Someone who controls the
host can restore an older, perfectly valid journal together with its signature
and the verifier will happily accept it: every hash matches, because the whole
set is genuine — just stale.

Signing does not fix this. A signature over an old state is still a valid
signature. What closes the gap is a monotonically increasing checkpoint counter
published somewhere the host does not control, so a verifier can ask "is 100 the
latest, or is there a 200 I am not being shown?".

    checkpoint = (log_id, sequence, journal_tip_hash, previous_checkpoint_hash)
                 signed with Ed25519, counter published to an external witness

Two divergent histories can each carry valid signatures; the witness sequence is
what makes one of them detectably a fork.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .witness import FileWitness, WitnessError, WitnessPort
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import dumps
from .export import GENESIS_HASH, verify_export

GENESIS_CHECKPOINT = "0" * 64


class CheckpointError(RuntimeError):
    """Raised when a checkpoint cannot be produced or trusted."""


@dataclass(frozen=True)
class Checkpoint:
    log_id: str
    sequence: int
    journal_tip_hash: str
    previous_checkpoint_hash: str
    signed_at: float
    signature: str = ""

    def body(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "sequence": self.sequence,
            "journal_tip_hash": self.journal_tip_hash,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "signed_at": self.signed_at,
        }

    def digest(self) -> str:
        import hashlib

        return hashlib.sha256(dumps(self.body()).encode("utf-8")).hexdigest()


class Signer:
    """Ed25519 signing. Key handling is the operator's problem, deliberately."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> "Signer":
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise CheckpointError("checkpoint signing requires an Ed25519 key")
        return cls(key)

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, checkpoint: Checkpoint) -> Checkpoint:
        payload = dumps(checkpoint.body()).encode("utf-8")
        signature = self._key.sign(payload).hex()
        return Checkpoint(
            checkpoint.log_id, checkpoint.sequence, checkpoint.journal_tip_hash,
            checkpoint.previous_checkpoint_hash, checkpoint.signed_at, signature,
        )


def verify_signature(checkpoint: Checkpoint, public_key_pem: bytes) -> bool:
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise CheckpointError("verification requires an Ed25519 public key")
    try:
        key.verify(bytes.fromhex(checkpoint.signature), dumps(checkpoint.body()).encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass
class Witness(FileWitness):
    """Backwards-compatible name for the file-backed witness.

    Kept because callers already say `Witness(path)` and because the change that
    matters is not the class - it is that `verify_freshness` now accepts anything
    satisfying `WitnessPort`, so a deployment can supply a witness that actually
    lives off the audited machine. See `core/witness.py` for why no vendor is
    picked here.

    `publish` still takes a Checkpoint, which is the convenient shape at this
    layer; the port takes the three fields, which is the shape a remote witness
    can honour without knowing what a Checkpoint is.
    """

    def publish(self, checkpoint: "Checkpoint | str", sequence: int | None = None,
                digest: str | None = None) -> None:
        try:
            if isinstance(checkpoint, Checkpoint):
                super().publish(checkpoint.log_id, checkpoint.sequence, checkpoint.digest())
            else:
                super().publish(checkpoint, int(sequence), str(digest))
        except WitnessError as error:
            # Callers of this class have always caught CheckpointError. Letting
            # the port's exception escape here would break them for the sake of
            # an internal refactor, so the compatibility boundary translates.
            raise CheckpointError(str(error)) from error


def journal_tip(journal_path: Path | str) -> str:
    """The hash of the last exported record, or genesis for an empty journal."""
    lines = [
        line for line in Path(journal_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not lines:
        return GENESIS_HASH
    return json.loads(lines[-1])["integrity"]["event_hash"]


def create_checkpoint(journal_path: Path | str, *, log_id: str, sequence: int,
                      previous: Checkpoint | None, signer: Signer,
                      now: float) -> Checkpoint:
    checkpoint = Checkpoint(
        log_id=log_id,
        sequence=sequence,
        journal_tip_hash=journal_tip(journal_path),
        previous_checkpoint_hash=previous.digest() if previous else GENESIS_CHECKPOINT,
        signed_at=now,
    )
    return signer.sign(checkpoint)


@dataclass(frozen=True)
class FreshnessReport:
    signature_valid: bool
    chain_intact: bool
    tip_matches: bool
    sequence_current: bool
    witness_sequence: int | None
    presented_sequence: int
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return all((self.signature_valid, self.chain_intact, self.tip_matches,
                    self.sequence_current))

    @property
    def verdict(self) -> str:
        """Which failure this is, as a value rather than a sentence.

        `ok` is one boolean over four checks, and two of the failures it covers
        need opposite responses. "The witness has never seen this log" is what a
        first checkpoint looks like before it is published; "rollback" is
        someone presenting an old checkpoint that was also validly signed. Both
        read as FAILED, and telling them apart meant matching on the note text -
        the same recovering-a-value-from-prose this project has had to fix twice
        elsewhere.

        Ordered by what a reader should act on first: a broken signature or
        chain says the artefact is not trustworthy at all, which outranks
        anything the witness has to say about it.
        """
        if not self.signature_valid:
            return "signature_invalid"
        if not self.chain_intact:
            return "chain_broken"
        if not self.tip_matches:
            return "tip_mismatch"
        if self.witness_sequence is None:
            return "not_witnessed"
        if self.presented_sequence < self.witness_sequence:
            return "rollback"
        if self.presented_sequence > self.witness_sequence:
            return "ahead_of_witness"
        return "current"

    def summary(self) -> str:
        if self.ok:
            return f"OK — checkpoint {self.presented_sequence} is signed, current, and matches the journal"
        return f"FAILED [{self.verdict}] — " + "; ".join(self.notes)


def verify_freshness(journal_path: Path | str, checkpoint: Checkpoint,
                     *, public_key_pem: bytes, witness: WitnessPort) -> FreshnessReport:
    """Check that a journal is intact *and* that it is the current one."""
    notes: list[str] = []

    signature_valid = verify_signature(checkpoint, public_key_pem)
    if not signature_valid:
        notes.append("checkpoint signature is invalid")

    export_report = verify_export(journal_path)
    if not export_report.ok:
        notes.append(f"journal chain is broken ({len(export_report.violations)} violation(s))")

    tip_matches = journal_tip(journal_path) == checkpoint.journal_tip_hash
    if not tip_matches:
        notes.append("checkpoint does not describe this journal's tip")

    witness_sequence = witness.latest_sequence(checkpoint.log_id)
    sequence_current = witness_sequence is not None and checkpoint.sequence == witness_sequence
    if witness_sequence is None:
        notes.append("the witness has never seen this log")
    elif checkpoint.sequence < witness_sequence:
        notes.append(
            f"rollback: witness has checkpoint {witness_sequence}, "
            f"only {checkpoint.sequence} was presented"
        )
    elif checkpoint.sequence > witness_sequence:
        notes.append(
            f"fork: checkpoint {checkpoint.sequence} was never published to the witness"
        )
    else:
        published = witness.digest_at(checkpoint.log_id, checkpoint.sequence)
        if published is not None and published != checkpoint.digest():
            sequence_current = False
            notes.append("fork: a different checkpoint was published at this sequence")

    return FreshnessReport(
        signature_valid=signature_valid,
        chain_intact=export_report.ok,
        tip_matches=tip_matches,
        sequence_current=sequence_current,
        witness_sequence=witness_sequence,
        presented_sequence=checkpoint.sequence,
        notes=tuple(notes),
    )


def load_checkpoint(path: Path | str) -> Checkpoint:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Checkpoint(**data)


def save_checkpoint(checkpoint: Checkpoint, path: Path | str) -> None:
    Path(path).write_text(
        json.dumps(checkpoint.__dict__, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
