"""Deleting sensitive data without destroying the audit record (finding F-13).

Two requirements point in opposite directions. An audit chain must be immutable,
or it proves nothing. Privacy law and retention policy say some of what passed
through must later be erased. If the sensitive values live *inside* the chained
records, honouring the second requirement breaks the first: editing a record
changes its hash and every record after it fails verification.

The way out is to keep them apart. The chained record holds only a digest, a
reference, and a classification; the values live in a separate store. Erasure
then means deleting from that store and *appending* a destruction event — the
chain grows, it is never rewritten.

What an auditor can still check after erasure: that the record existed, when it
was destroyed, who asked, and that nobody quietly swapped the contents (the
digest is still there and still covered by the chain). What they cannot recover
is the value itself, which is the entire point.

A legal hold blocks destruction, because "we were required to keep it" and "we
were required to delete it" is a conflict a system should surface rather than
resolve on its own.

Payloads are held under AES-256-GCM with a per-payload key. The payload id is
bound in as associated data, so a blob cannot be relabelled as a different
record and still decrypt.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import digest, dumps

CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")


class PayloadError(RuntimeError):
    """Raised when a payload cannot be stored, read, or destroyed as asked."""


@dataclass(frozen=True)
class PayloadReference:
    """What goes into the immutable record in place of the sensitive value."""

    payload_id: str
    payload_digest: str
    classification: str
    retention_class: str
    redactions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "payload_digest": self.payload_digest,
            "classification": self.classification,
            "retention_class": self.retention_class,
            "redactions": list(self.redactions),
        }


NONCE_BYTES = 12


def _encrypt(data: bytes, key: bytes, *, associated: bytes) -> bytes:
    """AES-256-GCM. The nonce is stored ahead of the ciphertext.

    Authenticated rather than merely obscured: an attacker who edits the stored
    bytes gets a decryption failure instead of different plaintext. The payload
    id travels as associated data, so a blob cannot be moved to a different
    record and still open.
    """
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, data, associated)


def _decrypt(blob: bytes, key: bytes, *, associated: bytes) -> bytes:
    if len(blob) <= NONCE_BYTES:
        raise PayloadError("stored payload is truncated")
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated)
    except InvalidTag as error:
        raise PayloadError("stored payload failed authentication: it was modified") from error


class PayloadStore:
    """Sensitive values, addressable by id, destroyable without touching the chain.

    A ``schedule`` turns ``retention_class`` from a label into a control: with
    one supplied, destruction before the stated period has elapsed is refused.
    Without one the store behaves as before, which keeps the retention decision
    an explicit choice rather than a default someone inherits.
    """

    def __init__(self, root: Path | str, *, schedule: Any = None,
                 clock: Any = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "keys").mkdir(exist_ok=True)
        (self.root / "blobs").mkdir(exist_ok=True)
        self._holds: set[str] = set()
        self._schedule = schedule
        self._clock = clock or (lambda: __import__("time").time())
        self._created: dict[str, float] = {}
        self._retention: dict[str, str] = {}

    # -- writing ------------------------------------------------------------

    def put(self, value: Any, *, classification: str = "confidential",
            retention_class: str = "standard",
            redactions: tuple[str, ...] = ()) -> PayloadReference:
        if classification not in CLASSIFICATIONS:
            raise PayloadError(f"unknown classification: {classification}")
        payload_id = secrets.token_hex(16)
        key = AESGCM.generate_key(bit_length=256)
        body = dumps(value).encode("utf-8")

        self._created[payload_id] = self._clock()
        self._retention[payload_id] = retention_class
        (self.root / "keys" / payload_id).write_bytes(key)
        (self.root / "blobs" / payload_id).write_bytes(
            _encrypt(body, key, associated=payload_id.encode("ascii"))
        )
        return PayloadReference(
            payload_id=payload_id,
            payload_digest=digest(value),
            classification=classification,
            retention_class=retention_class,
            redactions=redactions,
        )

    # -- reading ------------------------------------------------------------

    def get(self, reference: PayloadReference) -> Any:
        key_path = self.root / "keys" / reference.payload_id
        blob_path = self.root / "blobs" / reference.payload_id
        if not key_path.exists() or not blob_path.exists():
            raise PayloadError(f"payload {reference.payload_id} has been destroyed")
        plaintext = _decrypt(
            blob_path.read_bytes(), key_path.read_bytes(),
            associated=reference.payload_id.encode("ascii"),
        )
        value = json.loads(plaintext.decode("utf-8"))
        if digest(value) != reference.payload_digest:
            raise PayloadError("stored payload does not match the digest in the record")
        return value

    def exists(self, payload_id: str) -> bool:
        return (self.root / "blobs" / payload_id).exists()

    # -- retention ----------------------------------------------------------

    def place_hold(self, payload_id: str) -> None:
        """A legal hold outranks a deletion request until it is lifted."""
        self._holds.add(payload_id)

    def release_hold(self, payload_id: str) -> None:
        self._holds.discard(payload_id)

    def on_hold(self, payload_id: str) -> bool:
        return payload_id in self._holds

    def destroy(self, reference: PayloadReference, *, requester: str,
                reason: str) -> dict[str, Any]:
        """Erase the value and return the destruction event to append to the log.

        The caller appends the returned event; this function does not touch the
        chain, which is what keeps erasure from invalidating it.
        """
        if self._schedule is not None:
            # The schedule owns both questions, including the legal hold, so the
            # two rules cannot drift apart into contradicting each other.
            created_at = self._created.get(reference.payload_id, 0.0)
            try:
                self._schedule.require_destroyable(
                    reference.payload_id,
                    retention_class=self._retention.get(
                        reference.payload_id, reference.retention_class),
                    created_at=created_at,
                    on_hold=self.on_hold(reference.payload_id),
                    # **이 저장소의 시계로 판단한다.** `created_at`은 여기서 나온
                    # 값이고, 비교하는 "지금"이 다른 시계에서 오면 두 시각은 서로
                    # 아무 관계가 없다. schedule에 시계를 주지 않은 호출자에게는
                    # 10년 보존 클래스가 즉시 파기를 허용했다(2026-08-22 실측).
                    now=self._clock(),
                )
            except Exception as error:
                raise PayloadError(str(error)) from error
        elif self.on_hold(reference.payload_id):
            raise PayloadError(
                f"payload {reference.payload_id} is under legal hold and cannot be destroyed"
            )
        removed = False
        for folder in ("keys", "blobs"):
            path = self.root / folder / reference.payload_id
            if path.exists():
                # Overwrite before unlinking so a recovered inode yields nothing.
                length = path.stat().st_size
                with path.open("r+b") as handle:
                    handle.write(os.urandom(length))
                    handle.flush()
                    os.fsync(handle.fileno())
                path.unlink()
                removed = True
        if not removed:
            raise PayloadError(f"payload {reference.payload_id} was already destroyed")

        return {
            "kind": "payload_destroyed",
            "payload_id": reference.payload_id,
            "payload_digest": reference.payload_digest,
            "classification": reference.classification,
            "retention_class": reference.retention_class,
            "requester": requester,
            "reason": reason,
        }

    def retention_status(self, schedule: Any = None) -> tuple[Any, ...]:
        """This store's payloads, judged by a schedule **on this store's clock**.

        `pending_retention()` produces what `RetentionSchedule.sweep()` needs, so
        the obvious call is `schedule.sweep(store.pending_retention())` - and that
        call mixes two clocks. `created_at` comes from here; `now` would come from
        the schedule. A payload under a ten-year class was reported `eligible` the
        moment it was written, because a `created_at` of 1000.0 sits far behind
        wall time (measured 2026-08-22).

        The fix for `destroy` was the same: the object holding the clock makes the
        call. Passing `now` by hand works too, but it requires remembering, and a
        control that depends on remembering is the one that gets forgotten.
        """
        chosen = schedule if schedule is not None else self._schedule
        if chosen is None:
            raise PayloadError(
                "no retention schedule: this store was built without one and none "
                "was passed. Without a schedule there is nothing to judge against."
            )
        return chosen.sweep(self.pending_retention(), now=self._clock())

    def pending_retention(self) -> list[dict[str, Any]]:
        """What a sweep needs: every live payload with its class and age.

        Feeding this straight to `sweep()` compares these timestamps against the
        schedule's own clock. Use `retention_status()` unless you are passing
        `now=` yourself.
        """
        return [
            {"payload_id": payload_id,
             "retention_class": self._retention.get(payload_id, "standard"),
             "created_at": created_at,
             "on_hold": self.on_hold(payload_id)}
            for payload_id, created_at in sorted(self._created.items())
            if self.exists(payload_id)
        ]


def redact(value: Mapping[str, Any], *, secret_keys: tuple[str, ...]) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Replace sensitive fields with a marker, returning what was removed.

    Used for the copy that stays in the record when a value is small enough to
    keep inline. Nested keys are matched by name at any depth.
    """
    removed: list[str] = []

    def walk(node: Any, path: str = "") -> Any:
        if isinstance(node, dict):
            result = {}
            for key, item in node.items():
                here = f"{path}.{key}" if path else key
                if key in secret_keys:
                    removed.append(here)
                    result[key] = "[redacted]"
                else:
                    result[key] = walk(item, here)
            return result
        if isinstance(node, list):
            return [walk(item, f"{path}[{index}]") for index, item in enumerate(node)]
        return node

    return walk(dict(value)), tuple(removed)
