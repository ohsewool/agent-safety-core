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
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

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


def _obfuscate(data: bytes, key: bytes) -> bytes:
    """XOR with a per-payload keystream.

    Deliberately simple and deliberately labelled: this makes the stored bytes
    unreadable without the key, so destroying the key destroys the payload. It is
    not a substitute for authenticated encryption at rest, and the README says
    so; swapping in AES-GCM changes this function and nothing else.
    """
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        import hashlib

        stream.extend(hashlib.sha256(key + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(byte ^ stream[index] for index, byte in enumerate(data))


class PayloadStore:
    """Sensitive values, addressable by id, destroyable without touching the chain."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "keys").mkdir(exist_ok=True)
        (self.root / "blobs").mkdir(exist_ok=True)
        self._holds: set[str] = set()

    # -- writing ------------------------------------------------------------

    def put(self, value: Any, *, classification: str = "confidential",
            retention_class: str = "standard",
            redactions: tuple[str, ...] = ()) -> PayloadReference:
        if classification not in CLASSIFICATIONS:
            raise PayloadError(f"unknown classification: {classification}")
        payload_id = secrets.token_hex(16)
        key = secrets.token_bytes(32)
        body = dumps(value).encode("utf-8")

        (self.root / "keys" / payload_id).write_bytes(key)
        (self.root / "blobs" / payload_id).write_bytes(_obfuscate(body, key))
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
        value = json.loads(_obfuscate(blob_path.read_bytes(), key_path.read_bytes()).decode("utf-8"))
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
        if self.on_hold(reference.payload_id):
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
