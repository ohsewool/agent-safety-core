"""Canonical form for values that security decisions are computed over.

Two components that disagree about what a payload *means* can authorise one thing
and execute another.  The adversarial review found three ways that happens, and
this module closes all three at the parsing boundary rather than after the fact:

duplicate keys
    ``{"path": "safe", "path": "../secret"}`` is accepted by most JSON parsers,
    which then silently keep either the first or the last value.  Once parsed
    into a dict the duplicate is gone and no later hashing can recover it, so the
    only safe moment to reject it is during parsing.

non-finite numbers
    ``NaN``/``Infinity`` are not JSON, and ``NaN != NaN`` breaks the comparison
    that scope binding depends on.

unbounded shape
    Deep nesting and huge payloads turn canonicalisation into a denial of
    service, and a canonicaliser that fails is a control that fails.

Unicode is normalised to NFC so that two spellings of the same string produce the
same digest.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

MAX_DEPTH = 32
MAX_KEYS = 1000
MAX_STRING = 65536


class CanonicalizationError(ValueError):
    """Raised when a value cannot be reduced to an unambiguous canonical form."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise CanonicalizationError(f"duplicate JSON key is not permitted: {key!r}")
        seen.add(key)
    return dict(pairs)


def loads(text: str) -> Any:
    """Parse untrusted JSON, rejecting shapes that two parsers could disagree on."""
    if len(text) > MAX_STRING * 4:
        raise CanonicalizationError("payload exceeds the maximum accepted size")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_bad_constant)
    except CanonicalizationError:
        raise
    except json.JSONDecodeError as error:
        raise CanonicalizationError("payload is not valid JSON") from error


def _bad_constant(name: str) -> Any:
    raise CanonicalizationError(f"non-finite JSON constant is not permitted: {name}")


def normalize(value: Any, *, _depth: int = 0) -> Any:
    """Return an equivalent value in canonical form, or raise."""
    if _depth > MAX_DEPTH:
        raise CanonicalizationError(f"value nests deeper than {MAX_DEPTH} levels")

    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise CanonicalizationError("string exceeds the maximum accepted length")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalizationError("non-finite numbers are not permitted")
        return value
    if isinstance(value, dict):
        if len(value) > MAX_KEYS:
            raise CanonicalizationError(f"object has more than {MAX_KEYS} keys")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            canonical_key = unicodedata.normalize("NFC", key)
            if canonical_key in normalized:
                # Distinct spellings that normalise to one key are ambiguous.
                raise CanonicalizationError(f"keys collide after normalisation: {canonical_key!r}")
            normalized[canonical_key] = normalize(item, _depth=_depth + 1)
        return normalized
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_KEYS:
            raise CanonicalizationError(f"array has more than {MAX_KEYS} items")
        return [normalize(item, _depth=_depth + 1) for item in value]
    raise CanonicalizationError(f"unsupported type in canonical value: {type(value).__name__}")


def dumps(value: Any) -> str:
    """Serialise a value to its canonical string form."""
    return json.dumps(
        normalize(value), ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    )


def digest(value: Any) -> str:
    """SHA-256 of the canonical form. The unit every security decision compares."""
    return hashlib.sha256(dumps(value).encode("utf-8")).hexdigest()
