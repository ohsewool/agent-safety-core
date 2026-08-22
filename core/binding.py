"""Which differences between two calls are real differences.

An approval binds to a digest of the arguments, and that digest is exact by
default: `1000` and `1000.0` are different, and so are `["a", "b"]` and
`["b", "a"]`. Exactness is the safe default, but it is not free — a planner that
rewords a request without changing what it asks for gets its approval refused,
and a system that refuses correct work trains people to approve twice.

The published critique of naive payload hashing (arXiv:2608.02645) is that the
key should derive from intent rather than wording. The naive fix — normalise
everything — is worse than the problem: deciding that `["alice", "bob"]` equals
`["bob", "alice"]` is a claim about the domain, and it is wrong for a list of
approvers acting in sequence.

So equivalences are declared per argument, never inferred. A caller states that
`amount` is numeric and `tags` is unordered, and everything else stays strict.

The policy is itself part of the digest. Loosening a rule after an approval was
given would otherwise widen what that approval permits, which is the thing the
binding exists to prevent — so it invalidates the approval instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .canonical import CanonicalizationError, digest, normalize


class Equivalence(str, Enum):
    """How two values of one argument are compared."""

    EXACT = "exact"          # the default: byte-for-byte after canonicalisation
    NUMERIC = "numeric"      # 1000 and 1000.0 are one amount
    UNORDERED = "unordered"  # sequence order carries no meaning here
    TRIMMED = "trimmed"      # leading and trailing whitespace is not content
    CASE_FOLDED = "case_folded"  # letter case is not content


class BindingError(ValueError):
    """Raised when an equivalence cannot be applied to the value it names."""


def _apply(value: Any, rule: Equivalence) -> Any:
    if rule is Equivalence.EXACT:
        return value
    if rule is Equivalence.NUMERIC:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BindingError(f"numeric equivalence needs a number, got {type(value).__name__}")
        return float(value)
    if rule is Equivalence.UNORDERED:
        if not isinstance(value, (list, tuple)):
            raise BindingError(
                f"unordered equivalence needs a sequence, got {type(value).__name__}"
            )
        # Sorted by canonical form so ordering is stable across mixed types.
        return sorted((normalize(item) for item in value), key=lambda item: digest(item))
    if isinstance(value, str):
        if rule is Equivalence.TRIMMED:
            return value.strip()
        if rule is Equivalence.CASE_FOLDED:  # pragma: no branch - the enum has no sixth rule
            # Falling through with a string in hand would need a rule that is
            # none of the five: EXACT, NUMERIC and UNORDERED return above, and
            # these two return here. Measured on 2026-08-22 with branch coverage,
            # which is stricter than the statement gate added the day before -
            # the line ran, the arc out of it never did.
            return value.casefold()
    raise BindingError(f"{rule.value} equivalence needs a string, got {type(value).__name__}")


@dataclass(frozen=True)
class ArgumentPolicy:
    """Declared equivalences, by argument name. Everything unnamed stays exact."""

    rules: Mapping[str, Equivalence] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, rule in self.rules.items():
            if not isinstance(rule, Equivalence):
                raise BindingError(f"{name}: equivalence must be an Equivalence value")

    def canonical_arguments(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Return the arguments with each declared equivalence applied."""
        result: dict[str, Any] = {}
        for name, value in arguments.items():
            rule = self.rules.get(name, Equivalence.EXACT)
            try:
                result[name] = _apply(value, rule)
            except BindingError as error:
                raise BindingError(f"{name}: {error}") from error
        return result

    def digest_of(self, arguments: Mapping[str, Any]) -> str:
        """Digest the arguments *and* the policy that interpreted them.

        Including the policy is what stops a later relaxation from quietly
        widening an approval that was given under stricter rules.
        """
        try:
            return digest({
                "arguments": self.canonical_arguments(arguments),
                "policy": {name: rule.value for name, rule in sorted(self.rules.items())},
            })
        except CanonicalizationError as error:
            raise BindingError(str(error)) from error

    def equivalent(self, first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
        """Would these two calls bind to the same approval?"""
        return self.digest_of(first) == self.digest_of(second)

    def with_rule(self, name: str, rule: Equivalence) -> "ArgumentPolicy":
        return ArgumentPolicy({**self.rules, name: rule})

    def describe(self) -> dict[str, str]:
        """What a reviewer should see before approving under this policy."""
        return {name: rule.value for name, rule in sorted(self.rules.items())}


STRICT = ArgumentPolicy()
"""The default. Every difference is a difference."""
