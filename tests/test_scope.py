"""Scope binding regressions: ADR-002 §9 rows 3, 4, 5, 9 (findings F-01, F-06, F-07, F-14/15)."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.canonical import CanonicalizationError, digest, loads, normalize  # noqa: E402
from core.scope import (  # noqa: E402
    ContextSpec,
    ExecutionScope,
    PolicyBinding,
    ScopeError,
    rebind,
    resolve_opaque,
    resolve_path,
    resolve_url,
)

CONTEXT = {
    "code_revision": "abc123",
    "tool_version": "1.0.0",
    "execution_identity": "svc-agent",
    "working_directory": "/srv/app",
}

POLICY = PolicyBinding.from_document("fs-policy", "17", {"delete": "require_approval"})


def scope_for(path: Path, **overrides) -> ExecutionScope:
    base = dict(
        run_id="run-1", actor_id="agent-1", tool_id="filesystem", operation="write",
        arguments={"content": "x"}, resources=(resolve_path(str(path)),),
        policy=POLICY, context=dict(CONTEXT),
    )
    base.update(overrides)
    return ExecutionScope(**base)


class TestCanonicalization:
    """F-14/F-15: parsing must not silently pick a meaning."""

    def test_duplicate_keys_are_rejected_at_parse_time(self):
        with pytest.raises(CanonicalizationError):
            loads('{"path": "safe.txt", "path": "../../secret.txt"}')

    def test_nested_duplicate_keys_are_rejected(self):
        with pytest.raises(CanonicalizationError):
            loads('{"args": {"path": "a", "path": "b"}}')

    def test_non_finite_constants_are_rejected(self):
        with pytest.raises(CanonicalizationError):
            loads('{"amount": NaN}')
        with pytest.raises(CanonicalizationError):
            normalize({"amount": float("inf")})

    def test_unicode_spellings_agree(self):
        composed = "é"          # é as one code point
        decomposed = "é"       # e + combining acute
        assert digest({"name": composed}) == digest({"name": decomposed})

    def test_keys_colliding_after_normalisation_are_rejected(self):
        with pytest.raises(CanonicalizationError):
            normalize({"é": 1, "é": 2})

    def test_excessive_nesting_is_rejected(self):
        deep: dict = {}
        node = deep
        for _ in range(40):
            node["next"] = {}
            node = node["next"]
        with pytest.raises(CanonicalizationError):
            normalize(deep)

    def test_key_order_does_not_affect_the_digest(self):
        assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


class TestResourceIdentity:
    """F-07: bind the resolved target, not the string that names it."""

    def test_symlink_swap_after_approval_changes_the_digest(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        (real / "data.txt").write_text("safe", encoding="utf-8")
        protected = tmp_path / "protected"
        protected.mkdir()
        (protected / "data.txt").write_text("secret", encoding="utf-8")

        link = tmp_path / "safe"
        link.symlink_to(real)
        approved = scope_for(link / "data.txt")
        approved_digest = approved.digest()

        # The attacker repoints the directory; the path string is unchanged.
        link.unlink()
        link.symlink_to(protected)
        assert rebind(approved).digest() != approved_digest

    def test_unchanged_target_keeps_the_digest(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("safe", encoding="utf-8")
        approved = scope_for(target)
        assert rebind(approved).digest() == approved.digest()

    def test_swapping_a_different_file_into_place_changes_the_digest(self, tmp_path):
        """Renaming another file over the target keeps the name, changes the object."""
        target = tmp_path / "data.txt"
        target.write_text("original", encoding="utf-8")
        approved = scope_for(target)

        impostor = tmp_path / "impostor.txt"
        impostor.write_text("attacker content", encoding="utf-8")
        os.replace(impostor, target)  # same path, different inode
        assert rebind(approved).digest() != approved.digest()

    def test_creation_target_is_pinned_to_its_parent(self, tmp_path):
        target = tmp_path / "not-yet.txt"
        identity = resolve_path(str(target))
        assert identity.fingerprint.startswith("parent:")

    def test_relative_paths_cannot_be_bound(self):
        with pytest.raises(ScopeError):
            resolve_path("relative/path.txt")

    def test_url_binds_scheme_and_authority(self):
        assert resolve_url("HTTPS://API.Example.com/v1").locator == "https://api.example.com"

    def test_url_requires_authority(self):
        with pytest.raises(ScopeError):
            resolve_url("/just/a/path")

    def test_opaque_identifier_is_bound_verbatim(self):
        assert resolve_opaque("account", "acct-42").locator == "acct-42"


class TestPolicyBinding:
    """F-06: the version string is an identifier, not a commitment to content."""

    def test_same_version_different_content_changes_the_digest(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        approved = scope_for(target)

        weakened = PolicyBinding.from_document("fs-policy", "17", {"delete": "allow"})
        assert weakened.version == POLICY.version
        assert scope_for(target, policy=weakened).digest() != approved.digest()

    def test_identical_policy_documents_agree(self):
        first = PolicyBinding.from_document("p", "1", {"a": 1, "b": 2})
        second = PolicyBinding.from_document("p", "1", {"b": 2, "a": 1})
        assert first.content_digest == second.content_digest


class TestContextBinding:
    """F-01: an approval must not survive the code or identity changing under it."""

    def test_code_revision_change_invalidates_the_scope(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        approved = scope_for(target)
        moved = scope_for(target, context={**CONTEXT, "code_revision": "def456"})
        assert moved.digest() != approved.digest()

    def test_execution_identity_change_invalidates_the_scope(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        approved = scope_for(target)
        elevated = scope_for(target, context={**CONTEXT, "execution_identity": "root"})
        assert elevated.digest() != approved.digest()

    def test_unlisted_context_drift_does_not_invalidate(self, tmp_path):
        """The stated trade-off: only allow-listed fields may invalidate approvals."""
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        approved = scope_for(target)
        noisy = scope_for(target, context={**CONTEXT, "hostname": "worker-7", "pid": 4242})
        assert noisy.digest() == approved.digest()

    def test_missing_bound_context_is_an_error(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        incomplete = scope_for(target, context={"code_revision": "abc123"})
        with pytest.raises(ScopeError):
            incomplete.digest()

    def test_context_spec_is_configurable(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        narrow = ContextSpec(fields=("code_revision",))
        scope = scope_for(target, context={"code_revision": "abc123"}, context_spec=narrow)
        assert scope.digest()  # does not raise: only the listed field is required


class TestArgumentBinding:
    def test_argument_change_invalidates_the_scope(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        approved = scope_for(target)
        tampered = scope_for(target, arguments={"content": "malicious"})
        assert tampered.digest() != approved.digest()

    def test_unbindable_arguments_raise_scope_error(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        scope = scope_for(target, arguments={"amount": float("nan")})
        with pytest.raises(ScopeError):
            scope.digest()


class TestArgumentPolicyIntegration:
    """Declared equivalences reach the approval binding (arXiv:2608.02645 critique)."""

    def test_strictness_is_the_default(self, tmp_path):
        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        first = scope_for(target, arguments={"amount": 1000})
        second = scope_for(target, arguments={"amount": 1000.0})
        assert first.digest() != second.digest()

    def test_a_declared_equivalence_keeps_the_approval_valid(self, tmp_path):
        """A planner rewording 1000 as 1000.0 should not need re-approval."""
        from core.binding import ArgumentPolicy, Equivalence

        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC})
        first = scope_for(target, arguments={"amount": 1000}, argument_policy=policy)
        second = scope_for(target, arguments={"amount": 1000.0}, argument_policy=policy)
        assert first.digest() == second.digest()

    def test_loosening_the_policy_invalidates_an_existing_approval(self, tmp_path):
        """Otherwise a relaxation would widen what was already approved."""
        from core.binding import ArgumentPolicy, Equivalence

        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        approved = scope_for(target, arguments={"amount": 1000})
        relaxed = scope_for(target, arguments={"amount": 1000},
                            argument_policy=ArgumentPolicy({"amount": Equivalence.NUMERIC}))
        assert approved.digest() != relaxed.digest()

    def test_an_equivalence_does_not_hide_a_real_change(self, tmp_path):
        from core.binding import ArgumentPolicy, Equivalence

        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC})
        first = scope_for(target, arguments={"amount": 1000}, argument_policy=policy)
        second = scope_for(target, arguments={"amount": 9999}, argument_policy=policy)
        assert first.digest() != second.digest()

    def test_rebinding_preserves_the_argument_policy(self, tmp_path):
        from core.binding import ArgumentPolicy, Equivalence

        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC})
        scope = scope_for(target, arguments={"amount": 1000}, argument_policy=policy)
        assert rebind(scope).digest() == scope.digest()

    def test_a_misapplied_equivalence_surfaces_as_a_scope_error(self, tmp_path):
        from core.binding import ArgumentPolicy, Equivalence

        target = tmp_path / "data.txt"
        target.write_text("x", encoding="utf-8")
        scope = scope_for(target, arguments={"amount": "1000"},
                          argument_policy=ArgumentPolicy({"amount": Equivalence.NUMERIC}))
        with pytest.raises(ScopeError):
            scope.digest()
