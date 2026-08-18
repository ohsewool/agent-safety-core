"""Separation of duties: the checks that permissions alone do not make."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.access import (
    ROLE_PERMISSIONS,
    AccessControl,
    AccessDenied,
    Permission,
    Principal,
    Role,
)


@pytest.fixture
def control():
    return AccessControl([
        Principal.with_roles("agent-1", Role.OPERATOR),
        Principal.with_roles("human-1", Role.APPROVER),
        Principal.with_roles("auditor-1", Role.AUDITOR),
        Principal.with_roles("reconciler-1", Role.RECONCILER),
        Principal.with_roles("dpo-1", Role.DATA_PROTECTION),
        Principal.with_roles("admin-1", Role.ADMINISTRATOR),
    ])


class TestDefaultDenial:
    def test_an_unknown_actor_holds_nothing(self, control):
        assert control.get("stranger").permissions == frozenset()

    def test_an_unknown_actor_is_refused_rather_than_erroring_oddly(self, control):
        with pytest.raises(AccessDenied):
            control.require("stranger", Permission.EXECUTION_DISPATCH)

    def test_a_role_grants_only_what_it_lists(self, control):
        operator = control.get("agent-1")
        assert operator.holds(Permission.EXECUTION_DISPATCH)
        assert not operator.holds(Permission.EXECUTION_APPROVE)


class TestRoleBoundaries:
    def test_an_operator_cannot_approve_its_own_work(self, control):
        with pytest.raises(AccessDenied):
            control.require("agent-1", Permission.EXECUTION_APPROVE)

    def test_an_operator_cannot_read_payloads(self, control):
        """Running the agent does not entitle you to everything it handled."""
        with pytest.raises(AccessDenied):
            control.require("agent-1", Permission.PAYLOAD_READ)

    def test_an_approver_cannot_dispatch(self, control):
        with pytest.raises(AccessDenied):
            control.require("human-1", Permission.EXECUTION_DISPATCH)

    def test_an_auditor_changes_nothing(self, control):
        for permission in (Permission.EXECUTION_APPROVE, Permission.PAYLOAD_DESTROY,
                           Permission.POLICY_WRITE, Permission.EXECUTION_DISPATCH):
            with pytest.raises(AccessDenied):
                control.require("auditor-1", permission)

    def test_a_data_protection_officer_cannot_read_the_payloads_they_destroy(self, control):
        control.require("dpo-1", Permission.PAYLOAD_DESTROY)
        with pytest.raises(AccessDenied):
            control.require("dpo-1", Permission.PAYLOAD_READ)

    def test_an_administrator_cannot_approve_or_dispatch(self, control):
        """Administering the system is not the same as using it."""
        for permission in (Permission.EXECUTION_APPROVE, Permission.EXECUTION_DISPATCH):
            with pytest.raises(AccessDenied):
                control.require("admin-1", permission)

    def test_only_a_reconciler_resolves_unknown_outcomes(self, control):
        control.require("reconciler-1", Permission.EXECUTION_RECONCILE)
        for actor in ("agent-1", "human-1", "auditor-1", "admin-1"):
            with pytest.raises(AccessDenied):
                control.require(actor, Permission.EXECUTION_RECONCILE)


class TestApprovalSeparation:
    def test_an_approver_may_approve_someone_elses_action(self, control):
        control.require_approval_separation(approver_id="human-1", requester_id="agent-1")

    def test_self_approval_is_refused_even_with_the_permission(self, control):
        """The failure that makes an approval gate decorative."""
        control.add(Principal.with_roles("both", Role.OPERATOR, Role.APPROVER))
        control.require("both", Permission.EXECUTION_APPROVE)  # holds it
        with pytest.raises(AccessDenied) as error:
            control.require_approval_separation(approver_id="both", requester_id="both")
        assert "proposed it" in str(error.value)

    def test_an_actor_without_the_permission_cannot_approve(self, control):
        with pytest.raises(AccessDenied):
            control.require_approval_separation(approver_id="agent-1", requester_id="human-1")


class TestAuditIndependence:
    def test_a_plain_auditor_passes(self, control):
        control.require_audit_independence("auditor-1")

    def test_an_auditor_who_can_destroy_is_refused(self, control):
        """Otherwise the examiner can erase what they were meant to examine."""
        control.add(Principal.with_roles("conflicted", Role.AUDITOR, Role.DATA_PROTECTION))
        with pytest.raises(AccessDenied) as error:
            control.require_audit_independence("conflicted")
        assert "may not be held by one actor" in str(error.value)

    def test_an_actor_without_read_access_is_refused(self, control):
        with pytest.raises(AccessDenied):
            control.require_audit_independence("stranger")


class TestComposition:
    def test_roles_compose_by_union(self, control):
        control.add(Principal.with_roles("multi", Role.OPERATOR, Role.RECONCILER))
        principal = control.get("multi")
        assert principal.holds(Permission.EXECUTION_DISPATCH)
        assert principal.holds(Permission.EXECUTION_RECONCILE)

    def test_composition_grants_nothing_extra(self, control):
        control.add(Principal.with_roles("multi", Role.OPERATOR, Role.RECONCILER))
        expected = ROLE_PERMISSIONS[Role.OPERATOR] | ROLE_PERMISSIONS[Role.RECONCILER]
        assert control.get("multi").permissions == expected

    def test_a_principal_with_no_roles_holds_nothing(self):
        assert Principal("nobody").permissions == frozenset()


class TestRoleTableInvariants:
    def test_no_single_role_can_both_approve_and_dispatch(self):
        """The separation must hold in the table, not only at the call site."""
        for role, permissions in ROLE_PERMISSIONS.items():
            both = {Permission.EXECUTION_APPROVE, Permission.EXECUTION_DISPATCH} <= permissions
            assert not both, role

    def test_no_single_role_can_both_read_and_destroy_payloads(self):
        for role, permissions in ROLE_PERMISSIONS.items():
            both = {Permission.PAYLOAD_READ, Permission.PAYLOAD_DESTROY} <= permissions
            assert not both, role

    def test_every_role_can_read_records(self):
        """Acting without being able to see what you did is not auditable."""
        for role, permissions in ROLE_PERMISSIONS.items():
            assert Permission.RECORD_READ in permissions, role

    def test_role_granting_is_held_by_exactly_one_role(self):
        holders = [role for role, perms in ROLE_PERMISSIONS.items()
                   if Permission.ROLE_GRANT in perms]
        assert holders == [Role.ADMINISTRATOR]


class TestDescription:
    def test_a_description_carries_roles_and_permissions(self, control):
        described = control.describe("human-1")
        assert described["actor_id"] == "human-1"
        assert described["roles"] == ["approver"]
        assert "execution:approve" in described["permissions"]

    def test_an_unknown_actor_describes_as_empty(self, control):
        described = control.describe("stranger")
        assert described["roles"] == []
        assert described["permissions"] == []
