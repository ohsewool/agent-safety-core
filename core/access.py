"""Who may do what, and why the audit log is the thing most in need of guarding.

The threat model names a specific danger: the journal concentrates prompts, tool
arguments, and whatever personal data passed through, which makes it a richer
target than the systems it describes. An operator who can read every payload has
more reach than one who can merely run the agent.

So the separations are chosen against concrete abuses rather than for tidiness:

approver ≠ requester
    someone who can both request and approve an action has no oversight at all,
    and self-approval is the failure that makes an approval gate decorative

auditor ≠ operator
    an auditor who can also destroy payloads can erase what they were meant to
    examine; an operator who can read the audit log can check whether their own
    mistake was noticed

payload access ≠ record access
    reading that an execution happened is routine. Reading what was in it is
    not, and the two are separate permissions because most work needs only the
    first

Denial is the default: an unknown role gets nothing, and a permission that has
not been granted is not held. Roles compose by union, so a person with two roles
holds both sets and nothing more.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping


class Permission(str, Enum):
    """Individually grantable capabilities."""

    EXECUTION_PROPOSE = "execution:propose"
    EXECUTION_APPROVE = "execution:approve"
    EXECUTION_REVOKE = "execution:revoke"
    EXECUTION_DISPATCH = "execution:dispatch"
    EXECUTION_RECONCILE = "execution:reconcile"

    RECORD_READ = "record:read"
    PAYLOAD_READ = "payload:read"
    PAYLOAD_DESTROY = "payload:destroy"
    LEGAL_HOLD_MANAGE = "legal_hold:manage"

    EVIDENCE_EXPORT = "evidence:export"
    CHECKPOINT_SIGN = "checkpoint:sign"

    POLICY_WRITE = "policy:write"
    ROLE_GRANT = "role:grant"


class Role(str, Enum):
    OPERATOR = "operator"
    APPROVER = "approver"
    AUDITOR = "auditor"
    RECONCILER = "reconciler"
    DATA_PROTECTION = "data_protection"
    ADMINISTRATOR = "administrator"


ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = {
    # Runs the agent. Cannot approve its own work and cannot read payloads.
    Role.OPERATOR: frozenset({
        Permission.EXECUTION_PROPOSE,
        Permission.EXECUTION_DISPATCH,
        Permission.RECORD_READ,
    }),
    # Decides whether a consequential action may proceed. Does not run it.
    Role.APPROVER: frozenset({
        Permission.EXECUTION_APPROVE,
        Permission.EXECUTION_REVOKE,
        Permission.RECORD_READ,
    }),
    # Examines. Changes nothing, so cannot erase what it was meant to examine.
    Role.AUDITOR: frozenset({
        Permission.RECORD_READ,
        Permission.PAYLOAD_READ,
        Permission.EVIDENCE_EXPORT,
    }),
    # Resolves UNKNOWN outcomes against the external system.
    Role.RECONCILER: frozenset({
        Permission.EXECUTION_RECONCILE,
        Permission.RECORD_READ,
    }),
    # Handles erasure and legal holds. Deliberately not an auditor.
    Role.DATA_PROTECTION: frozenset({
        Permission.PAYLOAD_DESTROY,
        Permission.LEGAL_HOLD_MANAGE,
        Permission.RECORD_READ,
    }),
    # Grants roles and edits policy. Notably holds neither approve nor dispatch:
    # administering the system is not the same as using it.
    Role.ADMINISTRATOR: frozenset({
        Permission.POLICY_WRITE,
        Permission.ROLE_GRANT,
        Permission.RECORD_READ,
        Permission.CHECKPOINT_SIGN,
    }),
}


class AccessDenied(PermissionError):
    """Raised when a principal attempts something it does not hold."""

    def __init__(self, actor_id: str, permission: Permission, reason: str = "") -> None:
        detail = f": {reason}" if reason else ""
        super().__init__(f"{actor_id} may not {permission.value}{detail}")
        self.actor_id = actor_id
        self.permission = permission


@dataclass(frozen=True)
class Principal:
    """Someone acting on the system, and what they hold."""

    actor_id: str
    roles: frozenset[Role] = field(default_factory=frozenset)

    @classmethod
    def with_roles(cls, actor_id: str, *roles: Role) -> "Principal":
        return cls(actor_id, frozenset(roles))

    @property
    def permissions(self) -> frozenset[Permission]:
        granted: set[Permission] = set()
        for role in self.roles:
            granted |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(granted)

    def holds(self, permission: Permission) -> bool:
        return permission in self.permissions


class AccessControl:
    """Checks permissions, and the separations that permissions alone miss."""

    def __init__(self, principals: Iterable[Principal] = ()) -> None:
        self._principals = {principal.actor_id: principal for principal in principals}

    def add(self, principal: Principal) -> None:
        self._principals[principal.actor_id] = principal

    def get(self, actor_id: str) -> Principal:
        """An unknown actor holds nothing rather than raising."""
        return self._principals.get(actor_id, Principal(actor_id))

    def require(self, actor_id: str, permission: Permission) -> None:
        if not self.get(actor_id).holds(permission):
            raise AccessDenied(actor_id, permission)

    def require_approval_separation(self, *, approver_id: str, requester_id: str) -> None:
        """Approval by the person who asked for it is not oversight.

        Checked separately from permissions because holding `execution:approve`
        is not the question — the question is whose action is being approved.
        """
        self.require(approver_id, Permission.EXECUTION_APPROVE)
        if approver_id == requester_id:
            raise AccessDenied(
                approver_id, Permission.EXECUTION_APPROVE,
                "an execution cannot be approved by the actor that proposed it",
            )

    def require_audit_independence(self, actor_id: str) -> None:
        """An auditor who can also erase can erase what they were examining."""
        self.require(actor_id, Permission.RECORD_READ)
        principal = self.get(actor_id)
        if principal.holds(Permission.PAYLOAD_DESTROY):
            raise AccessDenied(
                actor_id, Permission.RECORD_READ,
                "auditing and payload destruction may not be held by one actor",
            )

    def describe(self, actor_id: str) -> dict[str, object]:
        """What a record should carry about who acted."""
        principal = self.get(actor_id)
        return {
            "actor_id": actor_id,
            "roles": sorted(role.value for role in principal.roles),
            "permissions": sorted(item.value for item in principal.permissions),
        }
