"""What an approval is bound to (ADR-002 §4).

An approval is only meaningful if it names the exact execution it permits.  The
adversarial review broke three assumptions that a naive binding makes:

F-01  binding on arguments alone lets the *code* change underneath an approval
F-06  binding on a policy **version string** lets the policy content change while
      the string stays ``"v17"``
F-07  binding on a path **string** lets the target change while the string stays
      ``/agent/safe/data.txt`` — replace a symlink and the same text now names a
      different file

So the binding covers the resolved identity of every element, and every element
is recomputed immediately before dispatch and compared with what was approved.

The trade-off named in the review is real: hash too much context and unrelated
environment drift invalidates approvals constantly.  ``ContextSpec`` therefore
takes an explicit allow-list — callers state which context actually changes the
meaning of an execution, and nothing else enters the digest.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlsplit

from .binding import STRICT, ArgumentPolicy, BindingError
from .canonical import CanonicalizationError, digest


class ScopeError(ValueError):
    """Raised when a scope element cannot be resolved to a stable identity."""


@dataclass(frozen=True)
class ResourceIdentity:
    """The resolved identity of what an execution will act on.

    ``requested`` is the string the caller asked for and is kept so the identity
    can be re-derived from the same starting point before dispatch — resolving an
    already-resolved locator would follow the new symlink target and quietly
    agree with the attacker.  ``locator`` is the canonical resolved name, and
    ``fingerprint`` is whatever additionally pins the target (an inode for an
    existing file, its parent's inode for one that does not exist yet).
    """

    kind: str
    requested: str
    locator: str
    fingerprint: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "requested": self.requested,
                "locator": self.locator, "fingerprint": self.fingerprint}


def resolve_path(raw: str) -> ResourceIdentity:
    """Resolve a filesystem path to a canonical, symlink-free identity.

    A path that exists is additionally pinned to its ``(device, inode)``: if the
    directory component is swapped for a symlink or junction after approval, the
    same string resolves to a different inode and the binding no longer matches.
    A path that does not exist yet is pinned to its resolved parent, so the
    creation target cannot be redirected either.

    Residual risk: a filesystem may reuse an inode number immediately after a
    delete, so delete-then-recreate at the same path can produce the same
    fingerprint. Content-addressed pinning would close that gap for small files
    and is deferred; the guarantee here is object identity, not content.
    """
    if not isinstance(raw, str) or not raw:
        raise ScopeError("a path resource requires a non-empty string")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ScopeError("relative paths cannot be bound: their meaning depends on cwd")
    # `..`는 **해석 전** 원시 입력에서 본다. 해석 뒤에 보던 판은 발동할 수 없었다 -
    # `.resolve()`가 `..`를 이미 접어 없애기 때문이다. `/tmp/../etc/passwd`는
    # `/etc/passwd`로 접히고 `parts`에 `..`가 남지 않는다. 메시지는 "traversal을
    # 거부한다"고 말하는데 실제로는 조용히 통과시키고 있었다.
    #
    # 커버리지가 이 줄을 한 번도 실행하지 않았다고 알려줬고, 발동시키려다 알았다.
    # **활성 검사처럼 보이는 죽은 코드**는 없는 검사보다 나쁘다 - 읽는 사람이
    # 보호받고 있다고 믿는다.
    #
    # 형제 저장소 `mcp-gateway`의 정책은 처음부터 원시 요청에서 `..`를 거부한다.
    # 같은 규칙을 두 곳에서 다르게 구현하고 있었던 셈이다.
    if ".." in PurePosixPath(raw).parts:
        raise ScopeError("path escapes through traversal components")
    resolved = candidate.resolve()
    try:
        status = os.stat(resolved)
        fingerprint = f"{status.st_dev}:{status.st_ino}"
    except FileNotFoundError:
        parent = resolved.parent
        try:
            parent_status = os.stat(parent)
        except OSError as error:
            raise ScopeError(f"parent of {resolved} cannot be resolved") from error
        fingerprint = f"parent:{parent_status.st_dev}:{parent_status.st_ino}"
    except OSError as error:
        raise ScopeError(f"{resolved} cannot be resolved") from error
    return ResourceIdentity("path", raw, str(resolved), fingerprint)


def resolve_url(raw: str) -> ResourceIdentity:
    """Resolve a URL to scheme+authority. Redirects are the caller's to police."""
    if not isinstance(raw, str) or not raw:
        raise ScopeError("a url resource requires a non-empty string")
    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        raise ScopeError("a url resource requires a scheme and an authority")
    origin = f"{parts.scheme.lower()}://{parts.netloc.lower()}"
    return ResourceIdentity("url", raw, origin, parts.path or "/")


def resolve_opaque(kind: str, identifier: str) -> ResourceIdentity:
    """For resources with an immutable id (a row key, an account number)."""
    if not identifier:
        raise ScopeError("an opaque resource requires an identifier")
    return ResourceIdentity(kind, identifier, identifier)


@dataclass(frozen=True)
class ContextSpec:
    """The execution context that is allowed to enter the binding.

    Explicit by design: an allow-list keeps unrelated environment drift from
    invalidating approvals, while still covering what changes an execution's
    meaning (which code runs it, as whom, from where).
    """

    fields: tuple[str, ...] = ("code_revision", "tool_version", "execution_identity", "working_directory")

    def digest_of(self, context: Mapping[str, Any]) -> str:
        missing = [name for name in self.fields if name not in context]
        if missing:
            raise ScopeError(f"context is missing bound fields: {', '.join(sorted(missing))}")
        return digest({name: context[name] for name in self.fields})


@dataclass(frozen=True)
class PolicyBinding:
    """Identity *and* content of the policy in force (F-06)."""

    policy_id: str
    version: str
    content_digest: str

    @classmethod
    def from_document(cls, policy_id: str, version: str, document: Any) -> "PolicyBinding":
        return cls(policy_id, version, digest(document))

    def as_dict(self) -> dict[str, str]:
        return {"policy_id": self.policy_id, "version": self.version,
                "content_digest": self.content_digest}


@dataclass(frozen=True)
class ExecutionScope:
    """Everything one approval permits. Any difference is a different execution."""

    run_id: str
    actor_id: str
    tool_id: str
    operation: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    resources: tuple[ResourceIdentity, ...] = ()
    policy: PolicyBinding | None = None
    context: Mapping[str, Any] = field(default_factory=dict)
    context_spec: ContextSpec = ContextSpec()
    argument_policy: ArgumentPolicy = STRICT

    def digest(self) -> str:
        try:
            return digest(
                {
                    "run_id": self.run_id,
                    "actor_id": self.actor_id,
                    "tool_id": self.tool_id,
                    "operation": self.operation,
                    # Digested through the argument policy, which is itself part
                    # of that digest: relaxing a rule after approval would widen
                    # what the approval permits.
                    "arguments": self.argument_policy.digest_of(self.arguments),
                    "resources": [item.as_dict() for item in self.resources],
                    "policy": self.policy.as_dict() if self.policy else None,
                    "context": self.context_spec.digest_of(self.context),
                }
            )
        except (CanonicalizationError, BindingError) as error:
            raise ScopeError(str(error)) from error


def rebind(scope: ExecutionScope, *, resolvers: Mapping[str, Any] | None = None) -> ExecutionScope:
    """Re-resolve the scope's resources against the world as it is *now*.

    Called immediately before dispatch. If a symlink was swapped or a file was
    replaced since approval, the fingerprints differ and the digest changes, so
    the lease cannot be claimed.
    """
    refreshed: list[ResourceIdentity] = []
    for resource in scope.resources:
        if resource.kind == "path":
            refreshed.append(resolve_path(resource.requested))
        elif resource.kind == "url":
            refreshed.append(resolve_url(resource.requested))
        else:
            refreshed.append(resource)
    return ExecutionScope(
        run_id=scope.run_id, actor_id=scope.actor_id, tool_id=scope.tool_id,
        operation=scope.operation, arguments=scope.arguments,
        resources=tuple(refreshed), policy=scope.policy,
        context=scope.context, context_spec=scope.context_spec,
        argument_policy=scope.argument_policy,
    )
