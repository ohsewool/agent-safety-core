"""Map runtime events to what a Korean AI Framework Act obligation asks for.

This is a *profile*, not a compliance tool. It answers one narrow question — "of
the things this law asks an operator to show, which ones did the runtime
actually observe?" — and is equally explicit about what it cannot answer.

The distinction that keeps this honest is the support level:

direct
    the runtime observed the thing the obligation asks about (an approval
    happened, a document exists and is intact)

indirect
    the runtime observed something adjacent that supports the claim without
    establishing it (a notice was rendered; whether a person read it is not
    observable)

not_supported
    the obligation is about organisational arrangements the runtime cannot see

applicability_check_required
    the obligation may not apply at all, and deciding that is not the runtime's
    call (Article 32 applies only above a compute threshold, among other things)

Every generated package repeats the disclaimer and lists the non-runtime
evidence that a reviewer still has to supply. A package that looked like a
compliance certificate would be worse than no package.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

PROFILE_PATH = Path(__file__).with_name("profile.json")

SUPPORT_ORDER = ("direct", "indirect", "conditional", "not_supported")


@dataclass(frozen=True)
class ObligationEvidence:
    """What the runtime can and cannot show for one obligation."""

    article: str
    title: str
    applicability: str
    support_level: str
    matched_events: tuple[dict[str, Any], ...]
    provides: str
    cannot_prove: str
    non_runtime_evidence: tuple[str, ...]
    note: str = ""

    @property
    def has_evidence(self) -> bool:
        return bool(self.matched_events)


@dataclass
class EvidencePackage:
    """A reviewable bundle: what was observed, and what still needs a human."""

    profile_id: str
    profile_version: str
    law_name: str
    effective_date: str
    verified_at: str
    disclaimer: str
    obligations: list[ObligationEvidence] = field(default_factory=list)
    unresolved_executions: list[str] = field(default_factory=list)
    integrity: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "law_name": self.law_name,
            "effective_date": self.effective_date,
            "verified_at": self.verified_at,
            "disclaimer": self.disclaimer,
            "obligations": [
                {
                    "article": item.article,
                    "title": item.title,
                    "applicability": item.applicability,
                    "support_level": item.support_level,
                    "runtime_evidence_count": len(item.matched_events),
                    "provides": item.provides,
                    "cannot_prove": item.cannot_prove,
                    "non_runtime_evidence_required": list(item.non_runtime_evidence),
                    **({"note": item.note} if item.note else {}),
                }
                for item in self.obligations
            ],
            "unresolved_executions": self.unresolved_executions,
            "integrity": self.integrity,
            "human_review_required": self._review_items(),
        }

    def _review_items(self) -> list[str]:
        items: list[str] = []
        for obligation in self.obligations:
            if obligation.applicability == "applicability_check_required":
                items.append(f"{obligation.article}: 적용 대상 여부 확인 필요")
            if obligation.support_level == "not_supported":
                items.append(f"{obligation.article}: 런타임 증적으로 지원되지 않음 — 별도 자료 필요")
            elif not obligation.has_evidence:
                items.append(f"{obligation.article}: 해당 런타임 이벤트가 관찰되지 않음")
        if self.unresolved_executions:
            items.append(
                f"{len(self.unresolved_executions)}건의 실행이 미해결 상태 — 결과 확인 필요"
            )
        return items

    def to_markdown(self) -> str:
        lines = [
            f"# 실행 증적 패키지 — {self.law_name}",
            "",
            f"- 프로파일: `{self.profile_id}` v{self.profile_version}",
            f"- 법 시행일: {self.effective_date} / 프로파일 검증일: {self.verified_at}",
            "",
            f"> {self.disclaimer}",
            "",
            "## 의무별 런타임 증적",
            "",
            "| 조항 | 지원 수준 | 관찰된 이벤트 | 런타임으로 증명 불가 |",
            "|---|---|---|---|",
        ]
        for item in self.obligations:
            lines.append(
                f"| {item.article} {item.title} | {item.support_level} | "
                f"{len(item.matched_events)} | {item.cannot_prove} |"
            )
        lines += ["", "## 사람 검토가 필요한 항목", ""]
        review = self._review_items()
        lines.extend(f"- {entry}" for entry in review) if review else lines.append("- 없음")
        lines += ["", "## 런타임 외 증거 (별도 확보 필요)", ""]
        seen: set[str] = set()
        for item in self.obligations:
            for evidence in item.non_runtime_evidence:
                if evidence not in seen:
                    seen.add(evidence)
                    lines.append(f"- {evidence}")
        if self.integrity:
            lines += ["", "## 증적 무결성", ""]
            for key, value in self.integrity.items():
                lines.append(f"- {key}: {value}")
        return "\n".join(lines)


def load_profile(path: Path | str = PROFILE_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_package(events: Iterable[Mapping[str, Any]], *,
                  profile: Mapping[str, Any] | None = None,
                  integrity: Mapping[str, Any] | None = None) -> EvidencePackage:
    """Match ledger events against the profile's obligations."""
    profile = profile or load_profile()
    materialised = [dict(event) for event in events]
    kinds = Counter(event.get("kind") for event in materialised)

    package = EvidencePackage(
        profile_id=profile["profile_id"],
        profile_version=profile["profile_version"],
        law_name=profile["law_name"],
        effective_date=profile["effective_date"],
        verified_at=profile["verified_at"],
        disclaimer=profile["disclaimer"],
        integrity=dict(integrity or {}),
    )

    for obligation in profile["obligations"]:
        wanted = obligation["runtime_events"]
        if wanted == ["*"]:
            matched = tuple(materialised)
        else:
            matched = tuple(
                event for event in materialised if event.get("kind") in set(wanted)
            )
        package.obligations.append(
            ObligationEvidence(
                article=obligation["article"],
                title=obligation["title"],
                applicability=obligation["applicability"],
                support_level=obligation["support_level"],
                matched_events=matched,
                provides=obligation["provides"],
                cannot_prove=obligation["cannot_prove"],
                non_runtime_evidence=tuple(obligation["non_runtime_evidence"]),
                note=obligation.get("note", ""),
            )
        )

    package.unresolved_executions = [
        event["execution_id"] for event in materialised
        if event.get("to_state") in {"UNKNOWN", "PERMANENTLY_UNRESOLVED"}
    ]
    _ = kinds  # counted for future per-kind reporting
    return package
