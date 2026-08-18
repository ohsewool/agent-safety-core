"""The Korean AI Act profile must report limits as loudly as it reports evidence."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ledger import ExecutionLedger, SUCCEEDED, UNKNOWN  # noqa: E402
from profiles.kr_ai_act.evidence import build_package, load_profile  # noqa: E402

SCOPE = "a" * 64


@pytest.fixture
def events(tmp_path):
    ledger = ExecutionLedger(str(tmp_path / "ledger.db"))
    approved = ledger.create(run_id="r", actor_id="agent", tool_id="payments",
                             operation="transfer", scope_digest=SCOPE)
    lease = ledger.approve(approved, approver_id="human-1", scope_digest=SCOPE, ttl_seconds=60)
    ledger.claim_lease(lease, scope_digest=SCOPE)
    ledger.record_outcome(approved, state=SUCCEEDED, evidence={})

    uncertain = ledger.create(run_id="r", actor_id="agent", tool_id="payments",
                              operation="transfer", scope_digest=SCOPE)
    lease2 = ledger.approve(uncertain, approver_id="human-1", scope_digest=SCOPE, ttl_seconds=60)
    ledger.claim_lease(lease2, scope_digest=SCOPE)
    ledger.record_outcome(uncertain, state=UNKNOWN, evidence={"reason": "timeout"})

    collected = ledger.events()
    ledger.close()
    return collected


class TestProfileIntegrity:
    def test_profile_declares_its_source_and_verification_date(self):
        profile = load_profile()
        assert profile["source_url"].startswith("https://www.law.go.kr")
        assert profile["effective_date"] == "2026-01-22"
        assert profile["verified_at"]

    def test_every_obligation_states_what_it_cannot_prove(self):
        for obligation in load_profile()["obligations"]:
            assert obligation["cannot_prove"], obligation["article"]

    def test_article_32_is_marked_as_conditional_not_universal(self):
        article = next(o for o in load_profile()["obligations"] if o["article"] == "제32조")
        assert article["applicability"] == "applicability_check_required"
        assert "10^26" in article["applies_when"]

    def test_penalty_is_scoped_to_the_first_paragraph(self):
        article = next(o for o in load_profile()["obligations"]
                       if o["article"] == "제31조 제1항")
        assert "제43조" in article["penalty_note"]
        assert "제31조 전체가 아니다" in article["penalty_note"]


class TestPackageContent:
    def test_human_oversight_is_directly_supported_by_approval_events(self, events):
        package = build_package(events)
        oversight = next(o for o in package.obligations if o.article == "제34조 제4호")
        assert oversight.support_level == "direct"
        assert oversight.has_evidence

    def test_user_protection_is_reported_as_unsupported(self, events):
        package = build_package(events)
        protection = next(o for o in package.obligations if o.article == "제34조 제3호")
        assert protection.support_level == "not_supported"
        assert not protection.has_evidence
        assert any("지원되지 않음" in item for item in package.to_dict()["human_review_required"])

    def test_unresolved_executions_are_surfaced(self, events):
        package = build_package(events)
        assert len(package.unresolved_executions) == 1
        assert any("미해결" in item for item in package.to_dict()["human_review_required"])

    def test_applicability_check_is_demanded_for_article_32(self, events):
        package = build_package(events)
        assert any("적용 대상 여부" in item for item in package.to_dict()["human_review_required"])

    def test_disclaimer_is_carried_into_every_package(self, events):
        package = build_package(events)
        assert "준수를 보장하지 않는다" in package.to_dict()["disclaimer"]
        assert "준수를 보장하지 않는다" in package.to_markdown()

    def test_markdown_lists_non_runtime_evidence(self, events):
        rendered = build_package(events).to_markdown()
        assert "런타임 외 증거" in rendered
        assert "UI 스크린샷" in rendered

    def test_integrity_block_is_included_when_supplied(self, events):
        package = build_package(events, integrity={"checkpoint_sequence": 3, "chain": "intact"})
        assert package.to_dict()["integrity"]["checkpoint_sequence"] == 3
        assert "증적 무결성" in package.to_markdown()

    def test_empty_runtime_produces_a_package_that_says_so(self):
        package = build_package([])
        review = package.to_dict()["human_review_required"]
        assert any("관찰되지 않음" in item for item in review)
