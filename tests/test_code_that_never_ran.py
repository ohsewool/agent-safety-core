"""스위트가 한 번도 실행하지 않던 줄들.

거부 감사는 `raise`만 봤다. 2026-08-22에 질문을 넓혔다 — **한 번도 실행되지 않는 줄이
무엇인가.** 네 저장소에서 81줄이 나왔고 여기가 21줄이었다(전체 1,182줄 중 98%).

무엇이 빠져 있었는지가 요점이다.

**`HttpWitness`의 오류 응답 처리 셋.** `FileWitness`는 자기 독스트링이 "이건 아무것도
증언하지 않는다"고 적어둔 물건이고, 실제로 쓰이는 것은 HTTP 쪽이다. 그런데 witness가
409·5xx·이상한 본문을 돌려줬을 때의 처리가 한 번도 돌지 않았다. **감사받는 기계 밖에
두려고 만든 장치의 실패 처리가 검사 밖에 있었다.**

**`FreshnessReport.verdict`의 두 갈래와 `summary()`의 OK 갈래.** 이 저장소는 "실패
차원을 각각 이름 붙여 보고한다"고 말한다. 그 이름을 만드는 코드가 일부 돌지 않았다.

**`refresh_scope`의 url 갈래.** 승인 직후 재해석해서 그 사이 바뀐 것을 잡는 장치인데,
path만 재해석돼 왔고 url은 한 번도 그 경로를 지나지 않았다.

**`reconcile`의 잘못된 목표 상태 거부.** 화해로 갈 수 있는 상태는 셋뿐인데, 넷째를
넣었을 때 막히는지 확인된 적이 없었다.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.checkpoint import FreshnessReport
from core.ledger import ExecutionLedger, LedgerError
from core.scope import ExecutionScope, ResourceIdentity, rebind
from core.witness import HttpWitness, WitnessError


class _Response:
    """`urlopen`이 돌려주는 것 흉내. 컨텍스트 매니저이고 `.status`와 본문을 준다."""

    def __init__(self, status, payload):
        self.status = status
        self._payload = b"" if payload is None else json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_returning(status, payload=None):
    def opener(request, timeout=None):
        return _Response(status, payload)
    return opener


class TestTheHttpWitnessReportsWhatWentWrong:
    """이 저장소가 실제로 쓰라고 만든 witness다. `FileWitness`는 자기 독스트링에
    "감사받는 기계 위에 있으므로 아무것도 증언하지 않는다"고 적혀 있다."""

    def test_a_refused_sequence_is_named_as_such(self):
        """409는 "그 번호는 최신보다 위가 아니다"이고, **그 판단은 서버의 몫**이다.
        클라이언트가 대신 판단하면 불변식이 감사받는 기계로 돌아온다."""
        witness = HttpWitness("http://witness.invalid", opener=opener_returning(409))
        with pytest.raises(WitnessError, match="refuses a non-advancing sequence"):
            witness.publish("log", 5, "digest")

    def test_any_other_failed_publication_says_the_status(self):
        witness = HttpWitness("http://witness.invalid", opener=opener_returning(503))
        with pytest.raises(WitnessError, match="rejected the publication: HTTP 503"):
            witness.publish("log", 5, "digest")

    def test_a_successful_publication_is_silent(self):
        """거부만 확인하면 전부 거부하는 구현도 통과한다."""
        witness = HttpWitness("http://witness.invalid", opener=opener_returning(201))
        assert witness.publish("log", 5, "digest") is None

    def test_a_bad_status_on_latest_sequence_is_refused(self):
        witness = HttpWitness("http://witness.invalid", opener=opener_returning(500))
        with pytest.raises(WitnessError, match="HTTP 500 for latest sequence"):
            witness.latest_sequence("log")

    def test_a_body_that_is_not_an_object_is_refused(self):
        """200인데 본문이 리스트다. **도달했다는 것과 답을 받았다는 것은 다르다** —
        여기서 통과시키면 다음 줄의 `payload["sequence"]`가 KeyError를 내고, 그것은
        witness의 문제가 아니라 파이썬의 문제처럼 보인다."""
        witness = HttpWitness("http://witness.invalid", opener=opener_returning(200, []))
        with pytest.raises(WitnessError, match="HTTP 200 for latest sequence"):
            witness.latest_sequence("log")

    def test_an_unknown_log_is_not_an_error(self):
        witness = HttpWitness("http://witness.invalid", opener=opener_returning(404))
        assert witness.latest_sequence("log") is None
        assert witness.digest_at("log", 1) is None

    def test_a_bad_status_on_a_digest_is_refused(self):
        witness = HttpWitness("http://witness.invalid", opener=opener_returning(502))
        with pytest.raises(WitnessError, match="HTTP 502 for a digest"):
            witness.digest_at("log", 1)

    def test_a_good_digest_comes_back(self):
        witness = HttpWitness("http://witness.invalid",
                              opener=opener_returning(200, {"digest": "abc"}))
        assert witness.digest_at("log", 1) == "abc"


def report(**overrides) -> FreshnessReport:
    fields = dict(signature_valid=True, chain_intact=True, tip_matches=True,
                  sequence_current=True, presented_sequence=4, witness_sequence=4,
                  notes=())
    fields.update(overrides)
    return FreshnessReport(**fields)


class TestTheVerdictNamesTheFailure:
    """"실패 차원을 각각 이름 붙여 보고한다"가 이 저장소의 문장이다. 이름이
    없으면 읽는 사람은 산문에서 값을 되찾아야 하고, 이 프로젝트는 그 되찾기를
    이미 두 번 고쳤다."""

    @pytest.mark.parametrize("overrides,expected", [
        ({"signature_valid": False}, "signature_invalid"),
        ({"chain_intact": False}, "chain_broken"),
        ({"tip_matches": False}, "tip_mismatch"),
        ({"witness_sequence": None}, "not_witnessed"),
        ({"presented_sequence": 3, "witness_sequence": 4}, "rollback"),
        ({"presented_sequence": 5, "witness_sequence": 4}, "ahead_of_witness"),
        ({}, "current"),
    ])
    def test_each_failure_has_its_own_name(self, overrides, expected):
        assert report(**overrides).verdict == expected

    def test_the_order_puts_the_artefact_first(self):
        """서명이 깨졌으면 witness가 무슨 말을 하든 그 아티팩트는 못 믿는다.
        순서가 뒤집히면 읽는 사람이 덜 급한 것을 먼저 본다."""
        both_wrong = report(signature_valid=False, witness_sequence=None)
        assert both_wrong.verdict == "signature_invalid"

    def test_a_good_report_summarises_as_ok(self):
        assert report().summary().startswith("OK — checkpoint 4 is signed, current")

    def test_a_bad_report_leads_with_the_verdict(self):
        summary = report(chain_intact=False, notes=("journal line 3",)).summary()
        assert summary.startswith("FAILED [chain_broken] — ")
        assert "journal line 3" in summary


class TestRefreshingAScopeTouchesEveryKind:
    """`rebind`는 승인과 dispatch 사이에 세상이 바뀌었는지 다시 본다. path만 재해석되고
    url은 그대로 지나갔다면, **url 자원에 대해서는 이 장치가 없는 것과 같다.**"""

    def scope_with(self, *resources):
        return ExecutionScope(
            run_id="r1", actor_id="agent:a", tool_id="t1", operation="call",
            arguments={"x": 1}, resources=tuple(resources))

    def test_a_url_resource_is_re_resolved(self):
        stale = ResourceIdentity(kind="url", requested="https://example.test/a",
                                 locator="https://elsewhere.invalid",
                                 fingerprint="stale-fingerprint")
        refreshed = rebind(self.scope_with(stale)).resources[0]
        assert refreshed.requested == "https://example.test/a"
        assert refreshed.fingerprint != "stale-fingerprint"

    def test_an_unknown_kind_is_carried_through_unchanged(self):
        """모르는 종류를 재해석하려 들면 예외가 나고, 그러면 승인 자체가 못 돈다.
        그대로 넘기는 것이 맞고, **그 갈래도 한 번은 지나가 봐야 한다.**"""
        other = ResourceIdentity(kind="opaque", requested="thing",
                                 locator="thing", fingerprint="f")
        assert rebind(self.scope_with(other)).resources[0] is other

    def test_a_path_resource_still_works(self, tmp_path):
        target = tmp_path / "f.txt"
        target.write_text("x", encoding="utf-8")
        original = ResourceIdentity(kind="path", requested=str(target),
                                    locator=str(target), fingerprint="stale")
        refreshed = rebind(self.scope_with(original)).resources[0]
        assert refreshed.fingerprint != "stale"


class TestReconciliationTargets:
    def test_a_state_that_is_not_a_resolution_is_refused(self, tmp_path):
        """화해가 갈 수 있는 곳은 셋뿐이다. `UNKNOWN`으로 "화해"하면 미상이
        미상으로 종결된 것처럼 기록에 남는다."""
        ledger = ExecutionLedger(str(tmp_path / "l.db"))
        try:
            with pytest.raises(LedgerError, match="illegal reconciliation target"):
                ledger.reconcile("any", new_state="UNKNOWN",
                                 reconciler_id="human:ops", evidence={})
        finally:
            ledger.close()

    def test_an_unknown_lease_cannot_be_claimed(self, tmp_path):
        """없는 lease는 거부가 아니라 `None`이다 — 부를 자격이 없다는 뜻이 아니라
        가져갈 것이 없다는 뜻이고, 호출자는 둘을 다르게 다룬다."""
        ledger = ExecutionLedger(str(tmp_path / "l.db"))
        try:
            assert ledger.claim_lease("no-such-lease", scope_digest="d") is None
        finally:
            ledger.close()


class TestTheRemainingFive:
    """작지만 각각 무언가를 말한다."""

    def test_a_path_whose_parent_is_gone_is_refused(self, tmp_path):
        """아직 없는 파일은 **부모의 신원**으로 지문을 만든다 — 승인 뒤에 만들어질
        산출물이 그렇다. 부모마저 없으면 지문을 만들 근거가 없고, 조용히 넘어가면
        존재하지 않는 자리에 승인이 묶인다."""
        from core.scope import ScopeError, resolve_path

        missing = tmp_path / "no-such-dir" / "output.txt"
        with pytest.raises(ScopeError, match="parent of .* cannot be resolved"):
            resolve_path(str(missing))

    def test_a_file_that_does_not_exist_yet_binds_to_its_parent(self, tmp_path):
        """거부만 확인하면 전부 거부하는 구현도 통과한다."""
        from core.scope import resolve_path

        identity = resolve_path(str(tmp_path / "output.txt"))
        assert identity.fingerprint.startswith("parent:")

    def test_the_compatibility_witness_accepts_the_three_field_form(self, tmp_path):
        """`Witness`는 `Checkpoint` 하나도 받고 (log_id, sequence, digest) 셋도 받는다.
        포트가 아는 것은 셋뿐이고, 그 갈래가 한 번도 지나가지 않았다."""
        from core.checkpoint import Witness

        witness = Witness(tmp_path / "w.jsonl")
        witness.publish("log", 1, "digest-one")
        assert witness.latest_sequence("log") == 1
        assert witness.digest_at("log", 1) == "digest-one"

    def test_a_blank_line_in_an_export_is_skipped_not_counted(self, tmp_path):
        """빈 줄은 기록이 아니다. 세어버리면 "N건 내보냈다"가 파일의 줄 수가 된다."""
        from core.export import verify_export

        source = tmp_path / "export.jsonl"
        source.write_text("\n\n", encoding="utf-8")
        assert verify_export(source).records == 0

    def test_reconciling_a_truncated_export_stops_at_the_broken_line(self, tmp_path):
        """마지막 줄이 쓰다 만 JSON이면 거기서 멈춘다 — 그 뒤를 읽으면 없는 기록을
        읽는 것이고, `verify_export`가 이미 그 줄을 위반으로 적어뒀다.

        이 갈래가 안 돌았다는 것은 **잘린 export를 원장과 대조해본 적이 없다**는
        뜻이다. 잘림은 이 저장소가 이름 붙여 다루는 실패 차원 중 하나다."""
        from core.export import reconcile_with_ledger, verify_export

        source = tmp_path / "export.jsonl"
        source.write_text('{"a": 1}\n{"b": 2', encoding="utf-8")
        assert not verify_export(source).ok

        class EmptyLedger:
            def events(self, *args, **kwargs):
                return []
            def read_events(self, *args, **kwargs):
                return []

        report = reconcile_with_ledger(source, EmptyLedger())
        assert not report.ok

    def test_a_path_the_operating_system_refuses_to_stat_is_refused(self):
        """`FileNotFoundError`가 아닌 `OSError`. 이름이 너무 긴 경로가 그렇다 —
        **없는 것과 물어볼 수 없는 것은 다르다.** 없으면 부모에 묶고, 물어볼 수
        없으면 지문을 만들 근거가 아예 없다."""
        from core.scope import ScopeError, resolve_path

        with pytest.raises(ScopeError, match="cannot be resolved"):
            resolve_path("/tmp/" + "x" * 300)

    def test_a_secret_inside_a_list_is_still_redacted(self):
        """`walk`의 리스트 갈래. 비밀이 리스트 안에 들어 있으면 지나쳐 버리는지가
        이 갈래에 걸려 있었고, 한 번도 지나가지 않았다."""
        from core.payload import redact

        cleaned, removed = redact({"items": [{"token": "s3cret", "id": 1}]},
                                  secret_keys={"token"})
        assert cleaned["items"][0]["token"] == "[redacted]"
        assert cleaned["items"][0]["id"] == 1
        assert removed
