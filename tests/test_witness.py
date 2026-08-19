"""The witness contract, and a conformance suite that can actually fail.

A checkpoint's signature stops forgery. It does not stop the host replaying an
older checkpoint that was also validly signed. The only thing that separates a
true history from a rewritten one is a counter the host cannot reach, and the
only property that counter needs is that it never goes down.

`assert_conforms` exists so a deployment can check whatever it brings against
that property. These tests check `assert_conforms` itself - a conformance suite
that passes everything certifies nothing, so most of what follows is broken
witnesses that it has to reject.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.witness import (
    FileWitness,
    HttpWitness,
    WitnessError,
    WitnessPort,
    assert_conforms,
)


class TestFileWitness:
    def test_it_conforms(self, tmp_path):
        assert_conforms(FileWitness(tmp_path / "w.jsonl"))

    def test_it_refuses_to_go_backwards(self, tmp_path):
        witness = FileWitness(tmp_path / "w.jsonl")
        witness.publish("log", 5, "digest-five")
        with pytest.raises(WitnessError):
            witness.publish("log", 4, "rewritten")
        with pytest.raises(WitnessError):
            witness.publish("log", 5, "replaced")

    def test_logs_are_independent(self, tmp_path):
        witness = FileWitness(tmp_path / "w.jsonl")
        witness.publish("first", 9, "a")
        witness.publish("second", 1, "b")
        assert witness.latest_sequence("second") == 1

    def test_it_survives_reopening(self, tmp_path):
        path = tmp_path / "w.jsonl"
        FileWitness(path).publish("log", 3, "digest-three")
        assert FileWitness(path).latest_sequence("log") == 3

    def test_it_satisfies_the_port(self, tmp_path):
        assert isinstance(FileWitness(tmp_path / "w.jsonl"), WitnessPort)


class TestTheConformanceSuiteRejectsBrokenWitnesses:
    """The suite has to be able to fail, or passing it means nothing."""

    def test_a_witness_that_accepts_a_repeat_is_rejected(self):
        class Permissive:
            def __init__(self):
                self.records = {}

            def publish(self, log_id, sequence, digest):
                self.records[(log_id, sequence)] = digest   # no monotonicity

            def latest_sequence(self, log_id):
                found = [s for (l, s) in self.records if l == log_id]
                return max(found) if found else None

            def digest_at(self, log_id, sequence):
                return self.records.get((log_id, sequence))

        with pytest.raises(WitnessError, match="witnesses nothing"):
            assert_conforms(Permissive())

    def test_a_witness_that_forgets_what_it_recorded_is_rejected(self):
        class Amnesiac:
            def publish(self, log_id, sequence, digest):
                pass

            def latest_sequence(self, log_id):
                return None

            def digest_at(self, log_id, sequence):
                return None

        with pytest.raises(WitnessError, match="did not reflect a publication"):
            assert_conforms(Amnesiac())

    def test_a_witness_that_rewrites_history_is_rejected(self):
        """Accepting a later sequence is not enough if earlier ones can move."""

        class Rewriter(FileWitness):
            def digest_at(self, log_id, sequence):
                latest = self.latest_sequence(log_id)
                return super().digest_at(log_id, latest) if latest else None

        with pytest.raises(WitnessError, match="earlier digest changed"):
            assert_conforms(Rewriter(Path("/tmp/rewriter-witness.jsonl")))

    def test_a_witness_that_invents_records_is_rejected(self):
        class Inventor(FileWitness):
            def digest_at(self, log_id, sequence):
                return super().digest_at(log_id, sequence) or "made-up"

        with pytest.raises(WitnessError, match="invented a record"):
            assert_conforms(Inventor(Path("/tmp/inventor-witness.jsonl")))

    def test_a_witness_that_answers_for_unknown_logs_is_rejected(self):
        class Confident(FileWitness):
            def latest_sequence(self, log_id):
                return super().latest_sequence(log_id) or 0

        with pytest.raises(WitnessError, match="never seen"):
            assert_conforms(Confident(Path("/tmp/confident-witness.jsonl")))


class FakeHttp:
    """A minimal server honouring the documented contract, in-process."""

    def __init__(self, *, enforce_monotonic=True):
        self.records: dict[str, dict[int, str]] = {}
        self.enforce_monotonic = enforce_monotonic

    def __call__(self, request, timeout=None):
        import urllib.error

        path = request.full_url.split("://", 1)[1].split("/", 1)[1]
        parts = path.strip("/").split("/")
        log_id = parts[1] if len(parts) > 1 else ""

        if request.get_method() == "POST":
            body = json.loads(request.data.decode())
            log = self.records.setdefault(log_id, {})
            if self.enforce_monotonic and log and body["sequence"] <= max(log):
                raise urllib.error.HTTPError(request.full_url, 409, "conflict", {}, None)
            log[body["sequence"]] = body["digest"]
            return _Response(201, {})

        log = self.records.get(log_id, {})
        if parts[-1] == "latest":
            if not log:
                raise urllib.error.HTTPError(request.full_url, 404, "unknown", {}, None)
            return _Response(200, {"sequence": max(log)})

        digest = log.get(int(parts[-1]))
        if digest is None:
            raise urllib.error.HTTPError(request.full_url, 404, "unknown", {}, None)
        return _Response(200, {"digest": digest})


class _Response:
    def __init__(self, status, payload):
        self.status = status
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestHttpWitness:
    def test_it_conforms_against_a_server_that_honours_the_contract(self):
        assert_conforms(HttpWitness("http://witness.invalid", opener=FakeHttp()))

    def test_a_server_that_does_not_enforce_monotonicity_fails_conformance(self):
        """The invariant is the server's to keep, so this is what catches a
        deployment that pointed at an ordinary key-value store."""
        loose = HttpWitness("http://witness.invalid", opener=FakeHttp(enforce_monotonic=False))
        with pytest.raises(WitnessError, match="witnesses nothing"):
            assert_conforms(loose)

    def test_an_unknown_log_reads_as_unknown(self):
        witness = HttpWitness("http://witness.invalid", opener=FakeHttp())
        assert witness.latest_sequence("never-published") is None

    def test_an_unreachable_witness_raises_rather_than_agreeing(self):
        """Silence is not consent.

        If an unreachable witness read as "no objection", the check would
        disappear at exactly the moment the host is having trouble - which is
        when it is most needed.
        """
        def refuse(request, timeout=None):
            raise OSError("connection refused")

        witness = HttpWitness("http://witness.invalid", opener=refuse)
        with pytest.raises(WitnessError, match="unreachable"):
            witness.latest_sequence("log")

    def test_it_does_not_enforce_monotonicity_client_side(self):
        """Deliberate: a client-side check runs on the audited machine.

        Enforcing it here would look like the invariant was being kept while
        placing it exactly where an attacker already stands.
        """
        witness = HttpWitness("http://witness.invalid", opener=FakeHttp(enforce_monotonic=False))
        witness.publish("log", 5, "five")
        witness.publish("log", 5, "five-again")     # the server allowed it
        assert witness.latest_sequence("log") == 5

    def test_it_satisfies_the_port(self):
        assert isinstance(HttpWitness("http://witness.invalid"), WitnessPort)
