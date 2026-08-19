"""What a witness has to be, and what it deliberately is not.

A checkpoint is signed, so nobody can forge one. Signing does not stop the host
replaying an older checkpoint that was also validly signed, and it does not stop
two divergent histories each carrying real signatures. What separates the true
history from a rewritten one is a monotonic counter kept somewhere the host
cannot reach.

So the witness has exactly one security-relevant property:

    the highest sequence it reports for a log never goes down.

Everything else - storage format, transport, who runs it - is deployment.

**Why this module does not choose a vendor.** The obvious next step was to pick
a transparency log or an object store and write an adapter for it. That would
make the project's central guarantee depend on one company's terms and one
service's availability, for a property so simple that any append-only store
provides it. Worse, it would read as though the guarantee came from the vendor,
when it comes from the counter being outside the host's control - a claim about
topology, not about a product.

What this module ships instead is the contract, an implementation for each end
of the range it is honest about, and a conformance suite. Someone deploying this
brings whatever they already trust and runs `assert_conforms` against it. If it
passes, it is a witness; if it does not, no vendor name makes it one.

    FileWitness   local file. Convenient, and NOT a witness under the threat
                  model - it lives on the machine being audited. Named so that
                  choosing it is a visible decision rather than a default.
    HttpWitness   any endpoint honouring a four-line contract. This is the shape
                  a real deployment takes, and it needs no particular provider.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


class WitnessError(RuntimeError):
    """Raised when a witness refuses a publication or cannot be reached."""


@runtime_checkable
class WitnessPort(Protocol):
    """The whole interface. Three methods, one invariant."""

    def publish(self, log_id: str, sequence: int, digest: str) -> None:
        """Record a checkpoint. Must refuse a sequence at or below the latest."""

    def latest_sequence(self, log_id: str) -> int | None:
        """The highest sequence recorded, or None if this log is unknown."""

    def digest_at(self, log_id: str, sequence: int) -> str | None:
        """The digest recorded at that sequence, or None."""


@dataclass
class FileWitness:
    """A witness in a local file.

    Deliberately named for what it is. Under the threat model this does not
    witness anything: an attacker who can rewrite the journal can rewrite this
    too, because both sit on the machine being audited. It exists for tests and
    for local development, and the name is meant to make reaching for it in
    production feel like the decision it is.
    """

    path: Path
    _entries: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if self.path.exists():
            self._entries = [
                json.loads(line)
                for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

    def publish(self, log_id: str, sequence: int, digest: str) -> None:
        latest = self.latest_sequence(log_id)
        if latest is not None and sequence <= latest:
            raise WitnessError(
                f"witness refuses a non-advancing sequence: {sequence} after {latest}"
            )
        entry = {"log_id": log_id, "sequence": sequence, "checkpoint_digest": digest}
        self._entries.append(entry)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def latest_sequence(self, log_id: str) -> int | None:
        sequences = [item["sequence"] for item in self._entries if item["log_id"] == log_id]
        return max(sequences) if sequences else None

    def digest_at(self, log_id: str, sequence: int) -> str | None:
        for item in self._entries:
            if item["log_id"] == log_id and item["sequence"] == sequence:
                return item["checkpoint_digest"]
        return None


@dataclass
class HttpWitness:
    """A witness reachable over HTTP, wherever it happens to run.

    The contract is four lines, so it can be satisfied by a transparency log, an
    object store with versioning behind a small handler, or a service another
    team already operates:

        POST {base}/logs/{log_id}   {"sequence": N, "digest": "..."}
            201 on success, 409 when N is not above the latest.
        GET  {base}/logs/{log_id}/latest
            200 {"sequence": N} or 404 when the log is unknown.
        GET  {base}/logs/{log_id}/{sequence}
            200 {"digest": "..."} or 404.

    Refusing a non-advancing sequence is the server's job, not this client's.
    Enforcing it here would place the invariant on the machine being audited,
    which is the arrangement the whole mechanism exists to avoid - and a client
    check would then be a comfort rather than a control.
    """

    base_url: str
    timeout: float = 10.0
    opener: Any = None          # injectable for tests; urllib by default

    def _request(self, method: str, path: str, body: dict | None = None):
        import urllib.error
        import urllib.request

        url = f"{self.base_url.rstrip('/')}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url, data=data, method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        opener = self.opener or urllib.request.urlopen
        try:
            with opener(request, timeout=self.timeout) as response:
                payload = response.read()
                return response.status, (json.loads(payload) if payload else None)
        except urllib.error.HTTPError as error:
            return error.code, None
        except Exception as error:                      # network, DNS, TLS
            # A witness that cannot be reached has not said the sequence is
            # fine. Treating unreachable as "no objection" would make the check
            # disappear exactly when the host is in trouble.
            raise WitnessError(f"witness unreachable at {url}: {error}") from error

    def publish(self, log_id: str, sequence: int, digest: str) -> None:
        status, _ = self._request(
            "POST", f"/logs/{log_id}", {"sequence": sequence, "digest": digest})
        if status == 409:
            raise WitnessError(
                f"witness refuses a non-advancing sequence: {sequence}")
        if status not in (200, 201):
            raise WitnessError(f"witness rejected the publication: HTTP {status}")

    def latest_sequence(self, log_id: str) -> int | None:
        status, payload = self._request("GET", f"/logs/{log_id}/latest")
        if status == 404:
            return None
        if status != 200 or not isinstance(payload, dict):
            raise WitnessError(f"witness returned HTTP {status} for latest sequence")
        return int(payload["sequence"])

    def digest_at(self, log_id: str, sequence: int) -> str | None:
        status, payload = self._request("GET", f"/logs/{log_id}/{sequence}")
        if status == 404:
            return None
        if status != 200 or not isinstance(payload, dict):
            raise WitnessError(f"witness returned HTTP {status} for a digest")
        return str(payload["digest"])


def assert_conforms(witness: WitnessPort, *, log_id: str = "conformance") -> None:
    """Check an implementation against the contract. Raises on the first failure.

    Written to be run against whatever a deployment actually brings, because
    "we use a transparency log" is a claim about a product and this is a check
    on behaviour. It exercises the one property that matters and the three that
    make it usable.

    Mutates the log it is given, so it should be pointed at a scratch log id.
    """
    start = witness.latest_sequence(log_id)
    base = 0 if start is None else start

    witness.publish(log_id, base + 1, "digest-one")
    if witness.latest_sequence(log_id) != base + 1:
        raise WitnessError("latest_sequence did not reflect a publication")
    if witness.digest_at(log_id, base + 1) != "digest-one":
        raise WitnessError("digest_at did not return the published digest")

    for repeated in (base + 1, base):
        try:
            witness.publish(log_id, repeated, "should-not-be-recorded")
        except WitnessError:
            pass
        else:
            raise WitnessError(
                f"witness accepted sequence {repeated} after {base + 1}; "
                "a counter that can go backwards witnesses nothing"
            )

    witness.publish(log_id, base + 2, "digest-two")
    if witness.latest_sequence(log_id) != base + 2:
        raise WitnessError("latest_sequence did not advance")
    if witness.digest_at(log_id, base + 1) != "digest-one":
        raise WitnessError("an earlier digest changed after a later publication")
    if witness.digest_at(log_id, base + 99) is not None:
        raise WitnessError("digest_at invented a record that was never published")
    if witness.latest_sequence(f"{log_id}-never-used") is not None:
        raise WitnessError("latest_sequence answered for a log it has never seen")
