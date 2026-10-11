"""Live TLS probe: recorded ``openssl s_client -msg`` transcripts, mocked processes, no network."""

import json
import random
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from quantumtrace import cli, pipeline
from quantumtrace.models import Finding, KindHint, ScanError, SourceType, Tier
from quantumtrace.output.cyclonedx import build_cbom, validate_cbom
from quantumtrace.scanners.network import probe

FIXTURES = Path(__file__).parent / "fixtures" / "probe"


def transcript(name: str) -> str:
    return (FIXTURES / f"{name}.txt").read_text()


def findings_of(name: str, target: str = "localhost:443", attempt: str = "default"):
    return probe.attempt_findings(probe.parse_target(target), probe.parse_attempt(attempt, transcript(name)))


def by_detector(items):
    return {item.detector: item for item in items if isinstance(item, Finding)}


@pytest.mark.parametrize(
    "text,expected",
    [
        ("example.org:443", ("example.org", 443, "example.org:443", "example.org")),
        ("Example.ORG.:8443", ("example.org", 8443, "example.org:8443", "example.org")),
        ("192.0.2.1:443", ("192.0.2.1", 443, "192.0.2.1:443", None)),
        ("[2001:db8::0001]:443", ("2001:db8::1", 443, "[2001:db8::1]:443", None)),
    ],
)
def test_valid_targets_are_canonical(text, expected):
    target = probe.parse_target(text)
    assert (target.host, target.port, target.text, target.sni) == expected


@pytest.mark.parametrize(
    "text",
    [
        "https://example.org:443",
        "10.0.0.0/24:443",
        "example.org",
        "example.org:0",
        "example.org:65536",
        "example.org:https",
        "2001:db8::1:443",
        "[2001:db8::1]",
        "[not-ip]:443",
        "bad_host!:443",
        "-bad.example:443",
        "999.1.1.1:443",
        ":443",
    ],
)
def test_invalid_targets_are_rejected(text):
    with pytest.raises(ValueError):
        probe.parse_target(text)


def test_tls13_hybrid_with_rsa_certificate():
    items = findings_of("tls13_hybrid_rsa")
    assert all(isinstance(item, Finding) for item in items)
    found = by_detector(items)
    assert found["live.tls.group"].raw_name == "0x11EC"
    assert found["live.tls.group"].extra["iana_name"] == "X25519MLKEM768"
    assert found["live.tls.cipher_suite"].raw_name == "0x1302"
    assert found["live.tls.signature_scheme"].raw_name == "0x0804"
    assert found["live.tls.signature_scheme"].extra["message"] == "CertificateVerify"
    cert = found["live.tls.certificate"]
    assert (cert.raw_name, cert.key_size, cert.kind_hint) == ("RSA", 2048, KindHint.CERTIFICATE)
    version = found["live.tls.version"]
    assert version.raw_name == "TLS 1.3"
    assert version.extra["authentication_observable"] is True
    assert version.extra["certificate_state"] == "observed"
    assert (version.extra["verify_code"], version.extra["verify_result"]) == (18, "self-signed certificate")
    session = version.extra["session"]
    assert session["negotiated_group"] == "0x11EC" and session["cert_key"] == "RSA"
    # The probe's own client offer is not inventory evidence.
    assert session["offered_groups"] is None and session["offered_cipher_suites"] is None
    assert all(item.negotiated is True for item in items)
    for item in items:
        assert item.location.source_type == SourceType.LIVE
        assert (item.location.target, item.location.sni, item.location.file) == (
            "localhost:443",
            "localhost",
            None,
        )
        assert item.session_id == version.session_id and item.extra["probe_attempt"] == "default"


def test_tls12_group_and_scheme_come_from_server_key_exchange():
    found = by_detector(findings_of("tls12_ecdsa"))
    assert found["live.tls.version"].raw_name == "TLS 1.2"
    assert found["live.tls.group"].raw_name == "0x001D"
    assert found["live.tls.cipher_suite"].extra["iana_name"] == "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    assert found["live.tls.signature_scheme"].extra["message"] == "ServerKeyExchange"
    assert found["live.tls.certificate"].raw_name == "EC"
    assert found["live.tls.certificate"].curve == "secp256r1"


def test_hello_retry_request_uses_the_final_server_hello():
    found = by_detector(findings_of("tls13_hrr_ed25519"))
    assert found["live.tls.group"].raw_name == "0x0017"
    assert found["live.tls.certificate"].raw_name == "Ed25519"


def test_unnamed_certificate_key_keeps_its_oid():
    found = by_detector(findings_of("tls13_mldsa"))
    assert found["live.tls.certificate"].raw_name == "2.16.840.1.101.3.4.3.18"


def test_targets_and_attempts_never_share_ids_or_sessions():
    rows = [
        *findings_of("tls13_hybrid_rsa", "a.example:443"),
        *findings_of("tls13_hybrid_rsa", "b.example:443"),
        *findings_of("tls13_hybrid_rsa", "a.example:443", "hybrid"),
    ]
    assert len({row.id for row in rows}) == len(rows)
    assert len({row.session_id for row in rows}) == 3


def test_truncated_or_missing_evidence_is_explicit():
    text = transcript("tls13_hybrid_rsa")
    cut = text[: text.index("Handshake [length 031a], Certificate") + 200]
    items = probe.attempt_findings(probe.parse_target("h:443"), probe.parse_attempt("default", cut))
    assert any(isinstance(item, ScanError) and "could not be decoded" in item.message for item in items)
    assert "live.tls.certificate" not in by_detector(items)
    assert by_detector(items)["live.tls.version"].extra["authentication_observable"] is False
    empty = probe.attempt_findings(probe.parse_target("h:443"), probe.parse_attempt("default", "garbage"))
    assert [item.message for item in empty] == ["default attempt: no ServerHello observed"]


class FakeOpenSSL:
    """Answers ``_s_client`` from recorded transcripts keyed by (target, attempt)."""

    def __init__(self, answers, hybrid_capable=True):
        self.answers = answers
        self.hybrid_capable = hybrid_capable
        self.calls = []

    def s_client(self, openssl, target, extra, timeout):
        attempt = "hybrid" if "-groups" in extra else "default"
        self.calls.append((target.text, attempt))
        answer = self.answers[(target.text, attempt)]
        return (None, answer[1]) if isinstance(answer, tuple) else (transcript(answer), None)


@pytest.fixture
def fake(monkeypatch):
    def install(answers, hybrid_capable=True):
        openssl = FakeOpenSSL(answers, hybrid_capable)
        monkeypatch.setattr(probe.shutil, "which", lambda name: "/usr/bin/openssl")
        monkeypatch.setattr(probe, "_s_client", openssl.s_client)
        monkeypatch.setattr(probe, "_supports_hybrid", lambda path, timeout: openssl.hybrid_capable)
        monkeypatch.setattr(probe, "_base_flags", lambda path, timeout: ["-no_rx_cert_comp"])
        return openssl

    return install


def test_attempt_plan_and_hybrid_notes(fake):
    openssl = fake(
        {
            ("hybrid.example:443", "default"): "tls13_hybrid_rsa",
            ("classic.example:443", "default"): "tls13_x25519_rsa",
            ("classic.example:443", "hybrid"): "hybrid_refused_alert",
            ("upgrade.example:443", "default"): "tls13_x25519_rsa",
            ("upgrade.example:443", "hybrid"): "tls13_hybrid_rsa",
            ("down.example:443", "default"): "refused",
            ("slow.example:443", "default"): ("timeout", "timed out after 10 s"),
        }
    )
    items = list(
        probe.probe_endpoints(
            [
                "hybrid.example:443",
                "classic.example:443",
                "upgrade.example:443",
                "down.example:443",
                "slow.example:443",
                "nope",
                "hybrid.example:443",
            ]
        )
    )
    # Hybrid attempt only where the default attempt did not already select a hybrid group.
    assert ("hybrid.example:443", "hybrid") not in openssl.calls
    assert openssl.calls.count(("hybrid.example:443", "default")) == 1  # deduplicated
    notes = {
        item.location.target: item.extra["hybrid_attempt"]["result"]
        for item in items
        if isinstance(item, Finding)
        and item.detector == "live.tls.version"
        and "hybrid_attempt" in item.extra
    }
    assert notes == {
        "hybrid.example:443": "skipped",
        "classic.example:443": "refused",
        "upgrade.example:443": "selected",
    }
    sessions = {
        item.session_id
        for item in items
        if isinstance(item, Finding) and item.location.target == "upgrade.example:443"
    }
    assert len(sessions) == 2
    errors = {(item.path, item.message) for item in items if isinstance(item, ScanError)}
    assert errors == {
        ("down.example:443", "default attempt: connection refused"),
        ("slow.example:443", "default attempt: timed out after 10 s"),
        ("nope", "invalid probe target: expected host:port"),
    }


def test_missing_local_capability_and_executable(fake, monkeypatch):
    fake({("classic.example:443", "default"): "tls13_x25519_rsa"}, hybrid_capable=False)
    items = list(probe.probe_endpoints(["classic.example:443"]))
    assert any(isinstance(item, ScanError) and "lacks X25519MLKEM768" in item.message for item in items)
    version = by_detector(items)["live.tls.version"]
    assert version.extra["hybrid_attempt"]["result"] == "unavailable"
    monkeypatch.setattr(probe.shutil, "which", lambda name: None)
    assert [item.message for item in probe.probe_endpoints(["a.example:443"])] == [
        "openssl executable not found; probe skipped"
    ]


def test_s_client_runs_without_shell_and_handles_timeout(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen.update(args=args, **kwargs)
        return subprocess.CompletedProcess(args, 0, b"out", b"err")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    text, failure = probe._s_client("openssl", probe.parse_target("[::1]:443"), [], 3.0)
    assert (text, failure) == ("out\nerr", None)
    assert seen["args"][:4] == ["openssl", "s_client", "-connect", "[::1]:443"]
    assert "-noservername" in seen["args"] and "shell" not in seen
    assert seen["timeout"] == 3.0 and seen["input"] == b"" and seen["env"]["LC_ALL"] == "C"

    def slow(args, **kwargs):
        raise subprocess.TimeoutExpired(args, 3.0)

    monkeypatch.setattr(probe.subprocess, "run", slow)
    assert probe._s_client("openssl", probe.parse_target("a.example:443"), [], 3.0) == (
        None,
        "timed out after 3 s",
    )


def test_order_and_ids_are_stable_for_shuffled_repeated_targets(fake):
    answers = {
        ("a.example:443", "default"): "tls13_hybrid_rsa",
        ("b.example:443", "default"): "tls12_ecdsa",
        ("b.example:443", "hybrid"): "hybrid_refused_alert",
    }
    fake(answers)
    first = [
        item.model_dump(mode="json") for item in probe.probe_endpoints(["a.example:443", "b.example:443"])
    ]
    targets = ["b.example:443", "a.example:443", "B.example:443"]
    random.Random(7).shuffle(targets)
    fake(answers)
    assert [item.model_dump(mode="json") for item in probe.probe_endpoints(targets)] == first


def live_adapter(monkeypatch, answers):
    """Make the pipeline's adapter answer from fixtures; returns the call log."""
    openssl = FakeOpenSSL(answers)
    monkeypatch.setattr(probe.shutil, "which", lambda name: "/usr/bin/openssl")
    monkeypatch.setattr(probe, "_s_client", openssl.s_client)
    monkeypatch.setattr(probe, "_supports_hybrid", lambda path, timeout: True)
    monkeypatch.setattr(probe, "_base_flags", lambda path, timeout: ["-no_rx_cert_comp"])
    return openssl


def test_pipeline_classifies_live_sessions(monkeypatch):
    live_adapter(
        monkeypatch,
        {
            ("rsa.example:443", "default"): "tls13_hybrid_rsa",
            ("legacy.example:443", "default"): "tls12_ecdsa",
            ("legacy.example:443", "hybrid"): "hybrid_refused_alert",
            ("pq.example:443", "default"): "tls13_mldsa",
        },
    )
    result = pipeline.run([], probes=["rsa.example:443", "legacy.example:443", "pq.example:443"])
    assert result.errors == [] and result.inputs == []
    sessions = {session.source: session for session in result.sessions}
    assert sessions["rsa.example:443"].pq_status == "pq_hybrid"
    # SAFE hybrid key exchange does not make classical RSA authentication SAFE.
    assert sessions["rsa.example:443"].verdict_tier == Tier.CRITICAL
    assert sessions["legacy.example:443"].pq_status == "classical"
    assert sessions["legacy.example:443"].verdict_tier == Tier.CRITICAL
    assert sessions["pq.example:443"].negotiated_group == "X25519MLKEM768"
    # ML-DSA-65 resolves by its FIPS 204 OID; the draft mldsa65 TLS scheme stays UNKNOWN.
    mldsa = [asset for asset in result.assets if asset.canonical_name.startswith("ML-DSA")]
    assert mldsa and all(asset.tier == Tier.SAFE for asset in mldsa)
    assert sessions["pq.example:443"].verdict_tier == Tier.UNKNOWN
    assert {finding.location.source_type for finding in result.findings} == {SourceType.LIVE}
    assert validate_cbom(build_cbom(result)) == []
    assert "live" in result.summary.counts_by_source


def test_no_probe_never_touches_the_adapter(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("probe called")

    monkeypatch.setattr(probe, "probe_endpoints", forbidden)
    monkeypatch.setattr(probe.subprocess, "run", forbidden)
    assert pipeline.run([tmp_path]).errors == []
    assert pipeline.run([tmp_path], probes=[]).errors == []


def test_adapter_failures_keep_partial_results(monkeypatch):
    def broken(targets):
        yield ScanError(detector="live", path=targets[0], message="first fails")
        raise RuntimeError("adapter crashed")

    monkeypatch.setattr(probe, "probe_endpoints", broken)
    result = pipeline.run([], probes=["b.example:443", "a.example:443"])
    assert [error.message for error in result.errors] == [
        "first fails",
        "probe: RuntimeError: adapter crashed",
    ]
    assert result.errors[0].path == "a.example:443"


runner = CliRunner()


def test_cli_probe_only_and_empty_invocation(monkeypatch, tmp_path):
    empty = runner.invoke(cli.app, ["scan", "--out", str(tmp_path / "none")])
    assert empty.exit_code == 2 and "--probe" in empty.output
    live_adapter(
        monkeypatch,
        {
            ("rsa.example:443", "default"): "tls13_hybrid_rsa",
            ("down.example:443", "default"): "refused",
        },
    )
    ok = runner.invoke(
        cli.app, ["scan", "--probe", "rsa.example:443", "--format", "json,cbom,md", "--out", str(tmp_path)]
    )
    assert ok.exit_code == 0, ok.output
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["sessions"][0]["source"] == "rsa.example:443"
    cbom = json.loads((tmp_path / "cbom.json").read_text())
    locations = {
        occurrence["location"]
        for component in cbom["components"]
        for occurrence in component.get("evidence", {}).get("occurrences", [])
    }
    assert locations == {"rsa.example:443"}
    partial = runner.invoke(cli.app, ["scan", "--probe", "down.example:443", "--out", str(tmp_path / "p")])
    assert partial.exit_code == 2 and "connection refused" in partial.output


def test_compressed_certificate_is_observed_but_not_decoded():
    text = transcript("tls13_hybrid_rsa").replace("], Certificate\n", "], CompressedCertificate\n")
    items = probe.attempt_findings(probe.parse_target("h:443"), probe.parse_attempt("default", text))
    assert any(isinstance(item, ScanError) and "RFC 8879" in item.message for item in items)
    version = by_detector(items)["live.tls.version"]
    assert version.extra["certificate_state"] == "observed"
    assert version.extra["authentication_observable"] is False


def test_base_flags_follow_local_openssl_help(monkeypatch):
    def help_text(output):
        return lambda args, **kwargs: subprocess.CompletedProcess(args, 0, b"", output)

    monkeypatch.setattr(probe.subprocess, "run", help_text(b" -no_rx_cert_comp  Disable receiving"))
    assert probe._base_flags("openssl", 1.0) == ["-no_rx_cert_comp"]
    monkeypatch.setattr(probe.subprocess, "run", help_text(b" -no_comp  Disable SSL/TLS compression"))
    assert probe._base_flags("openssl", 1.0) == []
