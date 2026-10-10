"""The hand-made UI sample must stay a valid ScanResult and keep the agreed cases (M3M4-02, M1M4-06)."""

import json
from pathlib import Path

import pytest

from quantumtrace.models import KindHint, ScanResult, SourceType, Tier
from quantumtrace.scanners.base import finding_id, is_test_path

SAMPLE = Path(__file__).parent / "fixtures" / "scan_result_sample.json"


@pytest.fixture(scope="module")
def raw():
    return json.loads(SAMPLE.read_text())


@pytest.fixture(scope="module")
def result(raw):
    return ScanResult.model_validate(raw)


def test_validates_and_round_trips(raw, result):
    # Pydantic ignores unknown keys, so the round trip is what catches a misspelled optional field.
    assert result.model_dump(mode="json", exclude_unset=True) == raw


def test_ids_and_references(result):
    assert all(f.id == finding_id(f.detector, f.raw_name, f.location) for f in result.findings)
    finding_ids = {f.id for f in result.findings}
    assert len(finding_ids) == len(result.findings)
    asset_ids = [a.asset_id for a in result.assets]
    assert len(set(asset_ids)) == len(asset_ids)
    for a in result.assets:
        assert set(a.finding_ids) <= finding_ids
        assert set(a.components) <= set(asset_ids)
        assert set(a.component_of) <= set(asset_ids)
    session_ids = {s.session_id for s in result.sessions}
    assert {f.session_id for f in result.findings if f.session_id} == session_ids


def test_summary_matches_assets(result):
    s = result.summary
    assert s.counts_by_tier == {t.value: sum(a.tier == t for a in result.assets) for t in Tier}
    assert s.hndl_exposed_count == sum(a.hndl_exposed for a in result.assets)
    assert set(s.top_risks) <= {a.asset_id for a in result.assets}
    assert s.score >= 60  # an active negotiated HNDL exposure floors the score
    assert {r.phase for r in result.roadmap} == {0, 1, 2, 3}


def test_sessions(result):
    tls = [s for s in result.sessions if s.transport == "tls"]
    ssh = [s for s in result.sessions if s.transport == "ssh"]
    assert (len(tls), len(ssh)) == (5, 2)
    hybrid = [s for s in result.sessions if s.pq_status == "pq_hybrid"]
    assert [(s.sni, s.verdict_tier) for s in hybrid] == [("vault01.lab", Tier.UNKNOWN)]
    assert all(s.cert_key is None for s in tls)
    session_findings = [f for f in result.findings if f.kind_hint == KindHint.PROTOCOL_VERSION]
    # M1M2-07: SSH host key algorithm selection is observed, a TLS Certificate message is not.
    assert {f.protocol: f.extra["authentication_observable"] for f in session_findings} == {
        "TLS 1.2": False,
        "TLS 1.3": False,
        "SSH-2.0": True,
    }
    assert all("certificate_state" not in f.extra for f in session_findings if f.protocol == "SSH-2.0")
    assert all(s.cert_key for s in ssh)


def test_ssh_aead_mac_is_offered_not_negotiated(result):
    """M1M4-22: no negotiated MAC for an AEAD cipher, the offer is kept with negotiated False."""
    macs = [f for f in result.findings if f.detector == "pcap.ssh.mac"]
    by_session = {}
    for f in macs:
        by_session.setdefault(f.session_id, []).append(f)
    modern = next(s for s in result.sessions if s.negotiated_cipher_suite == "chacha20-poly1305@openssh.com")
    assert [(f.raw_name, f.negotiated) for f in by_session[modern.session_id]] == [
        ("hmac-sha2-256-etm@openssh.com", False)
    ]
    legacy = next(s for s in result.sessions if s.negotiated_cipher_suite == "aes128-cbc")
    assert sorted(f.negotiated for f in by_session[legacy.session_id]) == [False, True]


def test_every_tier_and_source(result):
    assert {a.tier for a in result.assets} == set(Tier)
    assert set(result.summary.counts_by_source) == {"pcap", "ssh", "code", "kms", "loadbalancer", "acm"}


def test_cloud_facts(result):
    kms = [f for f in result.findings if f.location.source_type == SourceType.KMS]
    assert len(kms) == 10 and all(f.location.resource_id.startswith("arn:aws:kms:") for f in kms)
    rotation = {f.extra["alias"] for f in kms if "rotation_disabled" in f.extra["hygiene_flags"]}
    assert rotation == {"alias/ebs-volume-encryption", "alias/legacy-reports-export"}
    plain = {
        f.extra["lb_name"]: f
        for f in result.findings
        if f.kind_hint == KindHint.PLAINTEXT and f.location.source_type == SourceType.LOADBALANCER
    }
    assert plain["public-web-alb"].extra["hygiene_flags"] == ["redirect_only_listener"]
    assert plain["public-web-alb"].extra["redirects_to_https"] is True
    assert plain["batch-internal-alb"].extra["redirects_to_https"] is False
    assert all(f.extra["hygiene_only"] for f in plain.values())
    assert all(
        f.negotiated is None
        for f in result.findings
        if f.location.source_type in {SourceType.KMS, SourceType.LOADBALANCER, SourceType.ACM}
    )


def test_code_cases(result):
    code = [f for f in result.findings if f.location.source_type == SourceType.CODE]
    flags = [(f.language, fl) for f in code for fl in f.extra.get("hygiene_flags", [])]
    assert sorted(flags) == [
        ("go", "insecure_rng"),
        ("java", "insecure_rng"),
        ("python", "hardcoded_key"),
        ("python", "insecure_rng"),
    ]
    assert [f.raw_name for f in code if f.kind_hint == KindHint.LIBRARY] == ["cryptography==46.0.5"]
    rsa = {f.language for f in code if f.raw_name == "RSA" and f.key_size == 1024}
    assert rsa == {"python", "java", "go"}
    assert any(f.mode == "ECB" for f in code)
    test_only = [a for a in result.assets if a.in_test_code_only]
    assert len(test_only) == 1 and all(is_test_path(o.file) for o in test_only[0].occurrences)
    assert not any(is_test_path(f.location.file) for f in code if not f.in_test_code)


def test_no_key_literal(raw):
    assert "0123456789ABCDEF" not in SAMPLE.read_text()
    assert any(
        f["location"]["snippet"] == 'EXPORT_KEY = b"<redacted>"'
        for f in raw["findings"]
        if f["location"].get("snippet")
    )
