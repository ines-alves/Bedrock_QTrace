"""The bundled UI sample is real qtrace scan output of the starter kit; these checks do not depend on counts."""

import json
from pathlib import Path

import pytest

from quantumtrace.models import KindHint, ScanResult, SourceType, Tier
from quantumtrace.scanners.base import finding_id

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"
SESSION_SAMPLES = ROOT / "tests" / "fixtures" / "pcap" / "samples"


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
        assert a.finding_ids and set(a.finding_ids) <= finding_ids
        assert set(a.components) <= set(asset_ids)
        assert set(a.component_of) <= set(asset_ids)
    assert set(result.summary.top_risks) <= set(asset_ids)
    assert all(set(r.asset_ids) <= set(asset_ids) for r in result.roadmap)
    session_ids = [s.session_id for s in result.sessions]
    assert len(set(session_ids)) == len(session_ids)
    assert {f.session_id for f in result.findings if f.session_id} == set(session_ids)


def test_summary_counts_the_scored_assets_only(result):
    s = result.summary
    scored = [a for a in result.assets if a.max_points > 0]
    assert scored and len(scored) < len(result.assets)
    assert sum(s.counts_by_tier.values()) == len(scored)
    assert s.top_risks == [a.asset_id for a in result.assets if a.risk_points > 0]
    assert s.score >= 60  # an active negotiated HNDL exposure floors the score
    assert {r.phase for r in result.roadmap} == {0, 1, 2, 3}


def test_every_tier_and_source(result):
    assert {a.tier for a in result.assets} == set(Tier)
    assert set(result.summary.counts_by_source) == {"pcap", "ssh", "code", "kms", "loadbalancer", "acm"}


def test_paths_are_relative_to_the_repo_root(result):
    assert not any(Path(p).is_absolute() for p in result.inputs)
    assert not any(Path(e.path).is_absolute() for e in result.errors if e.path)


def test_m2_sample_sessions_are_present(result):
    """The M2 sample files are cut from the same kit: their findings and sessions must be in the result."""
    findings = {f.id: f for f in result.findings}
    sessions = {s.session_id: s for s in result.sessions}
    seen = set()
    for path in sorted(SESSION_SAMPLES.glob("*.json")):
        for item in json.loads(path.read_text()):
            assert findings[item["id"]].model_dump(mode="json", exclude_unset=True) == item, path.name
            seen.add(item.get("session_id"))
    assert seen - {None} <= set(sessions)
    assert {s.transport for s in result.sessions} == {"tls", "ssh"}


def test_session_findings_carry_the_authentication_rule(result):
    """M1M2-07: the SSH host key algorithm is observed, a TLS Certificate message is not."""
    versions = [f for f in result.findings if f.kind_hint == KindHint.PROTOCOL_VERSION and f.session_id]
    by_transport = {}
    for f in versions:
        by_transport.setdefault(f.protocol.startswith("SSH"), set()).add(f.extra["authentication_observable"])
    assert by_transport == {True: {True}, False: {False}}
    assert all("certificate_state" not in f.extra for f in versions if f.protocol.startswith("SSH"))
    hybrid = [s for s in result.sessions if s.pq_status == "pq_hybrid"]
    assert hybrid and all(s.verdict_tier == Tier.UNKNOWN for s in hybrid)


def test_ssh_aead_mac_is_offered_not_negotiated(result):
    """M1M4-22: no negotiated MAC for an AEAD cipher, the offer is kept with negotiated False."""
    sessions = {s.session_id: s for s in result.sessions}
    aead = {
        sid
        for sid, s in sessions.items()
        if s.transport == "ssh" and "poly1305" in (s.negotiated_cipher_suite or "")
    }
    macs = [f for f in result.findings if f.detector == "pcap.ssh.mac" and f.session_id in aead]
    assert aead and macs and not any(f.negotiated for f in macs)


def test_cloud_facts(result):
    kms = [f for f in result.findings if f.location.source_type == SourceType.KMS]
    assert kms and all(f.location.resource_id.startswith("arn:aws:kms:") for f in kms)
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


def test_code_findings_are_reachable_through_assets(result):
    code = {f.id: f for f in result.findings if f.location.source_type == SourceType.CODE}
    reachable = {i for a in result.assets for i in a.finding_ids}
    assert code and set(code) <= reachable
    assert any(
        f.kind_hint == KindHint.LIBRARY and f.raw_name.startswith("cryptography==") for f in code.values()
    )


def test_no_secret_literals_or_local_paths(raw):
    text = SAMPLE.read_text()
    for needle in ("0123456789ABCDEF", "PRIVATE KEY", "/Users/", "/private/", "/home/"):
        assert needle not in text
    assert any(
        "<redacted>" in f["location"]["snippet"] for f in raw["findings"] if f["location"].get("snippet")
    )
