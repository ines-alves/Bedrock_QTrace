"""Production owner registries at the M1 injection boundary (offline)."""

from pathlib import Path

import pytest

from quantumtrace.engine import analyze
from quantumtrace.engine.registries import CloudRegistry, TLSRegistry
from quantumtrace.models import Finding, KindHint, Location, SourceType, Tier, Usage
from quantumtrace.scanners.cloud.kms import KmsScanner
from quantumtrace.scanners.cloud.loadbalancer import LoadBalancerScanner


def raw(name, source=SourceType.PCAP, kind=KindHint.GROUP, **updates):
    data = dict(
        id="fixture",
        raw_name=name,
        kind_hint=kind,
        usage=Usage.KEY_EXCHANGE,
        detector="fixture",
        location=Location(source_type=source, file="fixture"),
    )
    data.update(updates)
    return Finding(**data)


def test_tls_numeric_namespaces_and_openssl():
    tls = TLSRegistry()
    assert tls.resolve(KindHint.GROUP, "0x001D").iana_name == "x25519"
    assert tls.resolve_name(KindHint.CIPHER_SUITE, "ECDHE-RSA-AES128-GCM-SHA256").iana_name == (
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    )
    assert tls.resolve(KindHint.ALGORITHM, "0x001D") is None
    assert tls.resolve(KindHint.GROUP, "0xFFFF") is None
    assert tls.resolve(KindHint.PROTOCOL_VERSION, "0x0304").iana_name == "TLS 1.3"
    for kind, namespace in [(KindHint.GROUP, "groups"), (KindHint.SIGNATURE_SCHEME, "signature_schemes")]:
        for code, row in tls.data[namespace].items():
            if "verify" in row and code != "0x0017":
                assert tls.resolve(kind, code) is None


def test_verify_marker_conflicts_and_ambiguous_aliases():
    tls = TLSRegistry()
    tls.data["groups"]["0x001D"]["verify"] = []
    assert tls.resolve(KindHint.GROUP, "0x001D") is None
    tls.data["cipher_suites"]["0xFAFA"] = dict(tls.data["cipher_suites"]["0xC02F"])
    assert tls.resolve_name(KindHint.CIPHER_SUITE, "ECDHE-RSA-AES128-GCM-SHA256") is None
    assets, _ = analyze([raw("0x001D", extra={"iana_name": "secp256r1"})])
    assert assets[0].tier == Tier.UNKNOWN


@pytest.mark.parametrize(
    "partition,expected",
    [("aws", Tier.SAFE), ("aws-us-gov", Tier.SAFE), ("aws-cn", Tier.UNKNOWN), ("unknown", Tier.UNKNOWN)],
)
def test_kms_partition_mapping(partition, expected):
    item = raw(
        "SYMMETRIC_DEFAULT",
        SourceType.KMS,
        KindHint.KEY,
        usage=Usage.ENCRYPTION,
        location=Location(source_type=SourceType.KMS, resource_id=f"arn:{partition}:kms:region:123:key/one"),
    )
    assets, summary = analyze([item])
    scored = [asset for asset in assets if asset.max_points > 0]
    assert len(scored) == 1 and scored[0].tier == expected
    assert sum(summary.counts_by_tier.values()) == 1
    if expected == Tier.SAFE:
        assert scored[0].canonical_name == "AES" and scored[0].key_size == 256
        assert scored[0].mode == "gcm"


def test_kms_missing_partition_observed_conflicts_and_usage():
    item = raw("SYMMETRIC_DEFAULT", SourceType.KMS, KindHint.KEY, usage=Usage.ENCRYPTION)
    assert analyze([item])[0][0].tier == Tier.UNKNOWN
    item.location.resource_id = "arn:aws:kms:region:123:key/one"
    item.key_size = 128
    assets, _ = analyze([item])
    assert all(asset.tier != Tier.SAFE for asset in assets)
    item.usage = Usage.SIGNATURE
    assert CloudRegistry(TLSRegistry()).resolve(item) is None


def test_published_cloud_policy_uses_only_documented_groups():
    cloud = CloudRegistry(TLSRegistry())
    classic = raw(
        "ELBSecurityPolicy-TLS13-1-3-2021-06", SourceType.LOADBALANCER, KindHint.POLICY, usage=Usage.UNKNOWN
    )
    resolved = cloud.resolve(classic)
    assert resolved and not any(spec.kind == KindHint.GROUP for spec in resolved.components)
    assets, summary = analyze([classic])
    assert all(asset.usage != Usage.KEY_EXCHANGE for asset in assets if asset.max_points > 0)
    assert next(asset for asset in assets if asset.canonical_name == classic.raw_name).tier == Tier.MEDIUM
    assert summary.hndl_exposed_count == 0
    assert cloud.resolve(classic.model_copy(update={"raw_name": "unpublished-policy"})) is None


def test_real_kms_and_listener_findings():
    root = Path(__file__).resolve().parents[1]
    findings = []
    kms = KmsScanner()
    lb = LoadBalancerScanner()
    for path in sorted((root / "cloud-posture").glob("*.json")):
        for scanner in (kms, lb):
            if scanner.can_handle(path):
                findings.extend(item for item in scanner.scan(path, root) if isinstance(item, Finding))
    assert sum(item.location.source_type == SourceType.KMS for item in findings) == 10
    assets, summary = analyze(findings)
    assert summary.counts_by_source["kms"]["SAFE"] > 0
    assert any(asset.components and asset.max_points == 0 for asset in assets)
    assert all(asset.risk_points <= asset.max_points for asset in assets)
    assert analyze(list(reversed(findings))) == (assets, summary)


def test_numeric_group_confirmation_is_separate_from_alias_uncertainty():
    tls = TLSRegistry()
    assert tls.resolve(KindHint.GROUP, "0x0017").iana_name == "secp256r1"
    assert tls.resolve_name(KindHint.GROUP, "prime256v1") is None
    assert tls.resolve_name(KindHint.GROUP, "secp256r1").iana_name == "secp256r1"
    assert tls.resolve_name(KindHint.GROUP, "P-256").iana_name == "secp256r1"
    assets, _ = analyze([raw("0x0017")])
    assert any(asset.tier == Tier.CRITICAL for asset in assets)
    conflicting, _ = analyze([raw("0x0017", extra={"iana_name": "secp384r1"})])
    assert conflicting[0].tier == Tier.UNKNOWN


@pytest.mark.parametrize(
    "marker",
    [
        [],
        "alias",
        [None],
        ["openssl alias absent paired via openssl ecparam"],
        ["openssl alias prime256v1 paired via openssl ecparam", "not in IANA snapshot"],
        ["codepoint unverified"],
    ],
)
def test_numeric_lookup_never_ignores_general_or_malformed_uncertainty(marker):
    tls = TLSRegistry()
    tls.data["groups"]["0x0017"]["verify"] = marker
    assert tls.resolve(KindHint.GROUP, "0x0017") is None
    assert tls.resolve_name(KindHint.GROUP, "secp256r1") is None


@pytest.mark.parametrize(
    "code,label,rfc",
    [
        ("0x0300", "SSL 3.0", "6101"),
        ("0x0301", "TLS 1.0", "2246"),
        ("0x0302", "TLS 1.1", "4346"),
        ("0x0303", "TLS 1.2", "5246"),
        ("0x0304", "TLS 1.3", "8446"),
    ],
)
def test_version_rows_cite_the_actual_rfc(code, label, rfc):
    tls = TLSRegistry()
    row = tls.resolve(KindHint.PROTOCOL_VERSION, code)
    assert row.iana_name == label and row.source == f"https://www.rfc-editor.org/rfc/rfc{rfc}.html"
    assets, _ = analyze([raw(code, kind=KindHint.PROTOCOL_VERSION, usage=Usage.UNKNOWN)])
    assert assets[0].max_points == 0
    assert "verified TLS registry unavailable" not in assets[0].rationale
    tls.data["versions"][code].pop("ref")
    assert tls.resolve(KindHint.PROTOCOL_VERSION, code) is None
