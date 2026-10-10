"""Load balancer adapter against the real kit file: Appendix D.5, the registry and the sample fixture."""

import json
from pathlib import Path

import yaml

from quantumtrace.models import Finding, KindHint, ScanError, ScanResult
from quantumtrace.scanners.cloud.loadbalancer import UNKNOWN_POLICY_CONFIDENCE, LoadBalancerScanner

ROOT = Path(__file__).resolve().parent.parent
LB = ROOT / "cloud-posture" / "load_balancer_listeners.json"
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"
REGISTRY = ROOT / "src" / "quantumtrace" / "kb" / "cloud_registry.yaml"


def _scan(path: Path = LB, root: Path = ROOT) -> list[Finding | ScanError]:
    return list(LoadBalancerScanner().scan(path, root))  # type: ignore[arg-type]


def test_can_handle_by_content_not_name(tmp_path: Path) -> None:
    renamed = tmp_path / "anything.json"
    renamed.write_text(LB.read_text())
    assert LoadBalancerScanner().can_handle(renamed)
    assert not LoadBalancerScanner().can_handle(ROOT / "cloud-posture" / "kms_key_inventory.json")
    assert not LoadBalancerScanner().can_handle(ROOT / "README.md")


def test_one_finding_per_listener_with_arn_resource_id() -> None:
    findings = _scan()
    assert len(findings) == 7 and all(isinstance(f, Finding) for f in findings)
    assert len({f.location.resource_id for f in findings}) == 7
    assert all(":listener/" in f.location.resource_id for f in findings)
    assert all(f.negotiated is None for f in findings)


def test_two_plaintext_hygiene_findings() -> None:
    plain = {f.extra["lb_name"]: f for f in _scan() if f.kind_hint == KindHint.PLAINTEXT}
    assert set(plain) == {"public-web-alb", "batch-internal-alb"}
    assert all(f.raw_name == "HTTP:80" and f.extra["hygiene_only"] for f in plain.values())
    assert plain["public-web-alb"].extra["redirects_to_https"] is True
    assert plain["public-web-alb"].extra["hygiene_flags"] == ["redirect_only_listener"]
    assert plain["batch-internal-alb"].extra["redirects_to_https"] is False
    assert plain["batch-internal-alb"].extra["hygiene_flags"] == []


def test_policy_facts_and_exposure() -> None:
    by_lb = {f.extra["lb_name"]: f for f in _scan() if f.kind_hint == KindHint.POLICY}
    assert len(by_lb) == 5
    nlb = by_lb["legacy-tcp-nlb"]
    assert (nlb.extra["lb_type"], nlb.extra["listener_protocol"], nlb.extra["port"]) == (
        "network",
        "TLS",
        8443,
    )
    assert nlb.extra["certificate_arns"] == [
        "arn:aws:acm:eu-west-1:123456789012:certificate/55555555-6666-7777-8888-999999999999"
    ]
    exposure = {name: f.extra["public_exposure"] for name, f in by_lb.items()}
    assert exposure == {
        "public-web-alb": True,
        "internal-admin-alb": False,
        "api-gateway-alb": True,
        "partner-api-alb": True,
        "legacy-tcp-nlb": False,
    }
    assert {f.extra["source_timestamp"] for f in _scan()} == {"2026-09-14T09:35:51Z"}


def test_every_kit_policy_is_in_the_registry() -> None:
    table = yaml.safe_load(REGISTRY.read_text())["elb_policies"]
    findings = [f for f in _scan() if f.kind_hint == KindHint.POLICY]
    assert all(f.raw_name in table and f.confidence == 1.0 for f in findings)


def test_registry_rows_match_aws_documentation() -> None:
    """Spot values read from the AWS ALB/NLB security-policy tables on 2026-10-10."""
    t = yaml.safe_load(REGISTRY.read_text())["elb_policies"]
    assert len(t) == 45
    assert t["ELBSecurityPolicy-2016-08"]["protocols"] == ["TLSv1.2", "TLSv1.1", "TLSv1.0"]
    assert len(t["ELBSecurityPolicy-2016-08"]["cipher_suites"]) == 18
    assert t["ELBSecurityPolicy-TLS-1-1-2017-01"]["protocols"] == ["TLSv1.2", "TLSv1.1"]
    assert t["ELBSecurityPolicy-TLS-1-2-2017-01"]["protocols"] == ["TLSv1.2"]
    assert "AES128-GCM-SHA256" in t["ELBSecurityPolicy-TLS-1-2-2017-01"]["cipher_suites"]
    fs = t["ELBSecurityPolicy-FS-1-2-Res-2020-10"]
    assert fs["cipher_suites"] == [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ]
    assert t["ELBSecurityPolicy-TLS13-1-2-2021-06"]["protocols"] == ["TLSv1.3", "TLSv1.2"]
    assert t["ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"]["pq_hybrid"] is True
    assert t["ELBSecurityPolicy-TLS13-1-2-2021-06"]["pq_hybrid"] is False


def test_groups_only_where_aws_documents_them() -> None:
    t = yaml.safe_load(REGISTRY.read_text())["elb_policies"]
    hybrid = ["SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768"]
    for name, row in t.items():
        assert row["groups_complete"] is False
        if row["pq_hybrid"]:
            assert "-PQ-" in name and row["groups"] == hybrid and row["groups_verified"] is True
        else:
            assert row["groups"] == [] and row["groups_verified"] is False


def _dump(tmp_path: Path, listener: dict, scheme: str | None = "internal") -> Path:
    lb = {"LoadBalancerName": "x", "Type": "application", "Listeners": [listener]}
    if scheme:
        lb["Scheme"] = scheme
    path = tmp_path / "lb.json"
    path.write_text(json.dumps({"GeneratedAt": "2026-09-14T00:00:00Z", "LoadBalancers": [lb]}))
    return path


def test_unknown_policy_gets_reduced_confidence(tmp_path: Path) -> None:
    listener = {
        "ListenerArn": "arn:l",
        "Protocol": "HTTPS",
        "Port": 443,
        "SslPolicy": "Custom-1",
        "Certificates": [],
    }
    (finding,) = _scan(_dump(tmp_path, listener), tmp_path)
    assert isinstance(finding, Finding)
    assert finding.raw_name == "Custom-1" and finding.confidence == UNKNOWN_POLICY_CONFIDENCE


def test_missing_scheme_is_unknown_exposure_not_false(tmp_path: Path) -> None:
    listener = {"ListenerArn": "arn:l", "Protocol": "HTTP", "Port": 80, "DefaultActions": []}
    (finding,) = _scan(_dump(tmp_path, listener, scheme=None), tmp_path)
    assert isinstance(finding, Finding) and finding.extra["public_exposure"] is None


def test_malformed_listeners_are_scan_errors(tmp_path: Path) -> None:
    for listener, text in [
        ({"Protocol": "HTTP"}, "without ARN"),
        ({"ListenerArn": "arn:l", "Protocol": "HTTPS", "Port": 443}, "without SslPolicy"),
        ({"ListenerArn": "arn:l", "Protocol": "TCP", "Port": 22}, "unsupported listener protocol"),
    ]:
        (error,) = _scan(_dump(tmp_path, listener), tmp_path)
        assert isinstance(error, ScanError) and text in error.message


def test_matches_sample_fixture_lb_findings() -> None:
    sample = ScanResult.model_validate_json(SAMPLE.read_text())
    expected = {f.id: f for f in sample.findings if f.detector == "cloud.loadbalancer"}
    assert {f.id: f for f in _scan() if isinstance(f, Finding)} == expected


def test_symmetric_default_depends_on_the_partition() -> None:
    """AWS KMS key-spec reference: AES-256-GCM, except China Regions (SM4, 128-bit)."""
    spec = yaml.safe_load(REGISTRY.read_text())["kms_key_specs"]["SYMMETRIC_DEFAULT"]
    assert spec["verified"] is True
    assert spec["default"] == {"algorithm": "AES", "key_size": 256, "mode": "gcm"}
    assert spec["partitions"] == {"aws-cn": {"algorithm": "SM4", "key_size": 128, "mode": None}}
    assert set(spec["default_partitions"]).isdisjoint(spec["partitions"])
    kms = json.loads((ROOT / "cloud-posture" / "kms_key_inventory.json").read_text())
    symmetric = [k for k in kms["Keys"] if k["KeySpec"] == "SYMMETRIC_DEFAULT"]
    assert len(symmetric) == 4
    assert {k["KeyArn"].split(":")[1] for k in symmetric} <= set(spec["default_partitions"])


def test_every_row_source_resolves_to_a_url() -> None:
    reg = yaml.safe_load(REGISTRY.read_text())
    urls = reg["meta"]["sources"]
    for row in reg["elb_policies"].values():
        assert all(part in urls for part in row["source"].split("+"))
    assert all(u.startswith("https://docs.aws.amazon.com/") for u in urls.values())
