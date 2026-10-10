"""ACM adapter against the real kit file: Appendix D.5, the listener dump and the sample fixture."""

import json
from pathlib import Path

from quantumtrace.models import Finding, KindHint, ScanError, ScanResult, Usage
from quantumtrace.scanners.cloud.acm import AcmScanner
from quantumtrace.scanners.cloud.loadbalancer import LoadBalancerScanner

ROOT = Path(__file__).resolve().parent.parent
ACM = ROOT / "cloud-posture" / "acm_certificates.json"
LB = ROOT / "cloud-posture" / "load_balancer_listeners.json"
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"


def _scan(path: Path = ACM, root: Path = ROOT) -> list[Finding | ScanError]:
    return list(AcmScanner().scan(path, root))  # type: ignore[arg-type]


def _certs() -> list[Finding]:
    return [f for f in _scan() if isinstance(f, Finding)]


def test_can_handle_by_content_not_name(tmp_path: Path) -> None:
    renamed = tmp_path / "anything.json"
    renamed.write_text(ACM.read_text())
    assert AcmScanner().can_handle(renamed)
    assert not AcmScanner().can_handle(ROOT / "cloud-posture" / "kms_key_inventory.json")
    assert not AcmScanner().can_handle(LB)
    assert not AcmScanner().can_handle(ROOT / "cloud-posture" / "README.md")


def test_one_certificate_finding_per_certificate() -> None:
    findings = _certs()
    assert len(findings) == 5 and len(_scan()) == 5
    assert {f.kind_hint for f in findings} == {KindHint.CERTIFICATE}
    assert {f.usage for f in findings} == {Usage.AUTHENTICATION}
    assert len({f.location.resource_id for f in findings}) == 5
    assert all(str(f.location.resource_id).startswith("arn:aws:acm:") for f in findings)
    assert all(f.location.file == "cloud-posture/acm_certificates.json" for f in findings)
    assert all(f.negotiated is None for f in findings)


def test_facts_match_appendix_d5() -> None:
    by_domain = {f.location.target: f for f in _certs()}
    legacy = by_domain["legacy-tcp.internal.example.com"]
    assert legacy.extra["origin"] == "IMPORTED"
    assert legacy.extra["signature_algorithm"] == "SHA1WITHRSA"
    assert legacy.extra["not_after"] == "2026-08-01T23:59:59Z"
    assert legacy.extra["state"] == legacy.extra["cert_status"] == "ISSUED"
    assert [a.split("/")[2] for a in legacy.extra["in_use_by"]] == ["legacy-tcp-nlb"]
    assert {f.extra["source_timestamp"] for f in by_domain.values()} == {"2026-09-14T09:38:19Z"}
    assert all(f.extra["hygiene_flags"] == [] for f in by_domain.values())


def test_key_size_and_curve_mapping() -> None:
    by_name = {f.raw_name: f for f in _certs()}
    assert (by_name["RSA_2048"].key_size, by_name["RSA_2048"].curve) == (2048, None)
    assert (by_name["EC_prime256v1"].key_size, by_name["EC_prime256v1"].curve) == (None, "P-256")
    assert (by_name["EC_secp384r1"].key_size, by_name["EC_secp384r1"].curve) == (None, "P-384")


def test_unknown_spelling_is_not_guessed(tmp_path: Path) -> None:
    dump = {"Certificates": [{"CertificateArn": "arn:c", "KeyAlgorithm": "EC_secp521r1"}]}
    path = tmp_path / "acm.json"
    path.write_text(json.dumps(dump))
    (finding,) = _scan(path, tmp_path)
    assert isinstance(finding, Finding)
    assert (finding.key_size, finding.curve) == (None, None)


def test_certificates_and_listeners_are_consistent() -> None:
    listeners = [f for f in LoadBalancerScanner().scan(LB, ROOT) if isinstance(f, Finding)]  # type: ignore[arg-type]
    listener_arns = {f.location.resource_id for f in listeners}
    for cert in _certs():
        holders = [f for f in listeners if cert.location.resource_id in f.extra.get("certificate_arns", [])]
        assert len(holders) == 1
        assert set(cert.extra["in_use_by"]) <= listener_arns


def test_matches_sample_fixture_acm_findings() -> None:
    sample = ScanResult.model_validate_json(SAMPLE.read_text())
    expected = {f.id: f for f in sample.findings if f.detector == "cloud.acm"}
    # The pipeline scans each input directory as the scan root, so Location.file is relative to cloud-posture/.
    scanned = _scan(ACM, ACM.parent)
    assert {f.id: f for f in scanned if isinstance(f, Finding)} == expected


def test_malformed_certificates_are_scan_errors(tmp_path: Path) -> None:
    good = {"CertificateArn": "arn:good", "KeyAlgorithm": "RSA_2048"}
    dump = {"Certificates": [good, {"KeyAlgorithm": "RSA_2048"}, {"CertificateArn": "arn:nokey"}]}
    path = tmp_path / "acm.json"
    path.write_text(json.dumps(dump))
    out = _scan(path, tmp_path)
    assert [type(o) for o in out] == [Finding, ScanError, ScanError]
    assert all(o.message.startswith("certificate without") for o in out[1:])  # type: ignore[union-attr]
