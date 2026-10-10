"""KMS adapter against the real kit file: Appendix D.5 and the sample fixture."""

import json
from pathlib import Path

from quantumtrace.models import Finding, KindHint, ScanResult, Usage
from quantumtrace.scanners.cloud.kms import KmsScanner

ROOT = Path(__file__).resolve().parent.parent
KMS = ROOT / "cloud-posture" / "kms_key_inventory.json"
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"


def _scan() -> list[Finding]:
    return list(KmsScanner().scan(KMS, ROOT))  # type: ignore[arg-type]


def test_can_handle_by_content_not_name(tmp_path: Path) -> None:
    renamed = tmp_path / "anything.json"
    renamed.write_text(KMS.read_text())
    assert KmsScanner().can_handle(renamed)
    assert not KmsScanner().can_handle(ROOT / "cloud-posture" / "acm_certificates.json")
    assert not KmsScanner().can_handle(ROOT / "README.md")


def test_one_key_finding_per_key() -> None:
    findings = _scan()
    assert len(findings) == 10
    assert {f.kind_hint for f in findings} == {KindHint.KEY}
    assert len({f.location.resource_id for f in findings}) == 10
    assert all(f.location.resource_id.startswith("arn:aws:kms:") for f in findings)


def test_facts_match_appendix_d5() -> None:
    by_alias = {f.extra["alias"]: f for f in _scan()}
    rsa = by_alias["alias/licensing-jwt-signing"]
    assert (rsa.raw_name, rsa.key_size, rsa.usage) == ("RSA_2048", 2048, Usage.SIGNATURE)
    assert by_alias["alias/internal-ca-root"].curve == "P-384"
    assert by_alias["alias/partner-feed-decrypt"].extra["origin"] == "EXTERNAL"
    assert by_alias["alias/hsm-backed-settlement"].extra["origin"] == "AWS_CLOUDHSM"
    assert by_alias["alias/legacy-reports-export"].extra["state"] == "PendingDeletion"
    flagged = {a: f.extra["hygiene_flags"] for a, f in by_alias.items() if f.extra["hygiene_flags"]}
    assert flagged == {
        "alias/ebs-volume-encryption": ["rotation_disabled"],
        "alias/legacy-reports-export": ["rotation_disabled"],
        "alias/internal-ca-root": ["multi_region_key"],
    }
    assert {f.extra["source_timestamp"] for f in by_alias.values()} == {"2026-09-14T09:32:07Z"}


def test_matches_sample_fixture_kms_findings() -> None:
    sample = ScanResult.model_validate_json(SAMPLE.read_text())
    expected = {f.id: f for f in sample.findings if f.detector == "cloud.kms"}
    # The pipeline scans each input directory as the scan root, so Location.file is relative to cloud-posture/.
    assert {f.id: f for f in KmsScanner().scan(KMS, KMS.parent)} == expected  # type: ignore[arg-type]


def test_missing_identifier_is_a_scan_error(tmp_path: Path) -> None:
    bad = tmp_path / "kms.json"
    bad.write_text(json.dumps({"Keys": [{"KeySpec": "RSA_2048"}]}))
    out = list(KmsScanner().scan(bad, tmp_path))  # type: ignore[arg-type]
    assert len(out) == 1 and out[0].message.startswith("key without")
