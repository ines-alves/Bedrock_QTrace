"""CycloneDX 1.6 CBOM: strict offline validation of every ScanResult fixture and the builder contract."""

import copy
import re
from pathlib import Path
from typing import Any

import pytest

from quantumtrace.engine import analyze
from quantumtrace.models import Finding, KindHint, ScanResult
from quantumtrace.output.cyclonedx import build_cbom, validate_cbom
from quantumtrace.scanners.cloud.acm import AcmScanner
from quantumtrace.scanners.cloud.kms import KmsScanner
from quantumtrace.scanners.cloud.loadbalancer import LoadBalancerScanner
from quantumtrace.scanners.code.engine import CodeScanner

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = sorted((ROOT / "tests" / "fixtures").glob("*scan_result*.json"))


def _sample() -> ScanResult:
    return ScanResult.model_validate_json(
        (ROOT / "tests" / "fixtures" / "scan_result_sample.json").read_text()
    )


def _real_result() -> ScanResult:
    """Cloud kit and code kit through the real scanners and the engine, without the pipeline."""
    findings: list[Finding] = []
    for scanner in (KmsScanner(), AcmScanner(), LoadBalancerScanner()):
        for path in sorted((ROOT / "cloud-posture").glob("*.json")):
            if scanner.can_handle(path):
                findings += [f for f in scanner.scan(path, ROOT) if isinstance(f, Finding)]
    code = CodeScanner()
    for path in sorted((ROOT / "sample-repos").rglob("*")):
        if path.is_file() and code.can_handle(path):
            findings += [f for f in code.scan(path, ROOT) if isinstance(f, Finding)]
    assets, summary = analyze(findings)
    return ScanResult(
        tool_version="0.1.0",
        scan_id="cbom-real-fixture",
        started_at="2026-09-14T10:00:00Z",
        finished_at="2026-09-14T10:00:42Z",
        inputs=["cloud-posture", "sample-repos"],
        findings=findings,
        assets=assets,
        summary=summary,
    )


def _by_ref(cbom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {component["bom-ref"]: component for component in cbom["components"]}


def _prop(component: dict[str, Any], name: str) -> str | None:
    values = [p["value"] for p in component.get("properties", []) if p["name"] == f"quantumtrace:{name}"]
    return values[0] if values else None


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_every_scan_result_fixture_strict_validates(path: Path) -> None:
    result = ScanResult.model_validate_json(path.read_text())
    assert validate_cbom(build_cbom(result)) == []


def test_real_scanner_output_strict_validates() -> None:
    result = _real_result()
    cbom = build_cbom(result)
    assert validate_cbom(cbom) == []
    assert len(_by_ref(cbom)) == len(cbom["components"])


def test_envelope_and_determinism() -> None:
    result = _sample()
    cbom = build_cbom(result)
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", cbom["serialNumber"])
    assert cbom["metadata"]["timestamp"] == result.finished_at
    assert build_cbom(result) == cbom


def test_components_are_assets_materials_and_libraries_only() -> None:
    result = _sample()
    cbom = build_cbom(result)
    kms = [f for f in result.findings if f.kind_hint == KindHint.KEY and f.detector == "cloud.kms"]
    libraries = [f for f in result.findings if f.kind_hint == KindHint.LIBRARY]
    assert len(cbom["components"]) == len(result.assets) + len(kms) + len(libraries)
    refs = _by_ref(cbom)
    assert all(asset.asset_id in refs for asset in result.assets)
    hygiene_ids = {f.id for f in result.findings if f.extra.get("hygiene_only")}
    assert not any(ref == f"material-{fid}" or ref == f"library-{fid}" for fid in hygiene_ids for ref in refs)


def test_one_related_material_per_kms_key_references_its_algorithm() -> None:
    result = _sample()
    cbom = build_cbom(result)
    kms = [f for f in result.findings if f.kind_hint == KindHint.KEY and f.detector == "cloud.kms"]
    assert len(kms) == 10
    refs = _by_ref(cbom)
    owner = {fid: asset.asset_id for asset in result.assets for fid in asset.finding_ids}
    for finding in kms:
        material = refs[f"material-{finding.id}"]
        props = material["cryptoProperties"]
        assert props["assetType"] == "related-crypto-material"
        rcm = props["relatedCryptoMaterialProperties"]
        assert rcm["id"] == finding.location.resource_id
        assert rcm["algorithmRef"] == owner[finding.id] and rcm["algorithmRef"] in refs
        assert _prop(material, "tier") is None
        assert material["name"] == finding.extra["alias"]


def test_key_material_without_classified_algorithm_has_no_reference() -> None:
    result = _sample()
    finding = next(f for f in result.findings if f.kind_hint == KindHint.KEY and f.detector == "cloud.kms")
    stripped = result.model_copy(deep=True)
    for asset in stripped.assets:
        asset.finding_ids = [fid for fid in asset.finding_ids if fid != finding.id]
    cbom = build_cbom(stripped)
    material = _by_ref(cbom)[f"material-{finding.id}"]
    assert "algorithmRef" not in material["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert validate_cbom(cbom) == []


def test_tier_and_test_code_only_are_properties() -> None:
    result = _sample()
    result.assets[0].in_test_code_only = True  # the kit has no test-path code, so mark one asset
    refs = _by_ref(build_cbom(result))
    assert {_prop(refs[a.asset_id], "tier") for a in result.assets} <= {
        "CRITICAL",
        "MEDIUM",
        "SAFE",
        "UNKNOWN",
    }
    test_only = {a.asset_id for a in result.assets if a.in_test_code_only}
    assert test_only == {result.assets[0].asset_id}
    for asset in result.assets:
        expected = "true" if asset.asset_id in test_only else None
        assert _prop(refs[asset.asset_id], "testCodeOnly") == expected


def test_unknown_tier_never_becomes_quantum_level_zero() -> None:
    result = _sample()
    refs = _by_ref(build_cbom(result))
    for asset in result.assets:
        props = refs[asset.asset_id]["cryptoProperties"].get("algorithmProperties", {})
        assert props.get("nistQuantumSecurityLevel") == (asset.nist_quantum_level if props else None)
    unknown = next(a for a in result.assets if a.tier.value == "UNKNOWN" and a.nist_quantum_level is None)
    assert "nistQuantumSecurityLevel" not in refs[unknown.asset_id]["cryptoProperties"].get(
        "algorithmProperties", {}
    )


def test_session_protocol_asset_carries_version_and_byte_split_suite_identifiers() -> None:
    result = _sample()
    refs = _by_ref(build_cbom(result))
    suites = [
        (refs[a.asset_id]["cryptoProperties"]["protocolProperties"], suite)
        for a in result.assets
        if a.asset_type == "protocol"
        for suite in refs[a.asset_id]["cryptoProperties"]["protocolProperties"].get("cipherSuites", [])
    ]
    proto, suite = next((p, s) for p, s in suites if s["name"] == "TLS_AES_256_GCM_SHA384")
    assert proto["type"] == "tls" and proto["version"] == "TLS 1.3"
    assert suite["identifiers"] == ["0x13", "0x02"] and set(suite["algorithms"]) <= set(refs)
    policies = [
        a
        for a in result.assets
        if a.asset_type == "protocol" and any(o.source_type == "loadbalancer" for o in a.occurrences)
    ]
    assert policies
    assert all(
        "cipherSuites" not in refs[a.asset_id]["cryptoProperties"]["protocolProperties"] for a in policies
    )


def test_components_become_dependencies() -> None:
    result = _sample()
    cbom = build_cbom(result)
    deps = {d["ref"]: d["dependsOn"] for d in cbom["dependencies"]}
    assert set(deps) == {a.asset_id for a in result.assets if a.components}
    assert all(deps[a.asset_id] == a.components for a in result.assets if a.components)


def test_library_component_has_purl_and_evidence() -> None:
    cbom = build_cbom(_sample())
    library = next(c for c in cbom["components"] if c["type"] == "library")
    assert (library["name"], library["version"]) == ("cryptography", "46.0.5")
    assert library["purl"] == "pkg:pypi/cryptography@46.0.5"
    assert library["evidence"]["occurrences"][0]["location"]


@pytest.mark.parametrize(
    ("raw_name", "language", "snippet", "version", "purl"),
    [
        ("PyJWT==2.8.0", "python", "PyJWT==2.8.0", "2.8.0", "pkg:pypi/PyJWT@2.8.0"),
        ("PyJWT", "python", "PyJWT", None, "pkg:pypi/PyJWT"),
        ("PyJWT", "python", "PyJWT>=2.8", None, "pkg:pypi/PyJWT"),
        ("org.bouncycastle:bcprov-jdk18on", "java", "<version>[1.70,)</version>", None, None),
        ("golang.org/x/crypto", "go", "golang.org/x/crypto v0.31.0", None, "pkg:golang/golang.org/x/crypto"),
    ],
    ids=["pinned", "unpinned", "range", "maven-range", "go-unversioned"],
)
def test_library_component_for_pinned_unpinned_and_range_declarations(
    raw_name: str, language: str, snippet: str, version: str | None, purl: str | None
) -> None:
    result = _sample()
    finding = next(f for f in result.findings if f.kind_hint == KindHint.LIBRARY)
    finding.raw_name, finding.language, finding.location.snippet = raw_name, language, snippet
    cbom = build_cbom(result)
    library = next(c for c in cbom["components"] if c["type"] == "library")
    assert library["name"] == raw_name.partition("==")[0]
    assert library.get("version") == version and library.get("purl") == purl
    assert library["evidence"]["occurrences"][0]["additionalContext"] == snippet
    assert validate_cbom(cbom) == []


def test_certificate_dates_and_signature_algorithm_come_from_the_finding() -> None:
    result = _sample()
    cbom = build_cbom(result)
    refs = _by_ref(cbom)
    cert = next(
        refs[a.asset_id]
        for a in result.assets
        if a.asset_type == "certificate"
        and refs[a.asset_id]["cryptoProperties"]["certificateProperties"]["subjectName"]
        == "legacy-tcp.internal.example.com"
    )
    props = cert["cryptoProperties"]["certificateProperties"]
    assert props["notValidAfter"] == "2026-08-01T23:59:59Z"
    assert _prop(cert, "signatureAlgorithm") == "SHA1WITHRSA"
    assert "signatureAlgorithmRef" not in props


def test_strict_validation_rejects_what_the_schema_catches() -> None:
    cbom = build_cbom(_sample())
    unknown_key = copy.deepcopy(cbom)
    unknown_key["components"][0]["bogus"] = 1
    assert any("bogus" in error for error in validate_cbom(unknown_key))
    bad_primitive = copy.deepcopy(cbom)
    bad_primitive["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] = "sha"
    assert any("primitive" in error for error in validate_cbom(bad_primitive))


def test_validation_rejects_duplicate_and_dangling_references_the_schema_misses() -> None:
    cbom = build_cbom(_sample())
    duplicate = copy.deepcopy(cbom)
    clone = copy.deepcopy(duplicate["components"][0])
    clone["name"] = "another name"
    duplicate["components"].append(clone)
    assert validate_cbom(duplicate) == [f"duplicate bom-ref: {clone['bom-ref']}"]
    dangling = copy.deepcopy(cbom)
    dangling["dependencies"].append({"ref": "no-such-asset"})
    assert validate_cbom(dangling) == ["dangling reference: no-such-asset"]
    material = copy.deepcopy(cbom)
    next(c for c in material["components"] if c["bom-ref"].startswith("material-"))["cryptoProperties"][
        "relatedCryptoMaterialProperties"
    ]["algorithmRef"] = "no-such-algorithm"
    assert validate_cbom(material) == ["dangling reference: no-such-algorithm"]
