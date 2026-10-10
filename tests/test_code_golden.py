"""Code section of tests/golden/expected.yaml (M3D-11): schema validity and agreement with the scanner.

The rows are written from Appendix D.4, M1M3-08 and PLAN 7.1, not from scanner output. Agreement is checked
one to one within LINE_TOLERANCE. A mismatch is a finding to report, never a reason to edit a row or a rule
to fit. Tier is the engine's, so it is checked against the PLAN 7.1 table, not against the scanner.
"""

import json
from collections import Counter
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner
from quantumtrace.scanners.code.manifests import ManifestScanner

ROOT = Path(__file__).parent.parent
KIT = ROOT / "sample-repos"
GOLDEN = ROOT / "tests" / "golden" / "expected.yaml"
SCHEMA = ROOT / "docs" / "golden.schema.json"
LINE_TOLERANCE = 2

# PLAN 7.1: canonical -> (tier, classically_broken)
POLICY = {
    "MD5": ("MEDIUM", True),
    "SHA-1": ("MEDIUM", True),
    "RSA-1024": ("CRITICAL", True),
    "Ed25519": ("CRITICAL", False),
    "AES-128": ("MEDIUM", False),
    "AES-256": ("SAFE", False),
    "SHA-384": ("SAFE", False),
    "HMAC-SHA256": ("SAFE", False),
    "PBKDF2": ("SAFE", False),
}

# Golden spelling of the raw names the code scanner emits (PLAN D.4 names). SHA1withRSA is a composite:
# RSA signature plus a SHA-1 digest component, as M1's decomposition (M1M3-03) produces it.
HASHES = {"md5": "MD5", "sha1": "SHA-1", "sha-1": "SHA-1", "sha384": "SHA-384", "sha-384": "SHA-384"}
MACS = {"hmac-sha256": "HMAC-SHA256", "hmacsha256": "HMAC-SHA256"}
KDFS = {"pbkdf2-hmac-sha256", "pbkdf2withhmacsha256"}


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return yaml.safe_load(GOLDEN.read_text())


@pytest.fixture(scope="module")
def findings() -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for path in sorted(KIT.rglob("*")):
        if path.suffix in {".py", ".java", ".go"}:
            results = list(CodeScanner().scan(path, KIT))
            assert all(isinstance(f, Finding) for f in results), results
            out["sample-repos/" + path.relative_to(KIT).as_posix()] = results
    return out


@pytest.fixture(scope="module")
def library_findings() -> dict[str, list[Finding]]:
    scanner = ManifestScanner()
    out: dict[str, list[Finding]] = {}
    for path in sorted(KIT.rglob("*")):
        if path.is_file() and scanner.can_handle(path):
            results = list(scanner.scan(path, KIT))
            assert all(isinstance(f, Finding) for f in results), results
            out["sample-repos/" + path.relative_to(KIT).as_posix()] = results
    return out


def is_hygiene(finding: Finding) -> bool:
    return bool(finding.extra.get("hygiene_only"))


def components(finding: Finding) -> list[tuple[str, str]]:
    """(canonical, usage) atoms of one raw finding, in golden spelling."""
    raw = finding.raw_name.lower()
    usage = finding.usage.value if finding.usage else "unknown"
    size = finding.key_size
    if raw in HASHES:
        return [(HASHES[raw], "hash")]
    if raw in MACS:
        return [(MACS[raw], "mac")]
    if raw in KDFS:
        return [("PBKDF2", "kdf")]
    if raw == "ed25519":
        return [("Ed25519", usage)]
    if raw == "rsa":
        return [(f"RSA-{size}", usage)]
    if raw == "sha1withrsa":
        return [(f"RSA-{size}", usage), ("SHA-1", "hash")]
    if raw in {"aes", "aesgcm"} or raw.startswith("aes/"):
        return [(f"AES-{size}", usage)]
    raise AssertionError(f"no golden spelling for raw_name {finding.raw_name!r}")


def match(expected: list[tuple], found: list[tuple], key) -> tuple[list[tuple], list[tuple]]:
    """One to one match on key(row) equality and line within LINE_TOLERANCE; (missing, unexpected)."""
    unused = list(found)
    missing = []
    for want in expected:
        cands = [g for g in unused if key(g) == key(want) and abs(g[0] - want[0]) <= LINE_TOLERANCE]
        if not cands:
            missing.append(want)
            continue
        unused.remove(min(cands, key=lambda g: (abs(g[0] - want[0]), g[0])))
    return missing, unused


def test_rows_validate_against_the_schema(rows):
    schema = json.loads(SCHEMA.read_text())
    errors = list(Draft202012Validator(schema).iter_errors(rows))
    assert not errors, [e.message for e in errors[:5]]


def test_every_row_is_a_code_row_for_a_kit_file(rows, findings, library_findings):
    assert rows
    for row in rows:
        assert row["source_type"] == "code", row
        assert row["source"] in findings or row["source"] in library_findings, row


def test_library_rows_agree_with_manifest_scanner(rows, library_findings):
    want = [
        (r["source"], r["line"], r["raw_name"])
        for r in rows
        if r["kind"] == "finding" and r["kind_hint"] == "library"
    ]
    got = [(source, f.location.line, f.raw_name) for source, found in library_findings.items() for f in found]
    assert sorted(got) == sorted(want)


def test_asset_tiers_and_flags_follow_the_plan_7_1_policy(rows):
    for row in (r for r in rows if r["kind"] == "asset"):
        tier, broken = POLICY[row["canonical"]]
        assert (row["tier"], row["classically_broken"]) == (tier, broken), row
        assert "hndl_exposed" not in row


def test_rows_carry_no_key_material(rows):
    text = GOLDEN.read_text()
    for needle in ("BEGIN", "PRIVATE KEY", "b'", 'b"'):
        assert needle not in text


@pytest.mark.parametrize(
    "source",
    sorted(
        {
            "sample-repos/" + p.relative_to(KIT).as_posix()
            for p in KIT.rglob("*")
            if p.suffix in {".py", ".java", ".go"}
        }
    ),
)
def test_file_rows_agree_with_scanner(source, rows, findings):
    found = findings[source]
    want_assets = [
        (r["line"], r["canonical"], r["usage"])
        for r in rows
        if r["kind"] == "asset" and r["source"] == source
    ]
    got_assets = [(f.location.line, c, u) for f in found if not is_hygiene(f) for c, u in components(f)]
    missing, unexpected = match(want_assets, got_assets, key=lambda t: t[1:])
    assert not missing, f"{source}: asset rows with no finding: {missing}"
    assert not unexpected, f"{source}: findings with no asset row: {unexpected}"

    want_flags = [
        (
            r["line"],
            r["kind_hint"],
            r["raw_name"],
            tuple(r["extra"]["hygiene_flags"]),
            r["extra"]["hygiene_only"],
        )
        for r in rows
        if r["kind"] == "finding" and r["source"] == source
    ]
    got_flags = [
        (
            f.location.line,
            f.kind_hint.value,
            f.raw_name,
            tuple(f.extra["hygiene_flags"]),
            f.extra["hygiene_only"],
        )
        for f in found
        if is_hygiene(f)
    ]
    missing, unexpected = match(want_flags, got_flags, key=lambda t: t[1:])
    assert not missing, f"{source}: finding rows with no finding: {missing}"
    assert not unexpected, f"{source}: hygiene findings with no row: {unexpected}"

    counts = [r["count"] for r in rows if r["kind"] == "count" and r["source"] == source]
    assert counts == [len(found)], f"{source}: count rows {counts}, scanner emitted {len(found)}"


def test_one_count_row_per_kit_file(rows, findings):
    per_file = Counter(r["source"] for r in rows if r["kind"] == "count")
    assert set(per_file) == set(findings)
    assert set(per_file.values()) == {1}


def test_go_pbkdf2_has_two_occurrences_of_one_asset(rows):
    rows_ = [
        r for r in rows if r["source"] == "sample-repos/go/auth-gateway/main.go" and r["kind"] == "asset"
    ]
    assert [(r["canonical"], r["line"]) for r in rows_] == [("PBKDF2", 25), ("PBKDF2", 34)]
