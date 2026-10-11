from pathlib import Path

from quantumtrace.engine import analyze
from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan_fixture() -> list[Finding]:
    results = list(CodeScanner().scan(FIXTURES / "python" / "pbkdf2_hashlib.py", FIXTURES))
    assert all(isinstance(r, Finding) for r in results), results
    return results


def test_hashlib_pbkdf2_hmac_findings():
    got = [(f.raw_name, f.location.line, f.extra["rule"]) for f in scan_fixture()]
    assert got == [
        ("PBKDF2-HMAC-sha256", 10, "PY_HASHLIB_PBKDF2_HMAC"),
        ("PBKDF2-HMAC-sha1", 14, "PY_HASHLIB_PBKDF2_HMAC"),
        ("PBKDF2-HMAC-sha384", 18, "PY_HASHLIB_PBKDF2_HMAC"),
        ("PBKDF2-HMAC-sha512", 22, "PY_HASHLIB_PBKDF2_HMAC"),
        ("PBKDF2-HMAC-sha256", 26, "PY_HASHLIB_PBKDF2_HMAC"),
        ("PBKDF2-HMAC-sha256", 30, "PY_HASHLIB_PBKDF2_HMAC"),
        ("PBKDF2", 34, "PY_HASHLIB_PBKDF2_HMAC_UNRESOLVED"),
        ("PBKDF2-HMAC-sha256", 46, "PY_HASHLIB_PBKDF2_HMAC"),
    ]


def test_findings_are_kdf_algorithms_from_hashlib():
    for finding in scan_fixture():
        assert finding.usage.value == "kdf"
        assert finding.kind_hint.value == "algorithm"
        assert finding.library == "hashlib"
        assert finding.key_size is None


def test_constant_name_carries_the_constant_line():
    finding = next(f for f in scan_fixture() if f.location.line == 22)
    assert finding.extra["resolved_from_line"] == 5
    assert finding.confidence == 1.0


def test_unknown_and_foreign_calls_emit_nothing_and_unresolved_hash_is_pbkdf2():
    findings = scan_fixture()
    assert not {f.location.line for f in findings} & {38, 42, 50}
    (unresolved,) = [f for f in findings if f.location.line == 34]
    got = (unresolved.raw_name, unresolved.confidence, unresolved.extra["iterations"])
    assert got == ("PBKDF2", 0.5, 600_000)


def test_password_literal_is_not_visible_in_the_snippet():
    finding = next(f for f in scan_fixture() if f.location.line == 46)
    assert "correct horse" not in finding.location.snippet
    assert "sha256" in finding.location.snippet


def test_not_reported_twice_as_a_plain_hash():
    names = sorted(f.raw_name for f in scan_fixture())
    assert not any(name in ("sha256", "sha1", "SHA256", "SHA1") for name in names)


def test_through_the_engine_sha1_follows_the_underlying_hash():
    assets, _ = analyze([f for f in scan_fixture() if f.location.line in (10, 14)])
    assert sorted((a.canonical_name, a.tier.value, a.usage.value) for a in assets) == [
        ("PBKDF2", "MEDIUM", "kdf"),
        ("PBKDF2", "SAFE", "kdf"),
    ]
