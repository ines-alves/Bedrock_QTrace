from pathlib import Path

from quantumtrace.engine import analyze
from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan(relative: str) -> list[Finding]:
    results = list(CodeScanner().scan(FIXTURES / relative, FIXTURES))
    assert all(isinstance(r, Finding) for r in results), results
    return [r for r in results if isinstance(r, Finding)]


def test_java_eddsa_generation_is_signature_usage():
    got = [(f.raw_name, f.location.line, f.usage, f.extra["rule"]) for f in scan("java/EdKeyGeneration.java")]
    assert got == [
        ("Ed25519", 8, Usage.SIGNATURE, "JAVA_KEYPAIR_EDDSA"),
        ("Ed448", 12, Usage.SIGNATURE, "JAVA_KEYPAIR_EDDSA"),
        ("EdDSA", 16, Usage.SIGNATURE, "JAVA_KEYPAIR_EDDSA"),
        ("Ed448", 20, Usage.SIGNATURE, "JAVA_KEYPAIR_EDDSA_REF"),
        ("XDH", 24, Usage.UNKNOWN, "JAVA_KEYPAIR_OTHER"),
        ("unresolved", 28, Usage.UNKNOWN, "JAVA_KEYPAIR_UNRESOLVED"),
    ]


def test_ed25519_generation_and_signing_are_one_signature_asset():
    findings = scan("java/Signatures.java")
    assets, _ = analyze([f for f in findings if f.raw_name == "Ed25519"])
    assert len(assets) == 1
    assert assets[0].usage.value == "signature"
    assert len(assets[0].occurrences) == 2


def test_scrypt_is_reported_as_the_kdf_alone():
    findings = scan("python/scrypt.py")
    assert [(f.raw_name, f.location.line) for f in findings] == [
        ("scrypt", 7),
        ("scrypt", 11),
        ("scrypt", 15),
        ("scrypt", 19),
    ]
    for finding in findings:
        assert finding.usage == Usage.KDF
        assert finding.library == "hashlib"
        assert finding.key_size is None
        assert "iterations" not in finding.extra
        assert "correct horse" not in finding.location.snippet


def test_scrypt_through_the_engine_is_safe_kdf():
    assets, _ = analyze(scan("python/scrypt.py"))
    assert [(a.canonical_name, a.tier.value, a.usage.value) for a in assets] == [("scrypt", "SAFE", "kdf")]
