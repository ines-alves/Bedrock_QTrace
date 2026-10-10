"""crypto/ecdsa, crypto/ecdh, x/crypto/curve25519 and crypto/mlkem rules (task 6, Go slice)."""

from pathlib import Path

from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan(source: str) -> list[Finding]:
    return scan_source(source, "app.go", "go", load_rules("go"))


def fixture(name: str) -> list[Finding]:
    return [r for r in CodeScanner().scan(FIXTURES / "go" / name, FIXTURES) if isinstance(r, Finding)]


def test_ec_fixture_reports_each_site_with_curve_as_seen() -> None:
    got = [(f.raw_name, f.location.line, f.curve, f.usage) for f in fixture("ec_keys.go")]
    assert got == [
        ("ECDSA", 13, "P256", Usage.SIGNATURE),
        ("ECDSA", 17, "P384", Usage.SIGNATURE),
        ("ECDSA", 21, None, Usage.SIGNATURE),
        ("ECDSA", 25, None, Usage.SIGNATURE),
        ("ECDSA", 29, None, Usage.SIGNATURE),
        ("ECDH", 33, "P256", Usage.KEY_EXCHANGE),
        ("X25519", 37, None, Usage.KEY_EXCHANGE),
        ("X25519", 41, None, Usage.KEY_EXCHANGE),
    ]


def test_ec_fixture_has_no_import_only_findings_and_no_key_size() -> None:
    found = fixture("ec_keys.go")
    assert all(f.confidence == 1.0 for f in found)
    assert all(f.key_size is None for f in found)


def test_mlkem_fixture_keeps_the_parameter_set() -> None:
    got = [(f.raw_name, f.location.line, f.usage) for f in fixture("mlkem.go")]
    assert got == [
        ("ML-KEM-768", 6, Usage.KEY_EXCHANGE),
        ("ML-KEM-1024", 10, Usage.KEY_EXCHANGE),
        ("ML-KEM-768", 14, Usage.KEY_EXCHANGE),
    ]


def test_import_only_findings_use_the_package_and_confidence() -> None:
    found = fixture("imports_ec.go")
    got = sorted((f.raw_name, f.location.line, f.confidence) for f in found)
    assert got == [
        ("ECDH", 5, 0.6),
        ("ECDSA", 4, 0.6),
        ("ML-KEM", 6, 0.6),
        ("X25519", 8, 0.6),
    ]
    assert all(f.library for f in found)


def test_call_wins_over_import() -> None:
    src = (
        "package main\n"
        'import "crypto/ecdsa"\n'
        'import "crypto/mlkem"\n'
        "func f() {\n"
        "\t_, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)\n"
        "\t_, _ = mlkem.GenerateKey1024()\n"
        "}\n"
    )
    assert [(f.raw_name, f.location.line, f.curve) for f in scan(src)] == [
        ("ECDSA", 5, "P521"),
        ("ML-KEM-1024", 6, None),
    ]


def test_unrelated_calls_and_comments_emit_nothing() -> None:
    src = (
        "package main\n"
        "// ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n"
        "func f() {\n"
        "\t_ = other.GenerateKey768()\n"
        "\t_ = mlkem.SharedKeySize\n"
        "\t_ = elliptic.P256()\n"
        "\t_ = ecdh.P1024()\n"
        "}\n"
    )
    assert scan(src) == []
