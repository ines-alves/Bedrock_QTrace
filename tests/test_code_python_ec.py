"""EC curve and ECDSA rules (task 6, Python slice 2)."""

from pathlib import Path

from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan(source: str) -> list[Finding]:
    return scan_source(source, "app.py", "python", load_rules("python"))


def test_fixture_reports_curves_and_ecdsa_sites() -> None:
    path = FIXTURES / "python" / "ec_keys.py"
    found = [r for r in CodeScanner().scan(path, FIXTURES) if isinstance(r, Finding)]
    got = [(f.raw_name, f.location.line, f.curve, f.usage) for f in found if f.usage is not Usage.HASH]
    assert got == [
        ("EC", 4, "SECP384R1", Usage.UNKNOWN),
        ("EC", 8, "SECP256R1", Usage.UNKNOWN),
        ("EC", 12, "SECP521R1", Usage.UNKNOWN),
        ("EC", 16, "SECP256K1", Usage.UNKNOWN),
        ("EC", 20, "BrainpoolP256R1", Usage.UNKNOWN),
        ("ECDSA", 28, None, Usage.SIGNATURE),
        ("ECDSA", 32, None, Usage.SIGNATURE),
    ]
    assert all(f.key_size is None for f in found)


def test_hash_argument_of_ecdsa_is_still_reported() -> None:
    src = (
        "from cryptography.hazmat.primitives import hashes\n"
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "sig = key.sign(data, ec.ECDSA(hashes.SHA1()))\n"
    )
    assert sorted(f.raw_name for f in scan(src)) == ["ECDSA", "SHA1"]


def test_aliases_and_from_imports_resolve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec as E\n"
        "from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, ECDSA\n"
        "a = E.generate_private_key(E.SECP256R1())\n"
        "b = SECP384R1()\n"
        "c = ECDSA(h)\n"
    )
    assert [(f.raw_name, f.location.line, f.curve) for f in scan(src)] == [
        ("EC", 3, "SECP256R1"),
        ("EC", 4, "SECP384R1"),
        ("ECDSA", 5, None),
    ]


def test_unknown_curve_names_and_other_modules_emit_nothing() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec, rsa\n"
        "a = ec.SECP999R1()\n"
        "b = other.SECP256R1()\n"
        "c = ec.EllipticCurvePublicKey\n"
    )
    assert scan(src) == []


def test_comment_mentions_emit_nothing() -> None:
    assert scan("# key = ec.generate_private_key(ec.SECP256R1())\n") == []
