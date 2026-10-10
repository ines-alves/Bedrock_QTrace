"""DH and DSA generation rules (task 6, Python slice 3)."""

from pathlib import Path

from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan(source: str) -> list[Finding]:
    return scan_source(source, "app.py", "python", load_rules("python"))


def test_fixture_reports_size_and_usage() -> None:
    path = FIXTURES / "python" / "dh_dsa.py"
    found = [r for r in CodeScanner().scan(path, FIXTURES) if isinstance(r, Finding)]
    got = [(f.raw_name, f.location.line, f.key_size, f.usage, f.extra.get("key_size_source")) for f in found]
    assert got == [
        ("DH", 8, 2048, Usage.KEY_EXCHANGE, "literal"),
        ("DH", 12, 1024, Usage.KEY_EXCHANGE, "literal"),
        ("DH", 16, 3072, Usage.KEY_EXCHANGE, "constant"),
        ("DSA", 20, 2048, Usage.SIGNATURE, "literal"),
        ("DSA", 24, 1024, Usage.SIGNATURE, "literal"),
        ("DSA", 28, 1024, Usage.SIGNATURE, "constant"),
        ("DSA", 32, 3072, Usage.SIGNATURE, "literal"),
        ("DSA", 36, 2048, Usage.SIGNATURE, "literal"),
    ]
    assert all(f.confidence == 1.0 for f in found)


def test_unresolved_size_is_none_and_capped() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import dh, dsa\n"
        "a = dh.generate_parameters(generator=2, key_size=bits)\n"
        "b = dsa.generate_private_key(size)\n"
    )
    found = scan(src)
    assert [(f.raw_name, f.key_size, f.extra.get("key_size_source")) for f in found] == [
        ("DH", None, "unresolved"),
        ("DSA", None, "unresolved"),
    ]
    assert all(f.confidence <= 0.5 for f in found)


def test_aliases_and_from_imports_resolve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import dh as D, dsa as S\n"
        "from cryptography.hazmat.primitives.asymmetric.dsa import generate_private_key\n"
        "a = D.generate_parameters(2, 2048)\n"
        "b = S.generate_private_key(key_size=1024)\n"
        "c = generate_private_key(3072)\n"
    )
    assert [(f.raw_name, f.location.line, f.key_size) for f in scan(src)] == [
        ("DH", 3, 2048),
        ("DSA", 4, 1024),
        ("DSA", 5, 3072),
    ]


def test_rsa_and_unrelated_calls_are_not_matched() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "a = rsa.generate_private_key(65537, 2048)\n"
        "b = other.generate_parameters(2, 2048)\n"
        "c = dh.load_pem_parameters(data)\n"
    )
    assert [f.raw_name for f in scan(src)] == ["RSA"]
