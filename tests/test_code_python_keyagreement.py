"""X25519, X448 and ECDH key agreement rules (task 6, Python slice 1)."""

from pathlib import Path

from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan(source: str) -> list[Finding]:
    return scan_source(source, "app.py", "python", load_rules("python"))


def names(findings: list[Finding]) -> list[tuple[str, int]]:
    return [(f.raw_name, f.location.line) for f in findings]


def test_fixture_reports_each_key_agreement_site() -> None:
    path = FIXTURES / "python" / "key_agreement.py"
    found = [r for r in CodeScanner().scan(path, FIXTURES) if isinstance(r, Finding)]
    assert names(found) == [
        ("X25519", 6),
        ("X25519", 10),
        ("X25519", 14),
        ("X448", 18),
        ("ECDH", 22),
    ]
    assert all(f.usage is Usage.KEY_EXCHANGE and f.kind_hint.value == "algorithm" for f in found)
    assert all(f.curve is None and f.key_size is None for f in found)


def test_private_key_loading_is_reported() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import x25519, x448\n"
        "a = x25519.X25519PrivateKey.from_private_bytes(raw)\n"
        "b = x448.X448PublicKey.from_public_bytes(raw)\n"
    )
    assert names(scan(src)) == [("X25519", 2), ("X448", 3)]


def test_aliases_and_from_imports_resolve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import x25519 as X, ec as E\n"
        "from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey as K\n"
        "from cryptography.hazmat.primitives.asymmetric.ec import ECDH\n"
        "a = X.X25519PrivateKey.generate()\n"
        "b = K.generate()\n"
        "c = k.exchange(E.ECDH(), p)\n"
        "d = k.exchange(ECDH(), p)\n"
    )
    assert names(scan(src)) == [("X25519", 4), ("X448", 5), ("ECDH", 6), ("ECDH", 7)]


def test_exchange_call_without_ecdh_class_emits_nothing() -> None:
    src = "from cryptography.hazmat.primitives.asymmetric import ec\nshared = key.exchange(algo, peer)\n"
    assert scan(src) == []


def test_user_defined_names_do_not_match() -> None:
    src = "def X25519PrivateKeyFactory():\n    return None\nx = my_x25519.generate()\n"
    assert scan(src) == []
