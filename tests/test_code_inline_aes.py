"""An inline literal key gives an AES finding next to the hard-coded key warning (task 6)."""

from pathlib import Path

from quantumtrace.engine import analyze
from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan_fixture(language: str, name: str) -> list[Finding]:
    path = FIXTURES / language / name
    return [f for f in CodeScanner().scan(path, FIXTURES) if isinstance(f, Finding)]


def aes(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if not f.extra.get("hygiene_only")]


def warnings(findings: list[Finding]) -> list[int]:
    return [f.location.line for f in findings if "hardcoded_key" in f.extra.get("hygiene_flags", [])]


def test_python_inline_literal_sizes_and_modes() -> None:
    found = scan_fixture("python", "inline_aes.py")
    got = [
        (f.raw_name, f.location.line, f.key_size, f.mode, f.extra.get("key_size_source"), f.confidence)
        for f in aes(found)
    ]
    assert got == [
        ("AES", 9, 128, "CBC", "literal", 1.0),
        ("AESGCM", 14, 256, "GCM", "literal", 1.0),
        ("AES", 18, 128, "ECB", "literal", 1.0),
        ("AESGCM", 22, 192, "GCM", "literal", 1.0),
        ("AESGCM", 26, None, "GCM", "unresolved", 0.5),
    ]
    assert warnings(found) == [9, 14, 18, 22]


def test_go_inline_literal_sizes_and_modes() -> None:
    found = scan_fixture("go", "inline_aes.go")
    got = [
        (f.location.line, f.key_size, f.mode, f.extra.get("key_size_source"), f.extra.get("mode_source"))
        for f in aes(found)
    ]
    assert got == [
        (11, 128, "GCM", "literal", None),
        (17, 256, None, "literal", None),
        (22, 128, "ECB", "literal", "block_loop"),
        (29, 128, None, "constant", None),
        (34, None, None, "unresolved", None),
    ]
    assert all(f.raw_name == "AES" for f in aes(found))
    assert [f.confidence for f in aes(found)] == [0.8, 1.0, 0.8, 1.0, 0.5]
    assert warnings(found) == [8, 11, 17, 22]


def test_literal_never_reaches_snippet_or_extra() -> None:
    for language, name in (("python", "inline_aes.py"), ("go", "inline_aes.go")):
        for f in scan_fixture(language, name):
            assert "0123456789abcdef" not in f.location.snippet
            assert "0123456789abcdef" not in str(f.extra)
            assert "fedcba9876543210" not in f.location.snippet


def test_aes_findings_through_the_engine() -> None:
    findings = scan_fixture("python", "inline_aes.py") + scan_fixture("go", "inline_aes.go")
    assets, _ = analyze(findings)
    sizes = {a.key_size for a in assets if a.canonical_name == "AES" and a.key_size is not None}
    assert sizes == {128, 192, 256}


def scan(language: str, source: str) -> list[Finding]:
    return scan_source(source, f"app.{language}", language, load_rules(language))


def test_expressions_that_are_not_one_literal_give_no_size() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        'a = AESGCM(b"0123456789abcdef" + salt)\n'
        'b = AESGCM(bytes.fromhex("00112233445566778899aabbccddeeff"))\n'
        "c = AESGCM(os.urandom(32))\n"
    )
    assert aes(scan("python", src)) == []


def test_hmac_and_other_key_arguments_are_not_aes() -> None:
    src = (
        "import hmac, hashlib\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        'tag = hmac.new(b"0123456789abcdef", m, hashlib.sha256)\n'
        'c = Cipher(algorithms.Camellia(b"0123456789abcdef"), modes.CBC(iv))\n'
    )
    assert [f.raw_name for f in scan("python", src)] == ["HMAC-sha256"]
    go = (
        "package main\n"
        'import ("crypto/hmac"; "crypto/sha256")\n'
        'func f() { _ = hmac.New(sha256.New, []byte("0123456789abcdef")) }\n'
    )
    assert [f.raw_name for f in scan("go", go)] == ["HMAC-sha256"]


def test_alias_and_keyword_forms() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher as C, algorithms as A, modes as M\n"
        'x = C(algorithm=A.AES(key=b"0123456789abcdef"), mode=M.CTR(nonce))\n'
    )
    got = [(f.raw_name, f.key_size, f.mode) for f in aes(scan("python", src))]
    assert got == [("AES", 128, "CTR")]


def test_single_quoted_bytes_literal() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "a = AESGCM(b'0123456789abcdef01234567')\n"
    )
    assert [(f.raw_name, f.key_size) for f in aes(scan("python", src))] == [("AESGCM", 192)]
