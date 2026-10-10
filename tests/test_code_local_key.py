"""A literal assigned to a local that reaches an AES key sink is a hard-coded key (M1M3-12)."""

from pathlib import Path

from quantumtrace.engine import analyze
from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"
LITERALS = ("0123456789abcdef", "fedcba9876543210")


def scan_fixture(language: str, name: str) -> list[Finding]:
    path = FIXTURES / language / name
    return [f for f in CodeScanner().scan(path, FIXTURES) if isinstance(f, Finding)]


def warnings(findings: list[Finding]) -> list[int]:
    return [f.location.line for f in findings if "hardcoded_key" in f.extra.get("hygiene_flags", [])]


def sized(findings: list[Finding]) -> list[tuple[int, int | None, str | None, float, int | None]]:
    return [
        (
            f.location.line,
            f.key_size,
            f.extra.get("key_size_source"),
            f.confidence,
            f.extra.get("resolved_from_line"),
        )
        for f in findings
        if not f.extra.get("hygiene_only")
    ]


def test_python_local_literal_keys() -> None:
    found = scan_fixture("python", "local_key.py")
    assert warnings(found) == [9, 15, 24]
    assert sized(found) == [
        (10, 128, "flow", 0.8, 9),
        (16, 256, "flow", 0.8, 15),
        (20, 128, "flow", 0.8, 24),
        (31, None, "unresolved", 0.5, None),
        (37, None, "unresolved", 0.5, None),
        (42, 256, "flow", 0.8, None),
        (47, None, "unresolved", 0.5, None),
        (53, 128, "flow", 0.8, None),
    ]


def test_go_local_literal_keys() -> None:
    found = scan_fixture("go", "local_key.go")
    assert warnings(found) == [9, 15, 26]
    assert sized(found) == [
        (10, 128, "flow", 0.8, 9),
        (16, 256, "flow", 0.8, 15),
        (21, 128, "flow", 0.8, 26),
        (33, None, "unresolved", 0.5, None),
        (40, 256, "flow", 0.8, None),
        (48, 128, "flow", 0.8, None),
    ]


def test_java_local_literal_keys() -> None:
    found = scan_fixture("java", "LocalKey.java")
    assert warnings(found) == [8, 23]
    assert sized(found) == [
        (10, 128, "flow", 0.8, 8),
        (17, 256, "flow", 0.8, 23),
        (31, None, "unresolved", 0.5, None),
        (39, None, "unresolved", 0.5, None),
    ]


def test_warning_is_bounded_and_redacted() -> None:
    for language, name in (("python", "local_key.py"), ("go", "local_key.go"), ("java", "LocalKey.java")):
        for f in scan_fixture(language, name):
            for literal in LITERALS:
                assert literal not in f.location.snippet
                assert literal not in str(f.extra)
            if "hardcoded_key" in f.extra.get("hygiene_flags", []):
                assert f.confidence <= 0.8
                assert f.location.snippet.count("<redacted>") == 1


def test_plaintext_literal_and_other_functions_do_not_leak() -> None:
    found = scan_fixture("python", "local_key.py")
    assert 52 not in warnings(found)
    assert not any(line > 24 for line in warnings(found))


def test_same_name_in_two_functions_stays_separate() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "\n"
        "def a(n):\n"
        '    key = b"0123456789abcdef"\n'
        "    return AESGCM(key).encrypt(n, b'', None)\n"
        "\n"
        "def b(n, key):\n"
        "    return AESGCM(key).encrypt(n, b'', None)\n"
    )
    found = scan_source(src, "app.py", "python", load_rules("python"))
    assert warnings(found) == [4]
    assert [(f.location.line, f.key_size) for f in found if not f.extra.get("hygiene_only")] == [
        (5, 128),
        (8, None),
    ]


def test_through_the_engine() -> None:
    findings = (
        scan_fixture("python", "local_key.py")
        + scan_fixture("go", "local_key.go")
        + scan_fixture("java", "LocalKey.java")
    )
    assets, _ = analyze(findings)
    sizes = {a.key_size for a in assets if a.key_size is not None and "AES" in a.canonical_name}
    assert {128, 256} <= sizes


def test_go_function_local_var_is_not_a_file_scope_constant() -> None:
    src = (
        "package main\n"
        "\n"
        'import "crypto/aes"\n'
        "\n"
        "func a() {\n"
        '\tvar k = []byte("0123456789abcdef")\n'
        "\t_ = k\n"
        "}\n"
        "\n"
        "func b(k []byte) {\n"
        "\tblock, _ := aes.NewCipher(k)\n"
        "\t_ = block\n"
        "}\n"
    )
    found = scan_source(src, "app.go", "go", load_rules("go"))
    assert [(f.location.line, f.key_size, f.extra.get("key_size_source")) for f in found] == [
        (11, None, "unresolved")
    ]
    assert warnings(found) == []
