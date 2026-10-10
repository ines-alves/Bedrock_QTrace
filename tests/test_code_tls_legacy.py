"""Configured obsolete TLS versions, Go DES and RC4, and Go InsecureSkipVerify (M3M4-09 to M3M4-11)."""

from pathlib import Path

from quantumtrace.engine import analyze
from quantumtrace.models import Finding, KindHint, Tier, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def fixture(language: str, name: str) -> list[Finding]:
    return [f for f in CodeScanner().scan(FIXTURES / language / name, FIXTURES) if isinstance(f, Finding)]


SUFFIX = {"python": "py", "java": "java", "go": "go"}


def scan(language: str, source: str) -> list[Finding]:
    return scan_source(source, f"app.{SUFFIX[language]}", language, load_rules(language))


def names(findings: list[Finding]) -> list[tuple[str, int]]:
    return [(f.raw_name, f.location.line) for f in findings]


# ---------------------------------------------------------------- fixtures


def test_python_fixture_reports_each_legacy_version_once_with_one_spelling() -> None:
    found = fixture("python", "tls_versions.py")
    assert [(f.raw_name, f.location.line, f.extra["source_constant"]) for f in found] == [
        ("TLS 1.0", 5, "ssl.PROTOCOL_TLSv1"),
        ("TLS 1.1", 10, "ssl.TLSVersion.TLSv1_1"),
        ("SSLv3", 16, "ssl.TLSVersion.SSLv3"),
        ("TLS 1.0", 22, "ssl.TLSVersion.TLSv1"),
    ]
    assert all(f.kind_hint is KindHint.PROTOCOL_VERSION and f.usage is Usage.UNKNOWN for f in found)
    assert all(f.negotiated is None for f in found)


def test_java_fixture_reports_literals_and_resolved_constants_only() -> None:
    found = fixture("java", "TlsVersions.java")
    assert [(f.raw_name, f.location.line, f.extra["source_constant"]) for f in found] == [
        ("TLS 1.0", 8, "TLSv1"),
        ("TLS 1.1", 12, "TLSv1.1"),
        ("SSLv3", 16, "SSLv3"),
    ]
    assert found[1].extra["resolved_from_line"] == 5


def test_go_fixture_reports_settings_not_comparisons() -> None:
    found = fixture("go", "tls_versions.go")
    assert [(f.raw_name, f.location.line, f.extra["source_constant"]) for f in found] == [
        ("TLS 1.0", 8, "tls.VersionTLS10"),
        ("TLS 1.1", 13, "tls.VersionTLS11"),
        ("SSLv3", 14, "tls.VersionSSL30"),
    ]


def test_go_des_and_rc4_fixture() -> None:
    found = fixture("go", "legacy_ciphers.go")
    assert [(f.raw_name, f.location.line, f.usage, f.key_size) for f in found] == [
        ("DES", 9, Usage.ENCRYPTION, None),
        ("TripleDES", 13, Usage.ENCRYPTION, None),
        ("RC4", 17, Usage.ENCRYPTION, None),
    ]


def test_go_skip_verify_fixture_is_hygiene_only_for_the_literal_true() -> None:
    found = fixture("go", "skip_verify.go")
    assert [f.location.line for f in found] == [8, 13]
    for f in found:
        assert f.extra["hygiene_only"] is True
        assert f.extra["hygiene_flags"] == ["tls_verify_disabled"]
        assert f.kind_hint is KindHint.POLICY


# ---------------------------------------------------------------- negatives and aliases


def test_python_constants_that_disable_or_negotiate_emit_nothing() -> None:
    src = (
        "import ssl\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3\n"
        "ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"
        "legacy = ssl.SSLContext(ssl.PROTOCOL_SSLv23)\n"
    )
    assert scan("python", src) == []


def test_python_import_aliases_resolve_to_the_same_findings() -> None:
    src = (
        "import ssl as s\n"
        "from ssl import PROTOCOL_TLSv1, TLSVersion\n"
        "A = s.PROTOCOL_TLSv1_1\n"
        "B = PROTOCOL_TLSv1\n"
        "C = TLSVersion.SSLv3\n"
    )
    assert names(scan("python", src)) == [("TLS 1.1", 3), ("TLS 1.0", 4), ("SSLv3", 5)]


def test_python_comments_are_not_findings() -> None:
    src = "import ssl\n# ssl.PROTOCOL_TLSv1 is gone\n"
    assert scan("python", src) == []


def test_java_unresolved_or_modern_protocols_emit_nothing() -> None:
    src = (
        "class A {\n"
        "  void f(String p) throws Exception {\n"
        '    SSLContext.getInstance("TLSv1.2");\n'
        '    SSLContext.getInstance("TLSv1.3");\n'
        '    SSLContext.getInstance("TLS");\n'
        '    SSLContext.getInstance("SSL");\n'
        "    SSLContext.getInstance(p);\n"
        "  }\n"
        "}\n"
    )
    assert scan("java", src) == []


def test_go_bare_references_and_tls_without_import_emit_nothing() -> None:
    src = (
        "package main\n"
        'import "crypto/tls"\n'
        "func f(v uint16) bool {\n"
        "\tswitch v {\n"
        "\tcase tls.VersionTLS10:\n"
        "\t\treturn true\n"
        "\t}\n"
        "\tcfg := &tls.Config{MinVersion: tls.VersionTLS12}\n"
        "\treturn cfg.MinVersion == tls.VersionTLS10\n"
        "}\n"
    )
    assert scan("go", src) == []
    other = "package main\nfunc f() {\n\tcfg := Config{MinVersion: tls.VersionTLS10}\n\t_ = cfg\n}\n"
    assert scan("go", other) == []


def test_go_des_and_rc4_need_the_import() -> None:
    src = "package main\nfunc f(key []byte) {\n\tdes.NewCipher(key)\n\trc4.NewCipher(key)\n}\n"
    assert scan("go", src) == []


def test_go_skip_verify_needs_the_literal_true_and_ignores_comments() -> None:
    src = (
        "package main\n"
        'import "crypto/tls"\n'
        "func f(skip bool) {\n"
        "\t// InsecureSkipVerify: true\n"
        "\t_ = &tls.Config{InsecureSkipVerify: false}\n"
        "\t_ = &tls.Config{InsecureSkipVerify: skip}\n"
        "\t_ = &tls.Config{InsecureSkipVerify: trueValue}\n"
        "}\n"
    )
    assert scan("go", src) == []


# ---------------------------------------------------------------- through the engine


def test_through_the_engine_versions_are_broken_unscored_and_one_asset_per_version() -> None:
    findings = (
        fixture("python", "tls_versions.py")
        + fixture("java", "TlsVersions.java")
        + fixture("go", "tls_versions.go")
    )
    assets, _ = analyze(findings)
    by_name = {a.canonical_name: a for a in assets}
    assert set(by_name) == {"TLS 1.0", "TLS 1.1", "SSLv3"}
    for asset in by_name.values():
        assert asset.tier is Tier.UNKNOWN
        assert asset.classically_broken is True
        assert asset.max_points == 0


def test_through_the_engine_des_and_rc4_are_medium_and_broken() -> None:
    assets, _ = analyze(fixture("go", "legacy_ciphers.go"))
    got = {a.canonical_name: (a.tier, a.classically_broken) for a in assets}
    assert got == {
        "DES": (Tier.MEDIUM, True),
        "3DES": (Tier.MEDIUM, True),
        "RC4": (Tier.MEDIUM, True),
    }


def test_through_the_engine_skip_verify_is_a_visible_unscored_warning() -> None:
    assets, _ = analyze(fixture("go", "skip_verify.go"))
    assert len(assets) == 1
    assert assets[0].tier is Tier.UNKNOWN and assets[0].max_points == 0
