"""Java KeyAgreement, KEM, EC curves, DH and DSA sizes, ML-KEM and ML-DSA, and constant-argument factories
(task 6, Java slice)."""

from pathlib import Path

from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan(source: str) -> list[Finding]:
    return scan_source(source, "App.java", "java", load_rules("java"))


def fixture(name: str, language: str = "java") -> list[Finding]:
    return [r for r in CodeScanner().scan(FIXTURES / language / name, FIXTURES) if isinstance(r, Finding)]


def test_agreement_curve_size_and_pqc_fixture() -> None:
    got = [
        (f.raw_name, f.location.line, f.usage, f.curve, f.key_size, f.confidence)
        for f in fixture("KeyAgreements.java")
    ]
    assert got == [
        ("ECDH", 9, Usage.KEY_EXCHANGE, None, None, 1.0),
        ("XDH", 10, Usage.KEY_EXCHANGE, None, None, 1.0),
        ("DiffieHellman", 11, Usage.KEY_EXCHANGE, None, None, 1.0),
        ("EC", 15, Usage.UNKNOWN, "secp256r1", None, 0.8),
        ("EC", 20, Usage.UNKNOWN, None, None, 1.0),
        ("EC", 25, Usage.UNKNOWN, "secp384r1", None, 1.0),
        ("DH", 29, Usage.UNKNOWN, None, 2048, 0.8),
        ("DSA", 31, Usage.UNKNOWN, None, 1024, 0.8),
        ("ML-KEM-768", 36, Usage.KEY_EXCHANGE, None, None, 1.0),
        ("ML-DSA-65", 37, Usage.UNKNOWN, None, None, 1.0),
        ("ML-DSA", 38, Usage.SIGNATURE, None, None, 1.0),
        ("SHA256withECDSA", 42, Usage.SIGNATURE, None, None, 1.0),
    ]


def test_ec_curve_spec_is_reported_once_next_to_its_generator() -> None:
    src = (
        'KeyPairGenerator g = KeyPairGenerator.getInstance("EC");\n'
        'g.initialize(new ECGenParameterSpec("secp521r1"));\n'
    )
    found = scan(src)
    assert [(f.raw_name, f.location.line, f.curve) for f in found] == [("EC", 1, "secp521r1")]
    assert '"EC"' in (found[0].location.snippet or "")


def test_ec_curve_does_not_cross_into_another_method() -> None:
    src = (
        "void a() {\n"
        '    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");\n'
        "}\n"
        "void b() {\n"
        '    h.initialize(new ECGenParameterSpec("secp256r1"));\n'
        "}\n"
    )
    assert [(f.raw_name, f.location.line, f.curve) for f in scan(src)] == [
        ("EC", 2, None),
        ("EC", 5, "secp256r1"),
    ]


def test_constant_arguments_resolve_through_file_constants() -> None:
    got = [
        (f.raw_name, f.location.line, f.usage, f.key_size, f.extra.get("resolved_from_line"))
        for f in fixture("ConstantFactories.java")
    ]
    assert got == [
        ("SHA-1", 20, Usage.HASH, None, 10),
        ("HmacSHA256", 21, Usage.MAC, None, 11),
        ("PBKDF2WithHmacSHA1", 22, Usage.KDF, None, 12),
        ("RSA", 23, Usage.UNKNOWN, 1024, 13),
        ("SHA256withRSA", 25, Usage.SIGNATURE, None, 14),
        ("Ed25519", 26, Usage.SIGNATURE, None, 15),
        ("ECDH", 27, Usage.KEY_EXCHANGE, None, 16),
    ]


def test_unresolved_constants_emit_nothing() -> None:
    src = (
        "class A {\n"
        "    void f(String name) throws Exception {\n"
        "        MessageDigest.getInstance(name);\n"
        "        Mac.getInstance(name);\n"
        "        KeyAgreement.getInstance(name);\n"
        "        KEM.getInstance(name);\n"
        "        KeyPairGenerator.getInstance(name);\n"
        "        Signature.getInstance(name);\n"
        "    }\n"
        "}\n"
    )
    assert scan(src) == []


def test_aes_key_generator_constant_gives_a_key_size_source_only() -> None:
    src = (
        'class A { static final String ALGO = "AES";\n'
        "  void f() throws Exception {\n"
        "    KeyGenerator kg = KeyGenerator.getInstance(ALGO);\n"
        "    kg.init(256);\n"
        "  } }\n"
    )
    assert scan(src) == []


def test_comments_emit_nothing() -> None:
    src = '// KeyAgreement.getInstance("ECDH");\n/* KEM.getInstance("ML-KEM"); */\n'
    assert scan(src) == []


def test_unresolved_name_never_satisfies_values_must_match() -> None:
    # session 21 engine change: an identifier that does not resolve is dropped even when its spelling
    # would match the regex (PY_HASHLIB_NEW lists md5).
    src = "import hashlib\n\n\ndef f(md5):\n    return hashlib.new(md5)\n"
    assert scan_source(src, "a.py", "python", load_rules("python")) == []
