"""PyCryptodome rules (task 6, Python): Crypto.* and Cryptodome.*."""

from pathlib import Path

from quantumtrace.engine import analyze
from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan_fixture(name: str) -> list[Finding]:
    path = FIXTURES / "python" / name
    return [f for f in CodeScanner().scan(path, FIXTURES) if isinstance(f, Finding)]


def scan(source: str) -> list[Finding]:
    return scan_source(source, "app.py", "python", load_rules("python"))


def by_rule(findings: list[Finding], prefix: str) -> list[Finding]:
    return [f for f in findings if str(f.extra["rule"]).startswith(prefix)]


def by_id(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.extra["rule"] == rule_id]


def test_symmetric_ciphers_sizes_and_modes() -> None:
    found = scan_fixture("pycryptodome.py")
    aes = [
        (f.location.line, f.key_size, f.mode, f.extra.get("key_size_source"), f.confidence)
        for f in found
        if f.extra["rule"] == "PYC_AES_NEW"
    ]
    assert aes == [
        (13, 256, "GCM", "flow", 0.8),
        (18, 128, "CBC", "literal", 1.0),
        (22, None, "ECB", "unresolved", 0.5),
        (26, 128, "EAX", "constant", 1.0),
    ]
    legacy = [(f.location.line, f.raw_name) for f in found if f.extra["rule"] == "PYC_LEGACY_CIPHER"]
    assert legacy == [(30, "DES"), (31, "DES3"), (32, "ARC4")]


def test_hard_coded_key_warnings_are_redacted_and_paired() -> None:
    found = scan_fixture("pycryptodome.py")
    warnings = [f for f in found if "hardcoded_key" in f.extra.get("hygiene_flags", [])]
    assert [f.location.line for f in warnings] == [7, 18]
    for f in found:
        assert "0123456789abcdef" not in f.location.snippet
        assert "fedcba9876543210" not in f.location.snippet


def test_hashes_hmac_and_pbkdf2() -> None:
    found = scan_fixture("pycryptodome.py")
    assert [f.raw_name for f in by_rule(found, "PYC_HASH")] == ["MD5", "SHA1", "SHA256", "SHA3_256"]
    assert [(f.location.line, f.raw_name) for f in by_id(found, "PYC_HMAC")] == [
        (41, "HMAC-SHA256"),
        (42, "HMAC-SHA1"),
    ]
    assert [(f.location.line, f.raw_name) for f in by_id(found, "PYC_PBKDF2")] == [
        (48, "PBKDF2-HMAC-SHA256"),
        (49, "PBKDF2-HMAC-SHA1"),
    ]


def test_dsa_and_ecc_keys() -> None:
    found = scan_fixture("pycryptodome.py")
    keys = [
        (f.location.line, f.raw_name, f.usage, f.key_size, f.curve)
        for f in found
        if f.extra["rule"].startswith(("PYC_DSA", "PYC_ECC"))
    ]
    assert keys == [
        (55, "DSA", Usage.SIGNATURE, 2048, None),
        (56, "EC", Usage.UNKNOWN, None, "P-256"),
        (57, "Ed25519", Usage.SIGNATURE, None, None),
        (58, "X25519", Usage.KEY_EXCHANGE, None, None),
        (59, "EC", Usage.UNKNOWN, None, "p384"),
    ]


def test_rsa_generation_usage_follows_the_sinks() -> None:
    found = scan_fixture("pycryptodome_rsa.py")
    got = [
        (f.location.line, f.usage, f.key_size, f.padding, f.extra.get("usage_source"))
        for f in found
        if f.raw_name == "RSA"
    ]
    assert got == [
        (8, Usage.SIGNATURE, 2048, None, "flow"),
        (9, Usage.SIGNATURE, 2048, "PKCS1v15", None),
        (13, Usage.UNKNOWN, 3072, None, None),
        (14, Usage.ENCRYPTION, 3072, "OAEP", None),
    ]


def test_one_key_used_for_signing_and_encryption_stays_unknown() -> None:
    found = [f for f in scan_fixture("pycryptodome_rsa_mixed.py") if f.raw_name == "RSA"]
    assert [(f.location.line, f.usage) for f in found] == [
        (7, Usage.UNKNOWN),
        (8, Usage.SIGNATURE),
        (9, Usage.ENCRYPTION),
    ]
    assert all("usage_source" not in f.extra for f in found)


def test_assets_through_the_engine() -> None:
    findings = scan_fixture("pycryptodome.py") + scan_fixture("pycryptodome_rsa.py")
    assets, _ = analyze(findings)
    seen = {(a.canonical_name, a.key_size, a.usage.value, a.tier.value) for a in assets}
    assert ("AES", 256, "encryption", "SAFE") in seen
    assert ("MD5", None, "hash", "MEDIUM") in seen
    assert ("RSA", 2048, "signature", "CRITICAL") in seen
    assert ("DSA", 2048, "signature", "CRITICAL") in seen
    assert ("Ed25519", None, "signature", "CRITICAL") in seen
    assert ("X25519", None, "key_exchange", "CRITICAL") in seen


def test_cryptodome_namespace_and_aliases() -> None:
    src = (
        "from Cryptodome.Cipher import AES as A\n"
        "from Cryptodome.Hash import SHA256 as S, HMAC as H\n"
        "from Cryptodome.PublicKey import RSA as R\n"
        "x = A.new(b'0123456789abcdef0123456789abcdef', A.MODE_CTR, nonce=n)\n"
        "y = H.new(k, m, digestmod=S)\n"
        "z = S.new(m)\n"
        "w = R.generate(bits=4096)\n"
    )
    got = [
        (f.raw_name, f.location.line, f.key_size, f.mode)
        for f in scan(src)
        if f.raw_name != "hard-coded symmetric key"
    ]
    assert got == [
        ("AES", 4, 256, "CTR"),
        ("HMAC-SHA256", 5, None, None),
        ("SHA256", 6, None, None),
        ("RSA", 7, 4096, None),
    ]


def test_dotted_import_and_kdf_module_forms() -> None:
    src = (
        "import Crypto.Hash.SHA512\n"
        "from Crypto.Protocol import KDF\n"
        "a = Crypto.Hash.SHA512.new(b'x')\n"
        "b = KDF.PBKDF2(p, s, 32, 1000, hmac_hash_module=Crypto.Hash.SHA512)\n"
    )
    assert [(f.raw_name, f.location.line) for f in scan(src)] == [("SHA512", 3), ("PBKDF2-HMAC-SHA512", 4)]


def test_names_of_other_libraries_are_not_reported() -> None:
    src = (
        "from passlib.utils.pbkdf2 import pbkdf2\n"
        "from mylib import MD5, HMAC, AES, RSA\n"
        "a = MD5.new(b'x')\n"
        "b = HMAC.new(k, m, digestmod=MD5)\n"
        "c = AES.new(k, AES.MODE_GCM)\n"
        "d = RSA.generate(2048)\n"
        "e = PBKDF2(p, s, 32, 1000, hmac_hash_module=SHA256)\n"
    )
    assert scan(src) == []


def test_unresolved_values_and_a_prf_callable_emit_nothing() -> None:
    src = (
        "from Crypto.Protocol.KDF import PBKDF2\n"
        "from Crypto.PublicKey import ECC\n"
        "c = PBKDF2(password, salt, 32, 1000, prf=my_prf)\n"
        "d = ECC.generate(curve=name)\n"
    )
    assert scan(src) == []


def test_legacy_pkcs1_v1_5_module_is_decided_by_its_import() -> None:
    sign = (
        "from Crypto.Signature import PKCS1_v1_5\n"
        "from Crypto.PublicKey import RSA\n"
        "k = RSA.generate(2048)\n"
        "s = PKCS1_v1_5.new(k)\n"
    )
    crypt = sign.replace("Crypto.Signature", "Crypto.Cipher")
    both = "from Crypto.Cipher import PKCS1_v1_5\n" + sign
    usages = lambda text: [f.usage for f in scan(text) if f.extra["rule"].startswith("PYC_RSA_PKCS1")]  # noqa: E731
    assert usages(sign) == [Usage.SIGNATURE]
    assert usages(crypt) == [Usage.ENCRYPTION]
    assert usages(both) == []
