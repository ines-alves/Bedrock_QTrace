"""Offline regressions for the outside-data fallback and reference rules."""

import pytest

from quantumtrace.engine import analyze
from quantumtrace.models import Tier, Usage
from quantumtrace.scanners.code.engine import load_rules, scan_source


def scan(source: str, language: str):
    return scan_source(
        source, f"app/source.{'py' if language == 'python' else language}", language, load_rules(language)
    )


@pytest.mark.parametrize(
    "factory,usage",
    [
        ("MessageDigest", Usage.HASH),
        ("Mac", Usage.MAC),
        ("Signature", Usage.SIGNATURE),
        ("Cipher", Usage.ENCRYPTION),
        ("KeyAgreement", Usage.KEY_EXCHANGE),
        ("KeyPairGenerator", Usage.UNKNOWN),
        ("KeyGenerator", Usage.UNKNOWN),
        ("SecretKeyFactory", Usage.UNKNOWN),
        ("KEM", Usage.KEY_EXCHANGE),
    ],
)
@pytest.mark.parametrize("argument", ["name", "this.algorithm", "getAlgorithm()"])
def test_java_dynamic_factory_retains_one_unknown_call(factory, usage, argument):
    found = scan(f"class A {{ void f(String name) {{ {factory}.getInstance({argument}); }} }}", "java")
    assert len(found) == 1
    hit = found[0]
    assert (hit.raw_name, hit.usage, hit.confidence) == ("unresolved", usage, 0.5)
    assert hit.extra["unresolved_argument"] == argument
    assets, _ = analyze(found)
    assert all(asset.tier == Tier.UNKNOWN for asset in assets)


def test_java_resolved_constant_and_literal_each_emit_one_call():
    found = scan(
        'class A { static final String NAME = "SHA-256"; void f() {\n'
        'MessageDigest.getInstance(NAME);\nMessageDigest.getInstance("SHA-256");\n} }',
        "java",
    )
    assert [(f.raw_name, f.confidence) for f in found] == [("SHA-256", 1.0), ("SHA-256", 1.0)]
    assert all("unresolved_argument" not in f.extra for f in found)


def test_python_expression_fallbacks_preserve_usage_and_iterations():
    found = scan(
        "import hashlib, hmac\n"
        "def f(name, key, msg, digest, iterations=600000):\n"
        "    hashlib.new(name)\n"
        "    hashlib.pbkdf2_hmac(digest().name, key, msg, iterations)\n"
        "    hmac.new(key, msg, digest)\n",
        "python",
    )
    assert [(f.raw_name, f.usage, f.confidence) for f in found] == [
        ("unresolved", Usage.HASH, 0.5),
        ("PBKDF2", Usage.KDF, 0.5),
        ("HMAC", Usage.MAC, 0.5),
    ]
    assert [f.extra["unresolved_argument"] for f in found] == ["name", "digest().name", "digest"]
    assert found[1].extra["iterations"] == 600000


def test_python_cipher_reference_is_unsized_and_call_wins():
    found = scan(
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "table = [algorithms.AES, algorithms.ARC4, algorithms.TripleDES]\n"
        "cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))\n",
        "python",
    )
    refs = [f for f in found if f.extra["rule"] == "PY_CIPHER_CLASS_REFERENCE"]
    assert [(f.raw_name, f.key_size, f.confidence) for f in refs] == [
        ("ARC4", None, 0.6),
        ("TripleDES", None, 0.6),
    ]
    assert sum(f.raw_name == "AES" for f in found) == 1
    assert not scan("class algorithms: pass\nx = algorithms.ARC4\n", "python")


@pytest.mark.parametrize("module", ["primitives", "decrepit"])
def test_python_bare_cipher_import(module):
    found = scan(f"from cryptography.hazmat.{module}.ciphers.algorithms import TripleDES\n", "python")
    assert [(f.raw_name, f.confidence) for f in found] == [("TripleDES", 0.6)]


@pytest.mark.parametrize(
    "language,source",
    [
        ("python", 'import jwt\nnames = ["HS512", "RS256", "EdDSA"]\n'),
        (
            "java",
            "class A { Object a = JWSAlgorithm.HS512; Object b = Jwts.SIG.RS256; Object c = SignatureAlgorithm.EdDSA; }",
        ),
        (
            "go",
            "package p\nvar a = jwt.SigningMethodHS512\nvar b = jose.RS256\nvar c = jwt.SigningMethodEdDSA\n",
        ),
    ],
)
def test_jose_references_distinguish_mac_from_signature(language, source):
    found = scan(source, language)
    assert {(f.raw_name, f.usage, f.confidence) for f in found} == {
        ("HS512", Usage.MAC, 0.6),
        ("RS256", Usage.SIGNATURE, 0.6),
        ("EdDSA", Usage.SIGNATURE, 0.6),
    }
    assets, _ = analyze(found)
    assert any(a.tier == Tier.SAFE and a.usage == Usage.MAC for a in assets)
    assert any(a.tier == Tier.CRITICAL and a.usage == Usage.SIGNATURE for a in assets)


@pytest.mark.parametrize(
    "package,call,name,usage",
    [
        ("crypto/sha3", "sha3.New256()", "SHA3-256", Usage.HASH),
        ("crypto/sha3", "sha3.NewSHAKE128()", "SHAKE128", Usage.HASH),
        ("golang.org/x/crypto/sha3", "sha3.NewShake256()", "SHAKE256", Usage.HASH),
        ("golang.org/x/crypto/bcrypt", "bcrypt.GenerateFromPassword(p, 12)", "bcrypt", Usage.KDF),
        ("golang.org/x/crypto/argon2", "argon2.IDKey(p, salt, 1, 65536, 4, 32)", "Argon2id", Usage.KDF),
        ("golang.org/x/crypto/argon2", "argon2.Key(p, salt, 1, 65536, 4, 32)", "Argon2i", Usage.KDF),
        ("golang.org/x/crypto/scrypt", "scrypt.Key(p, salt, 32768, 8, 1, 32)", "scrypt", Usage.KDF),
        ("crypto/hkdf", "hkdf.Key(h, s, salt, info, 32)", "HKDF", Usage.KDF),
        ("golang.org/x/crypto/hkdf", "hkdf.New(h, s, salt, info)", "HKDF", Usage.KDF),
        (
            "golang.org/x/crypto/chacha20poly1305",
            "chacha20poly1305.New(key)",
            "ChaCha20-Poly1305",
            Usage.ENCRYPTION,
        ),
        (
            "golang.org/x/crypto/chacha20poly1305",
            "chacha20poly1305.NewX(key)",
            "XChaCha20-Poly1305",
            Usage.ENCRYPTION,
        ),
    ],
)
def test_go_added_apis_require_import_and_follow_kb_policy(package, call, name, usage):
    source = f'package p\nimport "{package}"\nfunc f() {{ {call} }}\n'
    found = [f for f in scan(source, "go") if f.confidence == 1.0]
    assert [(f.raw_name, f.usage) for f in found] == [(name, usage)]
    assets, _ = analyze(found)
    expected_tier = Tier.MEDIUM if name == "SHAKE128" else Tier.SAFE
    assert assets and all(a.tier == expected_tier for a in assets)
    assert not scan(f"package p\nfunc f() {{ {call} }}\n", "go")


@pytest.mark.parametrize("argument", ['"sha256"', "DIGEST", "digestmod=DIGEST"])
def test_python_hmac_resolved_digest_is_not_an_unresolved_fallback(argument):
    found = scan(f'import hmac\nDIGEST = "sha256"\nhmac.new(key, msg, {argument})\n', "python")
    assert [(f.raw_name, f.confidence) for f in found] == [("HMAC-sha256", 1.0)]
    assert "unresolved_argument" not in found[0].extra
