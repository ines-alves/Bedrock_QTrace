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


def test_python_jose_name_table_is_reported_without_a_library_import():
    # python-jose jose/constants.py names the algorithms in a class table and never says jwt or jose.
    source = 'import hashlib\n\nclass Algorithms:\n    HS256 = "HS256"\n    RS512 = "RS512"\n'
    got = {(f.raw_name, f.usage) for f in scan(source, "python")}
    assert got == {("HS256", Usage.MAC), ("RS512", Usage.SIGNATURE)}
    assert scan('label = "RS256"\n', "python") == []


def test_python_cipher_attribute_read_is_not_a_use_and_variable_mode_call_is():
    # python-jose cryptography_backend.py: algorithms.AES.block_size next to Cipher(algorithms.AES(k), mode).
    source = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "IV = {'CBC': algorithms.AES.block_size // 8}\n"
        "def f(key, mode):\n"
        "    return Cipher(algorithms.AES(key), mode)\n"
    )
    got = [(f.location.line, f.raw_name, f.mode, f.extra["rule"]) for f in scan(source, "python")]
    assert got == [(4, "AES", None, "PY_AES_CIPHER_MODE_UNRESOLVED")]
    literal = "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nc = Cipher(algorithms.AES(k), modes.GCM(iv))\n"
    assert [(f.mode, f.extra["rule"]) for f in scan(literal, "python")] == [("GCM", "PY_AES_CIPHER")]


# ---- tool comparison follow-ups (oqs-scanner, cryptosweep on 12 public repos) ------------------


def test_go_rsa_sign_accepts_a_field_key_and_hmac_with_runtime_hash_is_reported():
    source = (
        'package p\nimport (\n\t"crypto/hmac"\n\t"crypto/rsa"\n)\n'
        "func f() {\n"
        "\tout, err := rsa.SignPKCS1v15(randReader, ctx.privateKey, hash, hashed)\n"
        "\tmac := hmac.New(ctx.hash, ctx.key)\n"
        "\tother := hmac.New(sha256.New, key)\n"
        "}\n"
    )
    got = [(f.location.line, f.raw_name, f.usage, f.extra["rule"]) for f in scan(source, "go")]
    assert (7, "RSA", Usage.SIGNATURE, "GO_RSA_SIGN") in got
    assert (8, "HMAC", Usage.MAC, "GO_HMAC_UNRESOLVED") in got
    assert not any(line == 9 and rule == "GO_HMAC_UNRESOLVED" for line, _, _, rule in got)


def test_python_ec_generation_with_variable_curve_and_edwards_key_loading():
    source = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
        "a = ec.generate_private_key(curve, backend=default_backend())\n"
        "b = ec.generate_private_key(\n    curve=cls.DSS_CURVES[crv](),\n)\n"
        "c = ec.generate_private_key(ec.SECP384R1())\n"
        "d = Ed25519PrivateKey.from_private_bytes(raw)\n"
        "e = X25519PublicKey.from_public_bytes(peer)\n"
        "CURVE = ec.SECP384R1()\n"
        "f = ec.generate_private_key(CURVE)\n"
    )
    got = [(f.location.line, f.raw_name, f.usage, f.extra["rule"]) for f in scan(source, "python")]
    assert (3, "EC", Usage.UNKNOWN, "PY_EC_GENERATE_UNRESOLVED") in got
    assert (4, "EC", Usage.UNKNOWN, "PY_EC_GENERATE_UNRESOLVED") in got
    assert not any(rule == "PY_EC_GENERATE_UNRESOLVED" and line == 7 for line, _, _, rule in got)
    assert (8, "Ed25519", Usage.SIGNATURE, "PY_EDWARDS_KEY_LOAD") in got
    assert (9, "X25519", Usage.KEY_EXCHANGE, "PY_X25519") in got
    assert (10, "EC", Usage.UNKNOWN, "PY_EC_CURVE") in got
    assert not any(line == 11 for line, _, _, _ in got)


def test_python_rsa_padding_table_is_a_reference_only_for_asymmetric_padding():
    table = (
        "from cryptography.hazmat.primitives.asymmetric import padding\n"
        "ALGS = [RSA1_5(padding.PKCS1v15()), RSA_OAEP(padding.OAEP(mgf, h, None))]\n"
    )
    got = {(f.raw_name, f.padding, f.usage) for f in scan(table, "python")}
    assert got == {("RSA", "PKCS1v15", Usage.UNKNOWN), ("RSA", "OAEP", Usage.ENCRYPTION)}
    symmetric = "from cryptography.hazmat.primitives import padding\np = padding.PKCS7(128)\n"
    assert scan(symmetric, "python") == []
    called = table + "sig = key.sign(msg, padding.PSS(mgf, 32), hashes.SHA256())\n"
    assert not any(
        f.extra["rule"].endswith("_REFERENCE") for f in scan(called, "python") if f.raw_name == "RSA"
    )


# ---- second tool comparison (10 more repos, cbomkit-theia) ----------------------------------------


def test_python_hashlib_passed_as_a_value_is_a_reference_but_a_rejection_list_is_not():
    source = (
        "import hashlib, hmac\n"
        "def otp(secret, digest=hashlib.sha1):\n"
        "    if digest in [hashlib.md5, hashlib.shake_128]:\n"
        "        raise ValueError\n"
        "    return hmac.new(secret, b'x', hashlib.sha256)\n"
    )
    got = [(f.location.line, f.raw_name, f.extra["rule"]) for f in scan(source, "python")]
    assert got == [(2, "sha1", "PY_HASHLIB_REFERENCE"), (5, "HMAC-sha256", "PY_HMAC")]


def test_python_positional_rsa_generation_with_a_variable_size():
    source = "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(e, size, b)\n"
    (finding,) = scan(source, "python")
    assert (finding.raw_name, finding.key_size, finding.confidence) == ("RSA", None, 0.5)


@pytest.mark.parametrize(
    "language,source,expected",
    [
        ("java", 'String k = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow";\n', "RSA"),
        ("go", "const k = `-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----`\n", "EC"),
        ("python", 'K = """-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"""\n', "unresolved"),
    ],
)
def test_private_keys_embedded_in_source_are_key_material_and_never_shown(language, source, expected):
    (finding,) = scan(source, language)
    assert finding.raw_name == expected and finding.kind_hint.value == "key"
    assert finding.extra["hygiene_flags"] == ["private_key_material"]
    assert "MIIE" not in (finding.location.snippet or "") and "MHcC" not in (finding.location.snippet or "")


def test_private_key_header_in_a_comment_is_documentation():
    assert scan("// -----BEGIN RSA PRIVATE KEY----- example\nclass A {}\n", "java") == []
