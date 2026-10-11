"""Outside-validation rules: Java KeyFactory, RSA transformation names in constants and enums, and
ChaCha20-Poly1305 in Python (spring-security RsaKeyConverters and RsaAlgorithm, authlib JWE drafts)."""

import time

import pytest

from quantumtrace.engine import analyze
from quantumtrace.models import Tier
from quantumtrace.scanners.code.engine import load_rules, scan_source


def scan(source: str, language: str):
    suffix = "py" if language == "python" else language
    return scan_source(source, f"app/source.{suffix}", language, load_rules(language))


def names(found):
    return [f.raw_name for f in found]


# ---- Java KeyFactory --------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm", ["RSA", "EC", "DSA", "DH", "Ed25519", "X25519"])
def test_key_factory_literal_is_one_reference_without_size_or_usage(algorithm):
    found = scan(
        f'class A {{ void f() throws Exception {{\n KeyFactory.getInstance("{algorithm}");\n}} }}', "java"
    )
    assert names(found) == [algorithm]
    hit = found[0]
    assert hit.confidence <= 0.6
    assert hit.key_size is None
    assert hit.location.line == 2


def test_key_factory_rsa_is_critical():
    found = scan('class A { void f() throws Exception { KeyFactory.getInstance("RSA"); } }', "java")
    assets, _ = analyze(found)
    assert [(a.canonical_name, a.tier) for a in assets] == [("RSA", Tier.CRITICAL)]


def test_key_factory_yields_to_a_key_generation_of_the_same_file():
    found = scan(
        "class A { void f() throws Exception {\n"
        ' KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n g.initialize(2048);\n'
        ' KeyFactory kf = KeyFactory.getInstance("RSA");\n} }',
        "java",
    )
    assert names(found) == ["RSA"]
    assert found[0].key_size == 2048


def test_key_factory_resolves_a_file_scope_constant():
    found = scan(
        'class A { static final String ALGO = "RSA"; void f() throws Exception { KeyFactory.getInstance(ALGO); } }',
        "java",
    )
    assert names(found) == ["RSA"]
    assert found[0].confidence <= 0.6


@pytest.mark.parametrize("argument", ["name", "this.algorithm", "getAlgorithm()", '"Unknown"', '"PKCS12"'])
def test_key_factory_unresolved_or_unlisted_name_emits_nothing(argument):
    found = scan(
        f"class A {{ void f(String name) throws Exception {{ KeyFactory.getInstance({argument}); }} }}",
        "java",
    )
    assert found == []


def test_key_factory_in_a_comment_is_ignored():
    assert scan('class A {\n // KeyFactory.getInstance("RSA")\n}', "java") == []


# ---- RSA transformation names -----------------------------------------------------------------


def test_rsa_enum_constants_are_reported_once_each():
    found = scan(
        'public enum RsaAlgorithm {\n\tDEFAULT("RSA", 117),\n\tOAEP("RSA/ECB/OAEPPadding", 86);\n}', "java"
    )
    assert sorted((f.raw_name, f.location.line) for f in found) == [
        ("RSA", 2),
        ("RSA/ECB/OAEPPadding", 3),
    ]
    assert all(f.confidence <= 0.6 for f in found)
    assets, _ = analyze(found)
    assert {a.tier for a in assets} == {Tier.CRITICAL}


def test_rsa_transform_in_a_constant_is_reported_once_with_its_call():
    found = scan(
        'class A { static final String T = "RSA/ECB/PKCS1Padding";\n'
        " void f() throws Exception { Cipher.getInstance(T); } }",
        "java",
    )
    assert names(found) == ["RSA/ECB/PKCS1Padding"]


def test_rsa_transform_literal_in_a_call_stays_one_call_finding():
    found = scan(
        'class A { void f() throws Exception { Cipher.getInstance("RSA/ECB/OAEPPadding"); } }', "java"
    )
    assert names(found) == ["RSA/ECB/OAEPPadding"]


@pytest.mark.parametrize(
    "source",
    [
        'class A { static final String TYPE_VALUE = "RSA"; }',
        'class A { String kty = "RSA"; }',
        'class A { boolean f(String s) { return "RSA".equals(s); } }',
        'class A { Map<String, Integer> m = Map.of("RSA", 2048); }',
        'class A {\n // OAEP("RSA/ECB/OAEPPadding", 86)\n}',
    ],
)
def test_bare_rsa_label_or_comment_is_not_a_use(source):
    assert scan(source, "java") == []


# ---- Python ChaCha20-Poly1305 -----------------------------------------------------------------

AEAD_IMPORT = "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n"


@pytest.mark.parametrize(
    "source,line",
    [
        (AEAD_IMPORT + "def f(key):\n    return ChaCha20Poly1305(key)\n", 3),
        (AEAD_IMPORT + "key = ChaCha20Poly1305.generate_key()\n", 2),
        ("from Cryptodome.Cipher import ChaCha20_Poly1305\nc = ChaCha20_Poly1305.new(key=k)\n", 2),
    ],
)
def test_chacha20poly1305_use_is_one_safe_finding(source, line):
    found = scan(source, "python")
    assert names(found) == ["ChaCha20-Poly1305"]
    assert found[0].location.line == line
    assert found[0].confidence == 1.0
    assets, _ = analyze(found)
    assert [(a.canonical_name, a.tier) for a in assets] == [("ChaCha20-Poly1305", Tier.SAFE)]


@pytest.mark.parametrize(
    "source",
    [
        "from cryptography import x\nclass ChaCha20Poly1305(Base):\n    pass\n",
        "def f(key):\n    return ChaCha20Poly1305(key)\n",
        "import cryptography\n# ChaCha20Poly1305(key)\n",
        AEAD_IMPORT,
    ],
)
def test_chacha20poly1305_definition_unrelated_name_or_import_only_is_not_a_call(source):
    assert names(scan(source, "python")) == []


# ---- cost -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "language,line",
    [
        ("java", "KeyFactory.getInstance(" + "a" * 200_000),
        ("java", '"RSA/' + "A" * 200_000),
        ("java", "X(" * 100_000),
        ("python", "ChaCha20Poly1305" * 20_000),
        ("python", "ChaCha20_Poly1305" + "." * 200_000),
    ],
)
def test_new_patterns_do_not_backtrack_on_long_lines(language, line):
    rules = [
        rule
        for rule in load_rules(language)
        if rule.id
        in {
            "JAVA_KEY_FACTORY",
            "JAVA_KEY_FACTORY_REF",
            "JAVA_RSA_TRANSFORM_NAME",
            "JAVA_RSA_ENUM_NAME",
            "PY_CHACHA20POLY1305",
        }
    ]
    assert rules
    source = f"import cryptography\n{line}\n"
    started = time.perf_counter()
    scan_source(source, "app/source.java" if language == "java" else "app/source.py", language, rules)
    assert time.perf_counter() - started < 2.0


def test_key_factory_eddsa_name_is_reported_once_by_the_signature_name_rule():
    found = scan('class A { void f() throws Exception { KeyFactory.getInstance("Ed25519"); } }', "java")
    assert names(found) == ["Ed25519"]


def test_chacha20_poly1305_pycryptodome_import_alias_is_resolved():
    found = scan("from Cryptodome.Cipher import ChaCha20_Poly1305 as CP\ncipher = CP.new(key=k)\n", "python")
    assert names(found) == ["ChaCha20-Poly1305"]
