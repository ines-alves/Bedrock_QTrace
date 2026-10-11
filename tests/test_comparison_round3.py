"""Third tool-comparison round (10 outside repos): engine names and code rules that were missed.

Sources: cfssl csr.go / key_agreement.go, jwx cmd/jwx/jwk.go, santuario DOMReference.java and
DOMSignatureMethod.java, mina-sshd BuiltinCiphers / BuiltinDHFactories, pyOpenSSL crypto.py.
"""

from datetime import UTC, datetime

import pytest

from quantumtrace.engine import analyze, classify_findings
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import Finding, KindHint, Location, SourceType, Tier, Usage
from quantumtrace.scanners.code.engine import load_rules, scan_source


@pytest.fixture(scope="module")
def kb():
    return load_kb()


def classify(kb, raw, kind=KindHint.ALGORITHM, usage=Usage.UNKNOWN, **updates):
    data = dict(
        id="x",
        raw_name=raw,
        kind_hint=kind,
        usage=usage,
        detector="fixture",
        location=Location(source_type=SourceType.CODE, file="a.java", line=1),
    )
    data.update(updates)
    return classify_findings([Finding(**data)], kb, datetime.now(UTC))[0]


def atoms(root):
    return {(row.node.normalized.identity.algorithm_id, row.tier) for row in root.walk()} - {
        (None, root.tier)
    }


# ---- engine (M1) --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,digest",
    [
        ("SHA256withRSAandMGF1", "SHA-256"),
        ("SHA1withRSAandMGF1", "SHA-1"),
        ("SHA3-512withRSAandMGF1", "SHA3-512"),
        ("SHA3-224withRSAandMGF1", "SHA3-224"),
    ],
)
def test_jca_mgf1_signature_names_are_rsa_pss(kb, name, digest):
    root = classify(kb, name)
    assert root.tier == Tier.CRITICAL
    rsa = next(row for row in root.walk() if row.node.normalized.identity.algorithm_id == "RSA")
    assert rsa.node.normalized.identity.parameters.padding == "pss"
    assert digest in {row.node.normalized.identity.algorithm_id for row in root.walk()}


def test_mgf1_suffix_is_rsa_only(kb):
    assert classify(kb, "SHA256withECDSAandMGF1").tier == Tier.UNKNOWN


@pytest.mark.parametrize("name,alg", [("SHA3-224withECDSA", "ECDSA"), ("SHA3-224withRSA", "RSA")])
def test_sha3_224_signature_names(kb, name, alg):
    root = classify(kb, name)
    assert root.tier == Tier.CRITICAL and {alg, "SHA3-224"} <= {a for a, _ in atoms(root)}


def test_iso10126_padding_transformation(kb):
    root = classify(kb, "AES/CBC/ISO10126Padding", usage=Usage.ENCRYPTION)
    assert ("AES", Tier.MEDIUM) in atoms(root)


def test_whirlpool_is_a_sourced_512_bit_hash(kb):
    assert classify(kb, "WHIRLPOOL", usage=Usage.HASH).tier == Tier.SAFE
    entry = kb.get("WHIRLPOOL")
    assert any("rfc6931" in source.url for source in entry.sources)


def test_oiw_sha1_with_rsa_certificate_signature(kb):
    root = classify(
        kb,
        "RSA",
        kind=KindHint.CERTIFICATE,
        usage=Usage.AUTHENTICATION,
        key_size=2048,
        extra={"signature_algorithm": "1.3.14.3.2.29"},
        location=Location(source_type=SourceType.KEYFILE, file="a.pem"),
    )
    assert ("SHA-1", Tier.MEDIUM) in atoms(root) and root.tier == Tier.CRITICAL


@pytest.mark.parametrize("name,parts", [("curve448-sha512", {"X448", "SHA-512"}), ("ssh-ed448", {"Ed448"})])
@pytest.mark.parametrize("source", [SourceType.CODE, SourceType.SSH])
def test_rfc8731_and_rfc8709_ssh_names(kb, name, parts, source):
    root = classify(kb, name, protocol="SSH", location=Location(source_type=source, file="a", line=1))
    assert root.tier == Tier.CRITICAL and parts <= {a for a, _ in atoms(root)}


# ---- code rules (M3 area) -----------------------------------------------------------------------


def scan(source, language):
    suffix = {"python": "py"}.get(language, language)
    return scan_source(source, f"app/source.{suffix}", language, load_rules(language))


def hits(found):
    return [(f.location.line, f.raw_name, f.extra.get("rule")) for f in found]


@pytest.mark.parametrize("size", ["kr.Size()", "*rsaBits", 'c.Int("keysize")'])
def test_go_rsa_generate_with_an_expression_size(size):
    found = scan(
        f'package p\nimport "crypto/rsa"\nfunc f() {{\n  rsa.GenerateKey(rand.Reader, {size})\n}}\n', "go"
    )
    rsa = [f for f in found if f.extra.get("rule") == "GO_RSA_GENERATE"]
    assert len(rsa) == 1 and rsa[0].key_size is None and rsa[0].location.line == 4


def test_go_rsa_generate_literal_size_still_read():
    found = scan("package p\nfunc f() { rsa.GenerateKey(rand.Reader, 2048) }\n", "go")
    assert [f.key_size for f in found if f.extra.get("rule") == "GO_RSA_GENERATE"] == [2048]


def test_go_elliptic_generation_and_encoding():
    found = scan(
        "package p\nfunc f() {\n"
        "  priv, x, y, err := elliptic.GenerateKey(ka.curve, config.rand())\n"
        "  pub := elliptic.Marshal(ka.curve, x, y)\n"
        "  k, _, _, _ := elliptic.GenerateKey(elliptic.P384(), r)\n}\n",
        "go",
    )
    rows = [(f.location.line, f.raw_name, f.curve) for f in found if f.extra.get("rule") == "GO_ELLIPTIC"]
    assert rows == [(3, "EC", None), (4, "EC", None), (5, "EC", "P384")]
    assets, _ = analyze(found)
    assert all(
        asset.tier == Tier.CRITICAL for asset in assets if asset.canonical_name.startswith(("EC", "ECDH"))
    )


def test_java_unresolved_call_split_across_lines_with_a_cast():
    found = scan(
        "class A { void f() throws Exception {\n"
        "  md = MessageDigest.getInstance\n"
        "      (((DOMDigestMethod)digestMethod).getMessageDigestAlgorithm());\n} }",
        "java",
    )
    assert [(raw, rule) for _, raw, rule in hits(found)] == [("unresolved", "JAVA_MESSAGE_DIGEST_UNRESOLVED")]


def test_java_transformation_literal_in_a_table_is_a_reference():
    found = scan(
        "enum C {\n"
        '  aes128cbc(Constants.AES128_CBC, 16, 0, "AES", 128, "AES/CBC/NoPadding", 16),\n'
        '  tdes(Constants.TDES, 8, 0, "DESede", 192, "DESede/CBC/NoPadding", 8);\n}',
        "java",
    )
    refs = [f for f in found if f.extra.get("rule") == "JAVA_TRANSFORMATION_LITERAL"]
    assert [f.raw_name for f in refs] == ["AES/CBC/NoPadding", "DESede/CBC/NoPadding"]
    assert all(f.confidence <= 0.6 for f in refs)


def test_java_transformation_inside_cipher_get_instance_is_not_doubled():
    found = scan('class A { void f() throws Exception { Cipher.getInstance("AES/GCM/NoPadding"); } }', "java")
    assert not [f for f in found if f.extra.get("rule") == "JAVA_TRANSFORMATION_LITERAL"]


def test_java_ssh_wire_names_carry_the_ssh_protocol(kb):
    found = scan(
        "class K {\n"
        '  public static final String DH_G1 = "diffie-hellman-group1-sha1";\n'
        '  public static final String HOST = "ssh-ed448";\n'
        '  public static final String GCM = "aes256-gcm@openssh.com";\n'
        '  public static final String MAC = "hmac-sha2-256-etm@openssh.com";\n'
        '  public static final String KEX = "mlkem768x25519-sha256";\n}',
        "java",
    )
    rows = {f.raw_name: f for f in found if f.extra.get("rule", "").startswith("JAVA_SSH")}
    assert set(rows) == {
        "diffie-hellman-group1-sha1",
        "ssh-ed448",
        "aes256-gcm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "mlkem768x25519-sha256",
    }
    assert {f.protocol for f in rows.values()} == {"SSH"}
    tiers = {asset.canonical_name: asset.tier for asset in analyze(list(rows.values()))[0]}
    assert Tier.UNKNOWN not in tiers.values()
    assert tiers["mlkem768x25519-sha256"] == Tier.SAFE


def test_java_ssh_names_need_a_string_literal():
    assert not scan("class K { // uses ssh-rsa and aes128-ctr\n int x; }", "java")


def test_pyopenssl_cffi_openssl_calls():
    found = scan(
        "TYPE_RSA = _lib.EVP_PKEY_RSA\n"
        "TYPE_DSA = _lib.EVP_PKEY_DSA\n"
        "def generate_key(self, bits):\n"
        "    rsa = _lib.RSA_new()\n"
        "    _lib.RSA_generate_key_ex(rsa, bits, exponent, _ffi.NULL)\n"
        "    dsa = _lib.DSA_new()\n",
        "python",
    )
    rows = sorted({(f.raw_name, f.extra.get("rule")) for f in found})
    assert rows == [("DSA", "PY_CFFI_OPENSSL_DSA"), ("RSA", "PY_CFFI_OPENSSL_RSA")]
    assert all(f.confidence <= 0.6 and f.key_size is None for f in found)


def test_xml_security_uri_fragments_are_not_ssh_names():
    found = scan(
        "class C {\n"
        '  public static final String NS_XMLENC = "http://www.w3.org/2001/04/xmlenc#";\n'
        '  public static final String AES192 = NS_XMLENC + "aes192-cbc";\n'
        '  public static final String MAC = "hmac-sha1";\n}',
        "java",
    )
    assert not [f for f in found if f.extra.get("rule", "").startswith("JAVA_SSH")]
    concatenated = scan('class C { String a = NS + "aes256-cbc"; String b = NS+"hmac-md5"; }', "java")
    assert not [f for f in concatenated if f.extra.get("rule", "").startswith("JAVA_SSH")]
