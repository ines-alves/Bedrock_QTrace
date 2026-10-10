"""Meaningful offline normalization, evidence and namespace cases for task 1.4."""

from dataclasses import FrozenInstanceError, replace
from types import MappingProxyType

import pytest

from quantumtrace.engine.normalize import RegistryResolution, normalize
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import Finding, KindHint, Location, SourceType, Usage


@pytest.fixture(scope="module")
def kb():
    return load_kb()


def finding(raw: str, **updates) -> Finding:
    data = dict(
        id="f1",
        raw_name=raw,
        kind_hint=KindHint.ALGORITHM,
        usage=Usage.UNKNOWN,
        detector="fixture",
        location=Location(source_type=SourceType.CODE, file="fixture.py", line=12),
    )
    data.update(updates)
    return Finding(**data)


# Exact aliases, punctuation, families, and recognized composite identities.
@pytest.mark.parametrize(
    "raw,canonical",
    [
        (" RSA ", "RSA"),
        ("rsaEncryption", "RSA"),
        ("RSASSA-PSS", "RSA"),
        ("RSA-OAEP", "RSA"),
        ("dss", "DSA"),
        ("DHE", "DH"),
        ("FFDHE", "DH"),
        ("ecdhEphemeral", "ECDH"),
        ("ECDHE", "ECDH"),
        ("ECDSA", "ECDSA"),
        ("curve25519", "X25519"),
        ("ssh-ed25519", "Ed25519"),
        ("curve448", "X448"),
        ("Ed448", "Ed448"),
        ("SM2", "SM2"),
        ("ElGamal", "ElGamal"),
        ("ECIES", "ECIES"),
        ("DESede", "3DES"),
        ("RC4", "RC4"),
        ("Blowfish", "Blowfish"),
        ("Camellia", "Camellia"),
        ("SEED", "SEED"),
        ("ChaCha20", "ChaCha20"),
        ("chacha20-poly1305@openssh.com", "ChaCha20-Poly1305"),
        ("MD5", "MD5"),
        ("sha", "SHA-1"),
        ("SHA_224", "SHA-224"),
        ("SHA 256", "SHA-256"),
        ("SHA-384", "SHA-384"),
        ("SHA512", "SHA-512"),
        ("SHA-512/224", "SHA-512/224"),
        ("SHA-512/256", "SHA-512/256"),
        ("sha3_224", "SHA3-224"),
        ("SHA3-256", "SHA3-256"),
        ("SHAKE128", "SHAKE128"),
        ("SHAKE256", "SHAKE256"),
        ("HmacSHA256", "HMAC-SHA256"),
        ("HMAC_384", "HMAC-SHA384"),
        ("HMAC-SHA3-256", "HMAC-SHA3-256"),
        ("PBKDF2WithHmacSHA256", "PBKDF2"),
        ("scrypt", "scrypt"),
        ("bcrypt", "bcrypt"),
        ("Poly1305", "Poly1305"),
        ("HKDF", "HKDF"),
        ("CMAC", "CMAC"),
        ("GMAC", "GMAC"),
        ("LMS", "LMS"),
        ("HSS", "HSS"),
        ("XMSSMT", "XMSS"),
        ("HQC", "HQC"),
        ("SYMMETRIC_DEFAULT", "KMS-SYMMETRIC-DEFAULT"),
        ("X25519MLKEM768", "X25519MLKEM768"),
        ("SecP256r1MLKEM768", "SecP256r1MLKEM768"),
        ("SecP384r1MLKEM1024", "SecP384r1MLKEM1024"),
        ("diffie-hellman-group1-sha1", "diffie-hellman-group1-sha1"),
        ("diffie-hellman-group14-sha1", "diffie-hellman-group14-sha1"),
        ("diffie-hellman-group16-sha512", "diffie-hellman-group16-sha512"),
        ("curve25519-sha256", "X25519"),
        ("ssh-rsa", "ssh-rsa"),
        ("rsa-sha2-512", "rsa-sha2-512"),
        ("mlkem768x25519-sha256", "mlkem768x25519-sha256"),
        ("sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512"),
        ("SHA1withRSA", "SHA1withRSA"),
        ("math/rand", "INSECURE-RNG"),
    ],
)
def test_aliases(raw, canonical, kb):
    result = normalize(finding(raw), kb)
    assert result.identity.algorithm_id == canonical
    assert result.is_resolved


@pytest.mark.parametrize(
    "raw,canonical,parameters",
    [
        ("rsa_2048", "RSA", {"key_size": 2048}),
        ("RSA-1024", "RSA", {"key_size": 1024}),
        ("rsa4096", "RSA", {"key_size": 4096}),
        ("RSA_3072", "RSA", {"key_size": 3072}),
        ("aes128-cbc", "AES", {"key_size": 128, "mode": "cbc"}),
        ("AES-256-GCM", "AES", {"key_size": 256, "mode": "gcm"}),
        ("aes_192_ctr", "AES", {"key_size": 192, "mode": "ctr"}),
        ("AES-GCM-256", "AES", {"key_size": 256, "mode": "gcm"}),
        ("AES/ECB/PKCS5Padding", "AES", {"mode": "ecb", "padding": "pkcs5"}),
        (" AES / ECB / PKCS5Padding ", "AES", {"mode": "ecb", "padding": "pkcs5"}),
        ("AES/GCM/NoPadding", "AES", {"mode": "gcm", "padding": "none"}),
        ("Camellia256CBC", "Camellia", {"key_size": 256, "mode": "cbc"}),
        ("ffdhe3072", "DH", {"key_size": 3072}),
        ("ECDHE-P256", "ECDH", {"curve": "secp256r1"}),
        ("ECDH-secp384r1", "ECDH", {"curve": "secp384r1"}),
        ("P-521", "ECDH", {"curve": "secp521r1"}),
        ("prime256v1", "ECDH", {"curve": "secp256r1"}),
        ("ECC_NIST_P384", "ECDSA", {"curve": "secp384r1"}),
        ("ECC_SECG_P256K1", "ECDSA", {"curve": "secp256k1"}),
        ("EC_prime256v1", "ECDSA", {"curve": "secp256r1"}),
        ("EC_secp384r1", "ECDSA", {"curve": "secp384r1"}),
        ("ML-KEM-512", "ML-KEM", {"parameter_set": "512"}),
        ("Kyber768", "ML-KEM", {"parameter_set": "768"}),
        ("ML-KEM-1024", "ML-KEM", {"parameter_set": "1024"}),
        ("Dilithium2", "ML-DSA", {"parameter_set": "44"}),
        ("Dilithium3", "ML-DSA", {"parameter_set": "65"}),
        ("Dilithium5", "ML-DSA", {"parameter_set": "87"}),
        ("ML-DSA-65", "ML-DSA", {"parameter_set": "65"}),
        ("Falcon512", "FN-DSA", {"parameter_set": "512"}),
        ("FN-DSA-1024", "FN-DSA", {"parameter_set": "1024"}),
        ("SLH-DSA-SHA2-128s", "SLH-DSA", {"parameter_set": "SHA2-128s"}),
        ("SPHINCS+-SHAKE-256f", "SLH-DSA", {"parameter_set": "SHAKE-256f"}),
        ("HKDF-SHA384", "HKDF", {"underlying_hash": "SHA-384"}),
        ("PBKDF2-HMAC-SHA1", "PBKDF2", {"underlying_hash": "SHA-1"}),
        ("PBKDF2-HMAC-SHA256", "PBKDF2", {"underlying_hash": "SHA-256"}),
        ("HMACSHA1", "HMAC-SHA1", {"underlying_hash": "SHA-1"}),
        ("HMACMD5", "HMAC-MD5", {"underlying_hash": "MD5"}),
        ("CMAC-AES256", "CMAC", {"key_size": 256, "underlying_cipher": "AES"}),
        ("GMAC-AES128", "GMAC", {"key_size": 128, "underlying_cipher": "AES"}),
        ("Argon2id", "Argon2", {"variant": "argon2id"}),
        ("BLAKE2b-256", "BLAKE2", {"variant": "blake2b", "output_size": 256}),
        ("3des-cbc", "3DES", {"mode": "cbc"}),
    ],
)
def test_name_parameters(raw, canonical, parameters, kb):
    result = normalize(finding(raw), kb)
    assert result.identity.algorithm_id == canonical
    assert result.is_resolved, result
    for field, value in parameters.items():
        assert getattr(result.identity.parameters, field) == value


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "customcrypto",
        "256",
        "29",
        "0x",
        "0xGGGG",
        "0x10000",
        "AES256GCMgarbage",
        "ML-KEM-999",
        "rsa-1",
        "SHA-512/128",
        "RSA2048 trailing",
    ],
)
def test_unrecognized_and_malformed_names(raw, kb):
    result = normalize(finding(raw), kb)
    assert result.identity.algorithm_id is None
    assert not result.is_resolved and result.unknown_reasons
    assert result.finding.raw_name == raw


@pytest.mark.parametrize("raw", ["P-256", "prime256v1", "secp256r1"])
@pytest.mark.parametrize("usage,canonical", [(Usage.KEY_EXCHANGE, "ECDH"), (Usage.SIGNATURE, "ECDSA")])
def test_curve_alias_identity(raw, usage, canonical, kb):
    result = normalize(finding(raw, usage=usage), kb)
    assert result.identity == normalize(finding("secp256r1", usage=usage), kb).identity
    assert result.identity.algorithm_id == canonical


@pytest.mark.parametrize(
    "raw,legacy",
    [
        ("Kyber768", True),
        ("Dilithium3", True),
        ("SPHINCS+-SHA2-128s", True),
        ("X25519Kyber768Draft00", True),
        ("ML-KEM-768", False),
        ("ML-DSA-65", False),
        ("SLH-DSA-SHA2-128s", False),
    ],
)
def test_legacy_provenance(raw, legacy, kb):
    result = normalize(finding(raw), kb)
    assert result.legacy_name is legacy
    assert bool(result.notes) is legacy
    assert result.finding.raw_name == raw


@pytest.mark.parametrize(
    "raw,canonical,size,mode,hash_name",
    [
        ("aes256-gcm@openssh.com", "AES", 256, "gcm", None),
        ("aes128-cbc", "AES", 128, "cbc", None),
        ("hmac-sha2-256-etm@openssh.com", "HMAC-SHA256", None, None, "SHA-256"),
        ("hmac-sha2-512", "HMAC-SHA512", None, None, "SHA-512"),
    ],
)
def test_ssh_specific_names(raw, canonical, size, mode, hash_name, kb):
    result = normalize(finding(raw, protocol="ssh"), kb)
    assert result.is_resolved and result.identity.algorithm_id == canonical
    assert result.identity.parameters.key_size == size
    assert result.identity.parameters.mode == mode
    assert result.identity.parameters.underlying_hash == hash_name


@pytest.mark.parametrize(
    "raw,fields,field",
    [
        ("AES128GCM", {"key_size": 256}, "key_size"),
        ("AES256GCM", {"mode": "ECB"}, "mode"),
        ("P-256", {"curve": "P-384"}, "curve"),
        ("AES/ECB/PKCS5Padding", {"padding": "NoPadding"}, "padding"),
        ("RSA", {"key_size": -1}, "key_size"),
        ("AES", {"mode": "unrecognized"}, "mode"),
        ("AES", {"key_size": 256, "extra": {"key_size_source": "ambiguous"}}, "key_size"),
        ("AES", {"mode": "ECB", "extra": {"mode_source": "jca_default"}}, "mode"),
        ("AES", {"mode": "ECB", "extra": {"mode_source": "provider_assumed"}}, "mode"),
    ],
)
def test_conflicts_are_unresolved_and_retained(raw, fields, field, kb):
    raw_finding = finding(raw, **fields)
    before = raw_finding.model_dump()
    result = normalize(raw_finding, kb)
    assert not result.is_resolved
    assert getattr(result.identity.parameters, field) is None
    assert any(conflict.field == field for conflict in result.conflicts)
    assert result.identity.conflicts == result.conflicts
    assert result.finding is raw_finding and raw_finding.model_dump() == before


def test_scanner_fields_provenance_and_metadata(kb):
    raw = finding(
        "AES",
        key_size=256,
        mode="GCM",
        padding="NoPadding",
        confidence=0.8,
        negotiated=False,
        session_id="session",
        in_test_code=True,
        extra={
            "key_size_source": "flow",
            "mode_source": "block_loop",
            "resolved_from_line": 3,
            "origin": "EXTERNAL",
            "state": "Enabled",
            "source_timestamp": "2026-10-10T12:00:00Z",
            "nested": {"offered": ["a", "b"]},
        },
    )
    snapshot = raw.model_dump_json()
    result = normalize(raw, kb)
    assert result.is_resolved
    assert result.identity.parameters.key_size == 256 and result.identity.parameters.mode == "gcm"
    assert any(e.source == "scanner:flow" for e in result.provenance)
    assert result.finding.confidence == 0.8 and result.finding.negotiated is False
    assert raw.model_dump_json() == snapshot
    assert normalize(raw, kb) == result
    with pytest.raises(FrozenInstanceError):
        result.identity.parameters.mode = "ecb"


def test_unknown_size_mode_and_generic_dependencies_not_invented(kb):
    result = normalize(finding("AES", language="java"), kb)
    assert result.identity.parameters.key_size is None and result.identity.parameters.mode is None
    for raw in ("CMAC", "GMAC", "PBKDF2"):
        params = normalize(finding(raw), kb).identity.parameters
        assert params.underlying_cipher is None and params.underlying_hash is None
    assert normalize(finding("SLH-DSA-128s"), kb).unknown_reasons


def test_distinct_identity_groups_and_semantic_hashes(kb):
    names = ["AES128CBC", "AES256CBC", "AES256GCM", "SHA-512", "SHA-512/256", "SHA-256"]
    assert len({normalize(finding(name), kb).identity for name in names}) == len(names)
    assert (
        normalize(finding("RSA", usage=Usage.SIGNATURE), kb).identity
        != normalize(finding("RSA", usage=Usage.ENCRYPTION), kb).identity
    )
    assert (
        normalize(finding("RSA", kind_hint=KindHint.CERTIFICATE), kb).identity
        != normalize(finding("RSA"), kb).identity
    )
    assert normalize(finding("unknown-a"), kb).identity != normalize(finding("unknown-b"), kb).identity
    assert normalize(finding("ec", usage=Usage.KEY_EXCHANGE), kb).identity.algorithm_id == "ECDH"
    assert not normalize(finding("ec"), kb).is_resolved


class FixtureRegistry:
    """Synthetic private values test mechanics; these are not production IANA rows."""

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def resolve(self, kind, codepoint):
        self.calls.append((kind, codepoint))
        return self.rows.get((kind, codepoint))


def row(kind=KindHint.GROUP, code="0xF001", name="ML-KEM-768", verified=True):
    return RegistryResolution(kind, code, name, verified, "synthetic offline fixture")


def test_registry_namespace_and_numeric_only_resolution(kb):
    registry = FixtureRegistry(
        {
            (KindHint.GROUP, "0xF001"): row(),
            (KindHint.SIGNATURE_SCHEME, "0xF001"): row(KindHint.SIGNATURE_SCHEME, name="ML-DSA-65"),
        }
    )
    group = normalize(finding("0xf001", kind_hint=KindHint.GROUP), kb, registry=registry)
    signature = normalize(finding("0xF001", kind_hint=KindHint.SIGNATURE_SCHEME), kb, registry=registry)
    assert group.is_resolved and group.identity.algorithm_id == "ML-KEM"
    assert signature.is_resolved and signature.identity.algorithm_id == "ML-DSA"
    assert registry.calls == [(KindHint.GROUP, "0xF001"), (KindHint.SIGNATURE_SCHEME, "0xF001")]
    assert not normalize(finding("0xF001"), kb, registry=registry).is_resolved
    assert not normalize(finding("61441", kind_hint=KindHint.GROUP), kb, registry=registry).is_resolved
    assert not normalize(finding("0xF001", kind_hint=KindHint.GROUP), kb).is_resolved


@pytest.mark.parametrize(
    "entry",
    [None, row(verified=False), row(KindHint.CIPHER_SUITE), row(code="0xF002"), replace(row(), source="")],
)
def test_absent_unverified_or_wrong_registry_rows(entry, kb):
    registry = FixtureRegistry({(KindHint.GROUP, "0xF001"): entry})
    result = normalize(
        finding("0xF001", kind_hint=KindHint.GROUP, extra={"iana_name": "ML-KEM-768"}), kb, registry=registry
    )
    assert not result.is_resolved and result.identity.algorithm_id is None


@pytest.mark.parametrize(
    "raw,extra,expected",
    [
        ("ML-KEM-768", {"codepoint": "0xf001", "iana_name": "ML-KEM-768"}, True),
        ("custom label", {"codepoint": "0xF001"}, False),
        ("ML-KEM-512", {"codepoint": "0xF001"}, False),
        ("0xF001", {"codepoint": "0xF002"}, False),
        ("0xF001", {"iana_name": "ML-DSA-65"}, False),
        ("0xF001", {"codepoint": 61441}, False),
    ],
)
def test_config_metadata_cross_checks(raw, extra, expected, kb):
    registry = FixtureRegistry({(KindHint.GROUP, "0xF001"): row()})
    result = normalize(finding(raw, kind_hint=KindHint.GROUP, extra=extra), kb, registry=registry)
    assert result.is_resolved is expected
    if not expected:
        assert result.conflicts


def test_registry_curve_cross_check_does_not_accept_family_only(kb):
    registry = FixtureRegistry({(KindHint.GROUP, "0xF001"): row(name="secp256r1")})
    assert normalize(
        finding("prime256v1", kind_hint=KindHint.GROUP, extra={"codepoint": "0xF001"}), kb, registry=registry
    ).is_resolved
    assert not normalize(
        finding("P-384", kind_hint=KindHint.GROUP, extra={"codepoint": "0xF001"}), kb, registry=registry
    ).is_resolved


def test_pattern_ambiguity_and_exact_precedence(kb):
    aes_rule = next(rule for rule in kb.patterns if rule.algorithm_id == "AES")
    conflicting = replace(aes_rule, algorithm_id="Camellia")
    ambiguous = replace(kb, patterns=(*kb.patterns, conflicting))
    assert not normalize(finding("AES256GCM"), ambiguous).is_resolved
    assert normalize(finding("AES"), ambiguous).identity.algorithm_id == "AES"
    # An alias remains authoritative even if a different family's pattern matches it.
    aliases = dict(kb.aliases)
    aliases["aes256gcm"] = "AES"
    authoritative = replace(ambiguous, aliases=MappingProxyType(aliases))
    assert normalize(finding("AES256GCM"), authoritative).is_resolved


@pytest.mark.parametrize(
    "raw,kind,usage",
    [
        ("AES256GCM", KindHint.GROUP, Usage.KEY_EXCHANGE),
        ("AES", KindHint.SIGNATURE_SCHEME, Usage.SIGNATURE),
        ("ECDHE", KindHint.ALGORITHM, Usage.SIGNATURE),
        ("ECDSA", KindHint.ALGORITHM, Usage.KEY_EXCHANGE),
    ],
)
def test_incompatible_kind_or_explicit_usage(raw, kind, usage, kb):
    result = normalize(finding(raw, kind_hint=kind, usage=usage), kb)
    assert result.conflicts and not result.is_resolved


def test_cloud_key_curves_respect_observed_usage_and_separator_cleanup(kb):
    assert normalize(finding("ECC_NIST_P256", usage=Usage.KEY_EXCHANGE), kb).identity.algorithm_id == "ECDH"
    assert (
        normalize(finding("EC-prime256v1", usage=Usage.SIGNATURE), kb).identity.parameters.curve
        == "secp256r1"
    )


def test_arbitrary_extension_shapes_do_not_crash_or_disappear(kb):
    raw = finding(
        "AES",
        key_size=256,
        mode="GCM",
        extra={"key_size_source": ["custom"], "mode_source": {"custom": True}},
    )
    result = normalize(raw, kb)
    assert result.is_resolved and result.finding.extra == raw.extra


def test_unresolved_code_identity_retains_namespace_and_canonical_hex(kb):
    group = normalize(finding("0xf01", kind_hint=KindHint.GROUP), kb)
    padded = normalize(finding("0x0F01", kind_hint=KindHint.GROUP), kb)
    signature = normalize(finding("0x0F01", kind_hint=KindHint.SIGNATURE_SCHEME), kb)
    assert group.identity == padded.identity
    assert group.identity != signature.identity
    assert group.finding.raw_name == "0xf01"


def test_same_entry_patterns_with_different_parameters_are_uncertain(kb):
    import re

    from quantumtrace.kb.loader import PatternRule

    altered = replace(
        kb, patterns=(*kb.patterns, PatternRule("AES", re.compile(r"^aes(?P<size>256)gcm(?P<mode>)$")))
    )
    result = normalize(finding("AES256GCM"), altered)
    assert not result.is_resolved and result.identity.parameters.key_size is None


def test_registry_resolution_retains_legacy_raw_name_provenance(kb):
    registry = FixtureRegistry({(KindHint.GROUP, "0xF001"): row()})
    result = normalize(
        finding("Kyber768", kind_hint=KindHint.GROUP, extra={"codepoint": "0xF001"}), kb, registry=registry
    )
    assert result.is_resolved and result.legacy_name
    assert result.finding.raw_name == "Kyber768" and result.notes


def test_unknown_size_is_separate_even_with_same_file(kb):
    unknown = finding("AES", mode="GCM")
    known = finding("AES", mode="GCM", key_size=256)
    assert unknown.location == known.location
    assert normalize(unknown, kb).identity != normalize(known, kb).identity
    assert normalize(known, kb).identity == normalize(finding("AES256GCM"), kb).identity


def test_atomic_hybrid_identity_remains_combiner(kb):
    result = normalize(finding("X25519MLKEM768", usage=Usage.KEY_EXCHANGE), kb)
    assert result.identity.algorithm_id == "X25519MLKEM768"
    assert result.identity.parameters.parameter_set is None
    assert kb.get(result.identity.algorithm_id).components[0].algorithm_id == "X25519"
    assert result.finding.usage == Usage.KEY_EXCHANGE
