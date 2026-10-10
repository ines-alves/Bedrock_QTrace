"""Offline examples for every PLAN 7.3 row and conservative evidence handling."""

from dataclasses import FrozenInstanceError, replace

import pytest

from quantumtrace.engine.decompose import CloudResolution, ComponentSpec, decompose
from quantumtrace.engine.normalize import RegistryResolution
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import Finding, KindHint, Location, SourceType, Usage


@pytest.fixture(scope="module")
def kb():
    return load_kb()


def finding(raw, kind=KindHint.ALGORITHM, **updates):
    data = dict(
        id="parent",
        raw_name=raw,
        kind_hint=kind,
        detector="fixture",
        location=Location(source_type=SourceType.CODE),
        usage=Usage.UNKNOWN,
    )
    data.update(updates)
    return Finding(**data)


def atoms(result):
    return [node for node in result.root.walk() if node.scoreable]


def by_role(result, role):
    return next(node for node in result.root.walk() if node.role == role)


def algorithms(result):
    return {(node.normalized.identity.algorithm_id, node.normalized.identity.usage) for node in atoms(result)}


@pytest.mark.parametrize(
    "name,kex,auth,fs,tail,tail_usage",
    [
        ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", False, "HMAC-SHA1", Usage.MAC),
        ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", False, "SHA-384", Usage.KDF),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDH", "RSA", True, "SHA-256", Usage.KDF),
        ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDH", "ECDSA", True, "SHA-384", Usage.KDF),
        ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DH", "RSA", True, "HMAC-SHA256", Usage.MAC),
        ("TLS_DH_DSS_WITH_AES_256_CBC_SHA", "DH", "DSA", False, "HMAC-SHA1", Usage.MAC),
        ("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "ECDH", "RSA", False, "HMAC-SHA1", Usage.MAC),
    ],
)
def test_tls12_roles_and_hash_context(name, kex, auth, fs, tail, tail_usage, kb):
    result = decompose(finding(name, KindHint.CIPHER_SUITE), kb)
    assert result.root.kind == "container" and not result.root.scoreable
    assert result.root.forward_secrecy is fs
    assert algorithms(result) == {
        (kex, Usage.KEY_EXCHANGE),
        (auth, Usage.AUTHENTICATION),
        ("AES", Usage.ENCRYPTION),
        (tail, tail_usage),
    }
    assert by_role(result, "authentication").normalized.identity.parameters.key_size is None


@pytest.mark.parametrize(
    "name,cipher,size,mode,digest,variant",
    [
        ("TLS_AES_128_GCM_SHA256", "AES", 128, "gcm", "SHA-256", None),
        ("TLS_AES_256_GCM_SHA384", "AES", 256, "gcm", "SHA-384", None),
        ("TLS_CHACHA20_POLY1305_SHA256", "ChaCha20-Poly1305", None, None, "SHA-256", None),
        ("TLS_AES_128_CCM_8_SHA256", "AES", 128, "ccm", "SHA-256", "ccm-8"),
    ],
)
def test_tls13_has_cipher_and_kdf_only(name, cipher, size, mode, digest, variant, kb):
    result = decompose(finding(name, KindHint.CIPHER_SUITE), kb)
    assert algorithms(result) == {(cipher, Usage.ENCRYPTION), ("HKDF", Usage.KDF)}
    params = by_role(result, "encryption").normalized.identity.parameters
    assert (params.key_size, params.mode, params.variant) == (size, mode, variant)
    assert by_role(result, "kdf").normalized.identity.parameters.underlying_hash == digest
    assert all(node.normalized.identity.usage != Usage.KEY_EXCHANGE for node in atoms(result))


class TLSFixture:
    """Synthetic private assignments exercise verified resolver interfaces only."""

    def __init__(self, names):
        self.names = names

    def resolve_name(self, kind, raw_name):
        return self.names.get((kind, raw_name))

    def resolve(self, kind, codepoint):
        return next(
            (row for row in self.names.values() if row.kind == kind and row.codepoint == codepoint), None
        )


def suite_row(name, code="0xF001", verified=True):
    return RegistryResolution(KindHint.CIPHER_SUITE, code, name, verified, "synthetic offline mapping")


@pytest.mark.parametrize(
    "openssl,iana",
    [
        ("ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        ("AES256-SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"),
    ],
)
def test_openssl_requires_verified_name_mapping(openssl, iana, kb):
    registry = TLSFixture({(KindHint.CIPHER_SUITE, openssl): suite_row(iana)})
    result = decompose(finding(openssl, KindHint.CIPHER_SUITE), kb, named_registry=registry)
    assert algorithms(result) == algorithms(decompose(finding(iana, KindHint.CIPHER_SUITE), kb))
    assert result.root.normalized.finding.raw_name == openssl
    assert not decompose(finding(openssl, KindHint.CIPHER_SUITE), kb).root.normalized.is_resolved
    with_code = decompose(
        finding(openssl, KindHint.CIPHER_SUITE, extra={"codepoint": "0xF001", "iana_name": iana}),
        kb,
        registry=registry,
        named_registry=registry,
    )
    assert algorithms(with_code) == algorithms(result)


@pytest.mark.parametrize(
    "name,algorithm,hash_name,padding",
    [
        ("SHA256withECDSA", "ECDSA", "SHA-256", None),
        ("SHA1withRSA", "RSA", "SHA-1", "pkcs1v15"),
        ("SHA256withRSA/PSS", "RSA", "SHA-256", "pss"),
        ("SHA384withDSA", "DSA", "SHA-384", None),
        ("RSASSA_PSS_SHA_256", "RSA", "SHA-256", "pss"),
        ("ECDSA_WITH_SHA384", "ECDSA", "SHA-384", None),
        ("sha256WithRSAEncryption", "RSA", "SHA-256", "pkcs1v15"),
        ("sha1WithRSAEncryption", "RSA", "SHA-1", "pkcs1v15"),
    ],
)
def test_jca_and_cloud_signatures(name, algorithm, hash_name, padding, kb):
    result = decompose(finding(name, usage=Usage.SIGNATURE, key_size=2048), kb)
    assert algorithms(result) == {(algorithm, Usage.SIGNATURE), (hash_name, Usage.SIGNATURE)}
    sig = by_role(result, "signature")
    assert sig.normalized.identity.parameters.key_size == 2048
    assert sig.normalized.identity.parameters.padding == padding
    assert by_role(result, "signature_hash").normalized.identity.parameters.key_size is None


@pytest.mark.parametrize(
    "name,algorithm,mode,padding",
    [
        ("AES/CBC/PKCS5Padding", "AES", "cbc", "pkcs5"),
        ("DESede/CBC/NoPadding", "3DES", "cbc", "none"),
        (" AES / GCM / NoPadding ", "AES", "gcm", "none"),
    ],
)
def test_jca_transform_preserves_parameters(name, algorithm, mode, padding, kb):
    result = decompose(finding(name, key_size=256), kb)
    assert algorithms(result) == {(algorithm, Usage.ENCRYPTION)}
    params = atoms(result)[0].normalized.identity.parameters
    assert (params.key_size, params.mode, params.padding) == (256, mode, padding)


def test_rsa_oaep_does_not_guess_mgf1_digest(kb):
    result = decompose(finding("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", key_size=2048), kb)
    assert algorithms(result) == {("RSA", Usage.ENCRYPTION), ("SHA-256", Usage.KDF)}
    assert by_role(result, "encryption").normalized.identity.parameters.padding == "oaep"
    assert any("MGF1 digest is not established" in note for note in result.root.notes)


@pytest.mark.parametrize(
    "name,algorithm,curve,digest,padding",
    [
        ("ecdsa_secp256r1_sha256", "ECDSA", "secp256r1", "SHA-256", None),
        ("ecdsa_secp384r1_sha384", "ECDSA", "secp384r1", "SHA-384", None),
        ("rsa_pss_rsae_sha256", "RSA", None, "SHA-256", "pss"),
        ("rsa_pkcs1_sha1", "RSA", None, "SHA-1", "pkcs1v15"),
    ],
)
def test_tls_signature_schemes(name, algorithm, curve, digest, padding, kb):
    result = decompose(finding(name, KindHint.SIGNATURE_SCHEME, usage=Usage.SIGNATURE), kb)
    assert algorithms(result) == {(algorithm, Usage.SIGNATURE), (digest, Usage.SIGNATURE)}
    params = by_role(result, "signature").normalized.identity.parameters
    assert params.curve == curve and params.padding == padding


@pytest.mark.parametrize("name,algorithm", [("ed25519", "Ed25519"), ("mldsa65", "ML-DSA")])
def test_atomic_signature_schemes(name, algorithm, kb):
    result = decompose(finding(name, KindHint.SIGNATURE_SCHEME, usage=Usage.SIGNATURE), kb)
    assert result.root.kind == "atom" and result.root.normalized.identity.algorithm_id == algorithm


@pytest.mark.parametrize(
    "name,algorithm,size,curve,padding,hash_name",
    [
        ("RS256", "RSA", None, None, "pkcs1v15", "SHA-256"),
        ("PS384", "RSA", None, None, "pss", "SHA-384"),
        ("ES256", "ECDSA", None, "secp256r1", None, "SHA-256"),
        ("ES512", "ECDSA", None, "secp521r1", None, "SHA-512"),
        ("HS256", "HMAC-SHA256", None, None, None, None),
        ("A128GCM", "AES", 128, None, None, None),
        ("A256GCM", "AES", 256, None, None, None),
        ("RSA-OAEP", "RSA", None, None, "oaep", "SHA-1"),
        ("RSA-OAEP-256", "RSA", None, None, "oaep", "SHA-256"),
        ("ECDH-ES", "ECDH", None, None, None, None),
    ],
)
def test_jose_algorithms(name, algorithm, size, curve, padding, hash_name, kb):
    result = decompose(finding(name), kb)
    primary = next(node for node in atoms(result) if node.normalized.identity.algorithm_id == algorithm)
    params = primary.normalized.identity.parameters
    assert (params.key_size, params.curve, params.padding) == (size, curve, padding)
    if hash_name:
        assert any(node.normalized.identity.algorithm_id == hash_name for node in atoms(result))
    assert primary.normalized.is_resolved


def test_jose_eddsa_requires_observed_curve(kb):
    result = decompose(finding("EdDSA"), kb)
    assert len(atoms(result)) == 1 and not atoms(result)[0].normalized.is_resolved
    for curve in ("Ed25519", "Ed448"):
        observed = decompose(finding("EdDSA", curve=curve), kb)
        assert algorithms(observed) == {(curve, Usage.SIGNATURE)}


@pytest.mark.parametrize(
    "name,algorithm,size,curve",
    [
        ("RSA_2048", "RSA", 2048, None),
        ("ECC_NIST_P256", "ECDSA", None, "secp256r1"),
        ("ML_DSA_65", "ML-DSA", None, None),
        ("HMAC_256", "HMAC-SHA256", None, None),
    ],
)
def test_kms_sourced_kb_aliases_without_fabricated_registry(name, algorithm, size, curve, kb):
    result = decompose(
        finding(name, KindHint.KEY, location=Location(source_type=SourceType.KMS, resource_id="key-arn")), kb
    )
    assert result.root.scoreable and result.root.normalized.identity.algorithm_id == algorithm
    assert result.root.normalized.identity.parameters.key_size == size
    assert result.root.normalized.identity.parameters.curve == curve
    assert result.resource_id == "key-arn"


class CloudFixture:
    def __init__(self, row):
        self.row = row

    def resolve(self, finding):
        return self.row


def test_cloud_coverage_is_explicit_and_conditional(kb):
    raw = finding("SYMMETRIC_DEFAULT", KindHint.KEY, location=Location(source_type=SourceType.KMS))
    missing = decompose(raw, kb)
    assert missing.issues and not missing.root.normalized.is_resolved
    for size in (128, 256):
        # Synthetic owner adapter mechanics; this is not an AWS policy table.
        row = CloudResolution(
            raw.raw_name,
            SourceType.KMS,
            (ComponentSpec("AES", Usage.ENCRYPTION, "key", key_size=size, mode="gcm"),),
            True,
            "synthetic offline owner mapping",
        )
        mapped = decompose(raw, kb, cloud_registry=CloudFixture(row))
        assert len(atoms(mapped)) == 1
        assert atoms(mapped)[0].normalized.identity.parameters.key_size == size
        assert atoms(mapped)[0].normalized.finding is raw
        unverified = decompose(raw, kb, cloud_registry=CloudFixture(replace(row, verified=False)))
        assert not unverified.root.normalized.is_resolved


@pytest.mark.parametrize(
    "name,size,digest",
    [
        ("diffie-hellman-group1-sha1", 1024, "SHA-1"),
        ("diffie-hellman-group14-sha1", 2048, "SHA-1"),
        ("diffie-hellman-group16-sha512", 4096, "SHA-512"),
    ],
)
def test_ssh_fixed_groups_and_hashes(name, size, digest, kb):
    result = decompose(finding(name, usage=Usage.KEY_EXCHANGE), kb)
    assert algorithms(result) == {("DH", Usage.KEY_EXCHANGE), (digest, Usage.HASH)}
    assert by_role(result, "key_exchange").normalized.identity.parameters.key_size == size


@pytest.mark.parametrize(
    "name,algorithm,digest",
    [
        ("ssh-rsa", "RSA", "SHA-1"),
        ("rsa-sha2-512", "RSA", "SHA-512"),
        ("ecdh-sha2-nistp256", "ECDH", "SHA-256"),
        ("ecdh-sha2-nistp521", "ECDH", "SHA-512"),
        ("curve25519-sha256", "X25519", "SHA-256"),
    ],
)
def test_ssh_signature_vs_kex_hash_context(name, algorithm, digest, kb):
    result = decompose(finding(name), kb)
    usage = Usage.SIGNATURE if name.startswith(("ssh-rsa", "rsa-sha")) else Usage.KEY_EXCHANGE
    hash_usage = Usage.SIGNATURE if usage == Usage.SIGNATURE else Usage.HASH
    assert algorithms(result) == {(algorithm, usage), (digest, hash_usage)}


def test_ssh_rsa_key_blob_does_not_establish_sha1(kb):
    result = decompose(finding("ssh-rsa", KindHint.KEY, usage=Usage.SIGNATURE, key_size=3072), kb)
    assert algorithms(result) == {("RSA", Usage.SIGNATURE)}
    assert atoms(result)[0].normalized.identity.parameters.key_size == 3072


@pytest.mark.parametrize(
    "name",
    [
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "X25519Kyber768Draft00",
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512",
    ],
)
def test_atomic_hybrids_keep_trace_halves_unscored(name, kb):
    raw = finding(name, usage=Usage.KEY_EXCHANGE)
    result = decompose(raw, kb)
    assert result.root.kind == "hybrid" and result.root.scoreable
    assert len(atoms(result)) == 1 and result.root.children
    assert all(
        not child.scoreable and child.parent_id == result.root.node_id for child in result.root.children
    )
    assert result.root.normalized.finding is raw


@pytest.mark.parametrize(
    "key,signature,algorithm,size,curve",
    [
        ("RSA_2048", "SHA256WITHRSA", "RSA", 2048, None),
        ("EC_prime256v1", "ECDSA_WITH_SHA256", "ECDSA", None, "secp256r1"),
    ],
)
def test_acm_subject_and_issuer_evidence_not_conflated(key, signature, algorithm, size, curve, kb):
    raw = finding(
        key,
        KindHint.CERTIFICATE,
        key_size=size,
        curve=curve,
        extra={"signature_algorithm": signature},
        location=Location(source_type=SourceType.ACM, resource_id="certificate-arn"),
    )
    result = decompose(raw, kb)
    subject = by_role(result, "certificate_key").normalized.identity
    issuer = by_role(result, "signature").normalized.identity
    assert subject.algorithm_id == algorithm and subject.usage == Usage.AUTHENTICATION
    assert subject.parameters.key_size == size and subject.parameters.curve == curve
    assert issuer.parameters.key_size is None and issuer.parameters.curve is None
    assert result.resource_id == "certificate-arn"


@pytest.mark.parametrize(
    "value",
    [
        "0x0a0a",
        "0x1A1A",
        "0xFAFA",
        "0x00FF",
        "0x5600",
        "TLS_FALLBACK_SCSV",
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    ],
)
def test_grease_and_signaling_suites_dropped(value, kb):
    result = decompose(finding(value, KindHint.CIPHER_SUITE), kb)
    assert result.root is None and result.dropped_reason


def test_signaling_value_not_dropped_from_different_namespace(kb):
    assert decompose(finding("0x00FF", KindHint.GROUP), kb).root is not None
    assert decompose(finding("0x0A0A", KindHint.ALGORITHM), kb).root is not None
    conflict = finding("0x0A0A", KindHint.GROUP, extra={"codepoint": "0xF001"})
    assert decompose(conflict, kb).root is not None


def test_numeric_tls_resolution_and_conflicts(kb):
    registry = TLSFixture({(KindHint.CIPHER_SUITE, "test"): suite_row("TLS_RSA_WITH_AES_128_CBC_SHA")})
    raw = finding("0xf001", KindHint.CIPHER_SUITE)
    result = decompose(raw, kb, registry=registry)
    assert len(atoms(result)) == 4
    assert all(node.normalized.finding is raw for node in result.root.walk())
    unknown = decompose(raw, kb)
    assert unknown.root.kind == "atom" and not unknown.root.normalized.is_resolved
    conflict = decompose(
        finding("0xF001", KindHint.CIPHER_SUITE, extra={"iana_name": "TLS_AES_256_GCM_SHA384"}),
        kb,
        registry=registry,
    )
    assert conflict.root.kind == "atom" and conflict.root.normalized.conflicts


def test_all_components_retain_evidence_and_semantic_ids(kb):
    raw = finding(
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        KindHint.CIPHER_SUITE,
        negotiated=False,
        confidence=0.5,
        session_id="session",
        extra={
            "origin": "prod",
            "state": "configured",
            "public_exposure": True,
            "nested": {"a": [1, 2]},
            "certificate_arns": ["cert-b", "cert-a"],
        },
        location=Location(source_type=SourceType.LOADBALANCER, resource_id="listener-arn"),
    )
    snapshot = raw.model_dump_json()
    result = decompose(raw, kb)
    assert result == decompose(raw, kb) and raw.model_dump_json() == snapshot
    assert result.certificate_arns == ("cert-a", "cert-b") and result.resource_id == "listener-arn"
    ids = [node.node_id for node in result.root.walk()]
    assert len(ids) == len(set(ids))
    for node in result.root.children:
        assert node.parent_id == result.root.node_id
        assert node.normalized.finding is raw
        assert node.normalized.finding.confidence == 0.5 and node.normalized.finding.negotiated is False
    dated = raw.model_copy(update={"extra": {**raw.extra, "source_timestamp": "2026-10-11T12:00:00Z"}})
    assert ids == [node.node_id for node in decompose(dated, kb).root.walk()]
    with pytest.raises(FrozenInstanceError):
        result.root.scoreable = True


def test_conflicting_size_is_not_silently_replaced(kb):
    raw = finding("diffie-hellman-group1-sha1", key_size=4096, usage=Usage.KEY_EXCHANGE)
    result = decompose(raw, kb)
    dh = by_role(result, "key_exchange").normalized
    assert dh.conflicts and dh.identity.parameters.key_size is None and not dh.is_resolved
    suite = decompose(finding("TLS_RSA_WITH_AES_128_CBC_SHA", KindHint.CIPHER_SUITE, key_size=256), kb)
    cipher = by_role(suite, "encryption").normalized
    assert cipher.conflicts and cipher.identity.parameters.key_size is None
    assert by_role(suite, "key_exchange").normalized.identity.parameters.key_size is None


@pytest.mark.parametrize(
    "name",
    [
        "TLS_MYSTERY_WITH_AES_256_GCM_SHA384",
        "TLS_AES_999_GCM_SHA256",
        "RSA/undefined/OAEPPadding",
        "0xFFFF",
        "65281",
        "RS999",
        "SHA999withRSA",
    ],
)
def test_unhandled_values_remain_structured_unknown(name, kb):
    result = decompose(
        finding(name, KindHint.CIPHER_SUITE if name.startswith("TLS_") else KindHint.ALGORITHM), kb
    )
    assert all(not node.normalized.is_resolved for node in atoms(result))


def test_observed_usage_contradiction_and_hygiene_exclusion(kb):
    result = decompose(finding("RS256", usage=Usage.ENCRYPTION), kb)
    assert result.root.kind == "atom" and result.root.normalized.conflicts
    for raw in (
        finding("math/rand"),
        finding("HTTP", KindHint.PLAINTEXT),
        finding("AES256GCM", extra={"hygiene_only": True}),
    ):
        assert not any(node.scoreable for node in decompose(raw, kb).root.walk())


def test_certificate_key_metadata_conflict_is_explicit(kb):
    raw = finding("RSA_2048", KindHint.CERTIFICATE, extra={"key_algorithm": "RSA_4096"})
    result = decompose(raw, kb)
    assert result.root.normalized.conflicts and not result.root.normalized.is_resolved
    consistent = decompose(
        finding("EC_prime256v1", KindHint.CERTIFICATE, extra={"key_algorithm": "ECC_NIST_P256"}), kb
    )
    assert not consistent.issues
    assert by_role(consistent, "certificate_key").normalized.identity.parameters.curve == "secp256r1"


@pytest.mark.parametrize("suite", ["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"])
def test_cloud_listener_policy_recipe_and_links(suite, kb):
    raw = finding(
        "synthetic-policy",
        KindHint.POLICY,
        location=Location(source_type=SourceType.LOADBALANCER, resource_id="listener-arn"),
        negotiated=None,
        extra={"certificate_arns": ["certificate-arn"]},
    )
    row = CloudResolution(
        raw.raw_name,
        SourceType.LOADBALANCER,
        (ComponentSpec(suite, Usage.UNKNOWN, "configured_suite", kind=KindHint.CIPHER_SUITE),),
        True,
        "synthetic owner fixture",
    )
    result = decompose(raw, kb, cloud_registry=CloudFixture(row))
    assert result.root.kind == "container" and not result.root.scoreable
    configured_suite = result.root.children[0]
    assert configured_suite.kind == "container" and not configured_suite.scoreable
    assert len(atoms(result)) == 4
    assert all(node.normalized.finding.negotiated is None for node in atoms(result))
    assert all(node.parent_id == configured_suite.node_id for node in configured_suite.children)
    assert result.resource_id == "listener-arn" and result.certificate_arns == ("certificate-arn",)


def test_cloud_recipe_order_and_duplicate_components_do_not_change_identity(kb):
    raw = finding("synthetic-policy", KindHint.POLICY, location=Location(source_type=SourceType.LOADBALANCER))
    specs = (
        ComponentSpec("AES", Usage.ENCRYPTION, "key", key_size=128),
        ComponentSpec("AES", Usage.ENCRYPTION, "key", key_size=256),
    )
    row = CloudResolution(raw.raw_name, SourceType.LOADBALANCER, specs, True, "synthetic owner fixture")
    first = decompose(raw, kb, cloud_registry=CloudFixture(row))
    second = decompose(raw, kb, cloud_registry=CloudFixture(replace(row, components=tuple(reversed(specs)))))
    assert first == second


@pytest.mark.parametrize(
    "raw",
    ["aes128-cbc", "aes256-gcm@openssh.com", "3des-cbc", "ssh-ed25519", "hmac-sha2-256-etm@openssh.com"],
)
def test_other_ssh_wire_atoms(raw, kb):
    result = decompose(finding(raw, location=Location(source_type=SourceType.SSH), protocol="ssh"), kb)
    assert result.root.normalized.is_resolved and result.root.kind == "atom"


def test_padding_spelling_preserves_main_digest_and_unknown_mgf(kb):
    raw = finding(
        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", padding="OAEPWithSHA-256AndMGF1Padding", key_size=2048
    )
    result = decompose(raw, kb)
    node = by_role(result, "encryption")
    assert node.normalized.is_resolved
    assert node.normalized.identity.parameters.underlying_hash == "SHA-256"
    assert node.normalized.identity.parameters.padding == "oaep"
    assert node.normalized.finding.padding == raw.padding


def test_malformed_grease_metadata_does_not_drop_evidence(kb):
    raw = finding("0x0A0A", KindHint.GROUP, extra={"codepoint": "bad"})
    result = decompose(raw, kb)
    assert result.root is not None and result.root.normalized.conflicts
    named = finding("X25519", KindHint.GROUP, extra={"codepoint": "0x0A0A"})
    assert decompose(named, kb).root is not None


def test_duplicate_owner_recipes_are_not_duplicate_scoring_atoms(kb):
    raw = finding("synthetic-policy", KindHint.POLICY, location=Location(source_type=SourceType.LOADBALANCER))
    spec = ComponentSpec("AES128GCM", Usage.ENCRYPTION, "encryption")
    row = CloudResolution(raw.raw_name, SourceType.LOADBALANCER, (spec, spec), True, "synthetic fixture")
    result = decompose(raw, kb, cloud_registry=CloudFixture(row))
    assert len(atoms(result)) == 1
    assert len({node.node_id for node in result.root.walk()}) == len(result.root.walk())


@pytest.mark.parametrize(
    "name",
    [
        "TLS_PSK_WITH_AES_128_CBC_SHA",
        "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    ],
)
def test_psk_or_anonymous_uncertainty_is_preserved(name, kb):
    result = decompose(finding(name, KindHint.CIPHER_SUITE), kb)
    assert result.root.notes
    assert any(not node.normalized.is_resolved for node in atoms(result))
    assert result.root.forward_secrecy is None


def test_jose_eddsa_parent_identity_never_claims_unobserved_variant(kb):
    ambiguous = decompose(finding("EdDSA"), kb)
    assert ambiguous.root.normalized.identity.algorithm_id is None
    ed448 = decompose(finding("EdDSA", curve="Ed448"), kb)
    assert ed448.root.normalized.identity.algorithm_id == "Ed448"


@pytest.mark.parametrize("padding,expected", [("PKCS1Padding", "pkcs1v15"), ("OAEPPadding", "oaep")])
def test_rsa_padding_aliases_are_canonicalized(padding, expected, kb):
    result = decompose(finding(f"RSA/ECB/{padding}", padding=padding), kb)
    node = by_role(result, "encryption")
    assert node.normalized.is_resolved and node.normalized.identity.parameters.padding == expected


@pytest.mark.parametrize(
    "signature,padding,digest",
    [("RSASSA_PSS_SHA_256", "pss", "SHA-256"), ("RSASSA_PKCS1_V1_5_SHA_384", "pkcs1v15", "SHA-384")],
)
def test_kms_observed_signature_metadata_uses_one_key_atom(signature, padding, digest, kb):
    raw = finding(
        "RSA_2048",
        KindHint.KEY,
        usage=Usage.SIGNATURE,
        extra={"signature_algorithm": signature},
        location=Location(source_type=SourceType.KMS, resource_id="key-arn"),
    )
    result = decompose(raw, kb)
    assert algorithms(result) == {("RSA", Usage.SIGNATURE), (digest, Usage.SIGNATURE)}
    primary = by_role(result, "signature")
    assert primary.normalized.identity.parameters.key_size == 2048
    assert primary.normalized.identity.parameters.padding == padding
    assert len(atoms(result)) == 2
    assert all(node.normalized.finding is raw for node in result.root.walk())


def test_cloud_key_recipe_cannot_override_observed_size(kb):
    raw = finding(
        "SYMMETRIC_DEFAULT", KindHint.KEY, key_size=128, location=Location(source_type=SourceType.KMS)
    )
    row = CloudResolution(
        raw.raw_name,
        SourceType.KMS,
        (ComponentSpec("AES", Usage.ENCRYPTION, "key", key_size=256),),
        True,
        "synthetic fixture",
    )
    result = decompose(raw, kb, cloud_registry=CloudFixture(row))
    assert atoms(result)[0].normalized.conflicts
    assert atoms(result)[0].normalized.identity.parameters.key_size is None


def test_versions_use_only_version_namespace_and_keep_partial_evidence(kb):
    from quantumtrace.engine.normalize import normalize

    version = RegistryResolution(
        KindHint.PROTOCOL_VERSION, "0xF001", "TLS 1.3", True, "synthetic version fixture"
    )
    wrong_namespace = RegistryResolution(KindHint.GROUP, "0xF001", "X25519", True, "synthetic group fixture")
    registry = TLSFixture(
        {(KindHint.PROTOCOL_VERSION, "version"): version, (KindHint.GROUP, "group"): wrong_namespace}
    )
    raw = finding(
        "TLS 1.3",
        KindHint.PROTOCOL_VERSION,
        negotiated=False,
        extra={"codepoint": "0xF001", "iana_name": None, "session": {"offered_groups": None}},
        location=Location(source_type=SourceType.PCAP),
    )
    normalized = normalize(raw, kb, registry=registry)
    assert normalized.resolved_name == "TLS 1.3" and not normalized.conflicts
    assert any(item.source.startswith("registry:") for item in normalized.provenance)
    result = decompose(raw, kb, registry=registry)
    assert result.root.normalized.finding is raw and not result.root.scoreable
    assert raw.extra["session"]["offered_groups"] is None and raw.negotiated is False
    missing_version = TLSFixture({(KindHint.GROUP, "group"): wrong_namespace})
    unknown = normalize(raw, kb, registry=missing_version)
    assert unknown.resolved_name == "TLS 1.3" and unknown.unknown_reasons


def test_equivalent_recipe_aliases_preserve_legacy_evidence_and_digest_identity(kb):
    raw = finding("synthetic-policy", KindHint.POLICY, location=Location(source_type=SourceType.LOADBALANCER))
    specs = (
        ComponentSpec("ML-KEM-768", Usage.KEY_EXCHANGE, "key_exchange"),
        ComponentSpec("kyber768", Usage.KEY_EXCHANGE, "key_exchange"),
    )
    row = CloudResolution(raw.raw_name, SourceType.LOADBALANCER, specs, True, "synthetic fixture")
    result = decompose(raw, kb, cloud_registry=CloudFixture(row))
    assert len(atoms(result)) == 1 and atoms(result)[0].normalized.legacy_name
    assert atoms(result)[0].normalized.notes
    digest = replace(row, components=(ComponentSpec("HKDF", Usage.KDF, "kdf", underlying_hash="sha256"),))
    kdf = decompose(raw, kb, cloud_registry=CloudFixture(digest))
    assert atoms(kdf)[0].normalized.identity.parameters.underlying_hash == "SHA-256"


def test_x509_rsa_encryption_signature_is_pkcs1_rsa_and_never_borrows_subject_parameters(kb):
    raw = finding(
        "RSA",
        KindHint.CERTIFICATE,
        usage=Usage.AUTHENTICATION,
        key_size=2048,
        extra={"key_algorithm": "RSA", "signature_algorithm": "sha256WithRSAEncryption"},
        location=Location(source_type=SourceType.PCAP, file="capture.pcap", flow="flow", frame=7),
    )
    result = decompose(raw, kb)
    issuer = by_role(result, "signature").normalized.identity
    assert issuer.algorithm_id == "RSA" and issuer.parameters.padding == "pkcs1v15"
    assert issuer.parameters.key_size is None
    assert by_role(result, "signature_hash").normalized.identity.algorithm_id == "SHA-256"
    assert by_role(result, "certificate_key").normalized.identity.parameters.key_size == 2048
    assert raw.extra["signature_algorithm"] == "sha256WithRSAEncryption"


def test_encryption_suffix_is_rsa_only(kb):
    raw = finding(
        "EC",
        KindHint.CERTIFICATE,
        usage=Usage.AUTHENTICATION,
        extra={"key_algorithm": "EC", "signature_algorithm": "sha256WithECDSAEncryption"},
        location=Location(source_type=SourceType.PCAP, file="capture.pcap"),
    )
    issuer = by_role(decompose(raw, kb), "signature").normalized.identity
    assert issuer.algorithm_id is None
