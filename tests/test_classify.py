"""Offline policy acceptance and Appendix D engine traps; no scanner substitutes."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import pytest

from quantumtrace.engine.classify import classify, summarize_verdict
from quantumtrace.engine.decompose import decompose
from quantumtrace.engine.normalize import Conflict
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import CryptoAsset, Finding, KindHint, Location, SourceType, Tier, Usage


@pytest.fixture(scope="module")
def kb():
    return load_kb()


def finding(name, **updates):
    data = dict(
        id="evidence",
        raw_name=name,
        kind_hint=KindHint.ALGORITHM,
        detector="fixture",
        location=Location(source_type=SourceType.CODE),
    )
    data.update(updates)
    return Finding(**data)


def result(kb, name, *, parameters=None, conflicts=(), **updates):
    node = decompose(finding(name, **updates), kb).root
    if parameters is not None or conflicts:
        normalized = node.normalized
        identity = replace(
            normalized.identity,
            parameters=replace(normalized.identity.parameters, **(parameters or {})),
            conflicts=conflicts,
        )
        node = replace(node, normalized=replace(normalized, identity=identity, conflicts=conflicts))
    return classify(node, kb)


@pytest.mark.parametrize(
    "name,usage,tier,broken",
    [
        ("RSA1024", Usage.ENCRYPTION, Tier.CRITICAL, True),
        ("RSA2048", Usage.SIGNATURE, Tier.CRITICAL, False),
        ("RSA3072", Usage.SIGNATURE, Tier.CRITICAL, False),
        ("RSA4096", Usage.KEY_EXCHANGE, Tier.CRITICAL, False),
        ("RSA15360", Usage.ENCRYPTION, Tier.CRITICAL, False),
        ("RSA", Usage.UNKNOWN, Tier.CRITICAL, False),
        ("DSA", Usage.SIGNATURE, Tier.CRITICAL, True),
        ("DH1024", Usage.KEY_EXCHANGE, Tier.CRITICAL, True),
        ("DH2048", Usage.KEY_EXCHANGE, Tier.CRITICAL, False),
        ("FFDHE4096", Usage.KEY_EXCHANGE, Tier.CRITICAL, False),
        ("ECDH", Usage.KEY_EXCHANGE, Tier.CRITICAL, False),
        ("ECDSA", Usage.SIGNATURE, Tier.CRITICAL, False),
        ("X25519", Usage.KEY_EXCHANGE, Tier.CRITICAL, False),
        ("X448", Usage.KEY_EXCHANGE, Tier.CRITICAL, False),
        ("Ed25519", Usage.SIGNATURE, Tier.CRITICAL, False),
        ("Ed448", Usage.SIGNATURE, Tier.CRITICAL, False),
        ("SM2", Usage.SIGNATURE, Tier.CRITICAL, False),
        ("ECIES", Usage.ENCRYPTION, Tier.CRITICAL, False),
        ("ElGamal", Usage.ENCRYPTION, Tier.CRITICAL, False),
        ("AES128GCM", Usage.ENCRYPTION, Tier.MEDIUM, False),
        ("AES192GCM", Usage.ENCRYPTION, Tier.MEDIUM, False),
        ("AES256GCM", Usage.ENCRYPTION, Tier.SAFE, False),
        ("AES", Usage.ENCRYPTION, Tier.MEDIUM, False),
        ("ChaCha20-Poly1305", Usage.ENCRYPTION, Tier.SAFE, False),
        ("3DES", Usage.ENCRYPTION, Tier.MEDIUM, True),
        ("DES", Usage.ENCRYPTION, Tier.MEDIUM, True),
        ("RC4", Usage.ENCRYPTION, Tier.MEDIUM, True),
        ("RC2", Usage.ENCRYPTION, Tier.MEDIUM, True),
        ("Blowfish", Usage.ENCRYPTION, Tier.MEDIUM, True),
        ("IDEA", Usage.ENCRYPTION, Tier.MEDIUM, True),
        ("Camellia256", Usage.ENCRYPTION, Tier.SAFE, False),
        ("SHA-1", Usage.HASH, Tier.MEDIUM, True),
        ("SHA-1", Usage.SIGNATURE, Tier.MEDIUM, True),
        ("SHA-1", Usage.MAC, Tier.MEDIUM, False),
        ("SHA-1", Usage.KDF, Tier.MEDIUM, False),
        ("MD5", Usage.HASH, Tier.MEDIUM, True),
        ("MD5", Usage.MAC, Tier.MEDIUM, False),
        ("MD2", Usage.HASH, Tier.MEDIUM, True),
        ("RIPEMD160", Usage.HASH, Tier.MEDIUM, False),
        ("HMAC-SHA1", Usage.MAC, Tier.MEDIUM, False),
        ("HMAC-MD5", Usage.MAC, Tier.MEDIUM, False),
        ("SHA-224", Usage.HASH, Tier.MEDIUM, False),
        ("SHA-512/224", Usage.HASH, Tier.MEDIUM, False),
        ("SHA-256", Usage.HASH, Tier.SAFE, False),
        ("SHA-512/256", Usage.HASH, Tier.SAFE, False),
        ("SHA3-256", Usage.HASH, Tier.SAFE, False),
        ("SHA-384", Usage.HASH, Tier.SAFE, False),
        ("SHA-512", Usage.HASH, Tier.SAFE, False),
        ("SHA3-384", Usage.HASH, Tier.SAFE, False),
        ("SHA3-512", Usage.HASH, Tier.SAFE, False),
        ("SHAKE128", Usage.HASH, Tier.MEDIUM, False),
        ("SHAKE256", Usage.HASH, Tier.SAFE, False),
        ("HMAC-SHA256", Usage.MAC, Tier.SAFE, False),
        ("ML-KEM-768", Usage.KEY_EXCHANGE, Tier.SAFE, False),
        ("ML-DSA-65", Usage.SIGNATURE, Tier.SAFE, False),
        ("SLH-DSA-SHA2-128s", Usage.SIGNATURE, Tier.SAFE, False),
        ("Falcon", Usage.SIGNATURE, Tier.SAFE, False),
        ("HQC", Usage.KEY_EXCHANGE, Tier.SAFE, False),
        ("LMS", Usage.SIGNATURE, Tier.SAFE, False),
        ("XMSS", Usage.SIGNATURE, Tier.SAFE, False),
        ("SNTRUP761", Usage.KEY_EXCHANGE, Tier.SAFE, False),
        ("X25519MLKEM768", Usage.KEY_EXCHANGE, Tier.SAFE, False),
        ("PBKDF2-HMAC-SHA256", Usage.KDF, Tier.SAFE, False),
        ("HKDF-SHA256", Usage.KDF, Tier.SAFE, False),
        ("PBKDF2WithHmacSHA1", Usage.KDF, Tier.MEDIUM, False),
        ("Argon2id", Usage.KDF, Tier.SAFE, False),
        ("scrypt", Usage.KDF, Tier.SAFE, False),
        ("bcrypt", Usage.KDF, Tier.SAFE, False),
        ("CMAC", Usage.MAC, Tier.UNKNOWN, False),
        ("GMAC", Usage.MAC, Tier.UNKNOWN, False),
        ("HMAC", Usage.MAC, Tier.UNKNOWN, False),
        ("mystery-primitive", Usage.UNKNOWN, Tier.UNKNOWN, False),
    ],
)
def test_family_policy(name, usage, tier, broken, kb):
    row = result(kb, name, usage=usage)
    assert row.tier == tier
    assert row.classically_broken is broken
    assert CryptoAsset.model_validate_json(row.to_asset().model_dump_json()).tier == tier


@pytest.mark.parametrize("source", list(SourceType))
@pytest.mark.parametrize("usage", [Usage.KEY_EXCHANGE, Usage.SIGNATURE, Usage.ENCRYPTION, Usage.UNKNOWN])
def test_hndl_requires_shor_kex_in_transit(source, usage, kb):
    row = result(kb, "RSA2048", usage=usage, location=Location(source_type=source))
    assert row.hndl_exposed == (
        usage == Usage.KEY_EXCHANGE
        and source in {SourceType.PCAP, SourceType.LIVE, SourceType.SSH, SourceType.LOADBALANCER}
    )
    if usage == Usage.SIGNATURE:
        assert "not HNDL" in row.rationale


def test_static_rsa_and_hmac_trap(kb):
    row = result(
        kb,
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        kind_hint=KindHint.CIPHER_SUITE,
        location=Location(source_type=SourceType.PCAP),
        negotiated=True,
    )
    assert row.tier == Tier.CRITICAL and row.hndl_exposed and not row.scoreable
    kex = next(c for c in row.children if c.node.role == "key_exchange")
    mac = next(c for c in row.children if c.node.role == "mac")
    assert kex.forward_secrecy is False and "server-key break" in kex.rationale
    assert mac.tier == Tier.MEDIUM and not mac.classically_broken
    assert sum(c.scoreable for c in row.children) == 4


@pytest.mark.parametrize(
    "authentication,expected", [(None, Tier.UNKNOWN), (False, Tier.UNKNOWN), (True, Tier.UNKNOWN)]
)
def test_hybrid_unknown_auth_never_safe(authentication, expected, kb):
    hybrid = result(
        kb,
        "X25519MLKEM768",
        usage=Usage.KEY_EXCHANGE,
        location=Location(source_type=SourceType.PCAP),
        negotiated=True,
    )
    summary = summarize_verdict(
        [hybrid], require_authentication=True, authentication_observable=authentication
    )
    assert hybrid.tier == Tier.SAFE and not hybrid.hndl_exposed
    assert summary.tier == expected and not summary.hndl_exposed
    assert "no certificate key" in summary.rationale
    assert sum(c.scoreable for c in hybrid.walk()) == 1
    assert any(c.tier == Tier.CRITICAL for c in hybrid.children)


@pytest.mark.parametrize(
    "auth,tier", [("RSA2048", Tier.CRITICAL), ("ECDSA", Tier.CRITICAL), ("ML-DSA-65", Tier.SAFE)]
)
def test_hybrid_observed_auth(auth, tier, kb):
    hybrid = result(kb, "X25519MLKEM768", usage=Usage.KEY_EXCHANGE)
    signature = result(kb, auth, usage=Usage.SIGNATURE)
    summary = summarize_verdict(
        [hybrid, signature], require_authentication=True, authentication_observable=True
    )
    assert summary.tier == tier and not summary.hndl_exposed


@pytest.mark.parametrize(
    "names,tier",
    [
        ([], Tier.UNKNOWN),
        (["AES256GCM"], Tier.SAFE),
        (["AES256GCM", "unrecognized"], Tier.UNKNOWN),
        (["AES128", "unrecognized"], Tier.MEDIUM),
        (["RSA2048", "unrecognized"], Tier.CRITICAL),
    ],
)
def test_composite_precedence(names, tier, kb):
    assert summarize_verdict(result(kb, n) for n in names).tier == tier


def test_aes_unknown_confidence_and_observed_ecb(kb):
    unknown = result(kb, "AES", usage=Usage.ENCRYPTION, confidence=0.8)
    assert unknown.confidence == 0.5 and unknown.to_asset().key_size is None
    assert "not determinable" in unknown.rationale
    assert "ECB" not in unknown.rationale
    low = result(kb, "AES", confidence=0.3)
    assert low.confidence == 0.3
    ecb = result(kb, "AES256ECB", usage=Usage.ENCRYPTION)
    assert ecb.tier == Tier.SAFE and any("ECB" in a.action for a in ecb.recommendations)
    assert ecb.primitive == "block-cipher"
    assert result(kb, "AES256GCM").primitive == "ae"


def test_aes192_configurable_without_quantum_level_inference(kb):
    alternative = replace(kb, scoring=kb.scoring.model_copy(update={"aes_192_tier": Tier.SAFE}))
    assert result(alternative, "AES192").tier == Tier.SAFE
    for name in ["AES128", "AES192", "AES256"]:
        row = result(kb, name)
        assert row.nist_quantum_level is None and row.classical_security_bits is None


@pytest.mark.parametrize(
    "name,updates,tier",
    [
        ("AES256", {"key_size": 128}, Tier.UNKNOWN),
        ("AES256GCM", {"mode": "CBC"}, Tier.UNKNOWN),
        (
            "ML-KEM-768",
            {"conflicts": (Conflict("parameter_set", ("768", "512"), "observations conflict"),)},
            Tier.UNKNOWN,
        ),
        ("RSA4096", {"key_size": 1024}, Tier.CRITICAL),
        ("ECDH", {"usage": Usage.SIGNATURE}, Tier.UNKNOWN),
    ],
)
def test_conflicts_cannot_create_false_safe(name, updates, tier, kb):
    row = result(kb, name, **updates)
    assert row.tier == tier
    assert row.oid is None and row.nist_quantum_level is None
    assert "conflict" in " ".join(a.action for a in row.recommendations)


@pytest.mark.parametrize(
    "name,standard,level,oid",
    [
        ("ML-KEM-768", "NIST FIPS 203", 3, "2.16.840.1.101.3.4.4.2"),
        ("ML-DSA-65", "NIST FIPS 204", 3, "2.16.840.1.101.3.4.3.18"),
        ("Kyber768", None, None, None),
        ("Dilithium3", None, None, None),
        ("Falcon", None, None, None),
        ("HQC", None, None, None),
        ("X25519MLKEM768", None, None, None),
        ("AES256GCM", None, None, "2.16.840.1.101.3.4.1.46"),
    ],
)
def test_only_sourced_facts_and_legacy_caveats(name, standard, level, oid, kb):
    row = result(kb, name)
    assert (row.pqc_standard, row.nist_quantum_level, row.oid) == (standard, level, oid)
    if name in {"Kyber768", "Dilithium3"}:
        assert row.deprecated_pqc_draft and "withheld" in row.rationale


@pytest.mark.parametrize(
    "usage,target",
    [
        (Usage.SIGNATURE, "ML-DSA-65"),
        (Usage.AUTHENTICATION, "ML-DSA-65"),
        (Usage.KEY_EXCHANGE, "ML-KEM-768"),
        (Usage.ENCRYPTION, "ML-KEM-768"),
        (Usage.UNKNOWN, None),
    ],
)
def test_rsa_recommendation_matches_usage(usage, target, kb):
    row = result(kb, "RSA2048", usage=usage)
    assert [a.target_algorithm for a in row.recommendations] == [target]
    if usage == Usage.UNKNOWN:
        # The use is not observed: both migration paths are named, no single target is guessed.
        assert row.recommendations[0].action == (
            "Identify the key's use, then migrate signatures to ML-DSA-65 and key establishment to ML-KEM-768."
        )
    if usage == Usage.ENCRYPTION:
        assert "not bulk encryption" in row.recommendations[0].action


@pytest.mark.parametrize(
    "name,extra,tier",
    [
        ("HMAC", {"underlying_hash": "SHA-256"}, Tier.SAFE),
        ("HMAC", {"underlying_hash": "SHA-1"}, Tier.MEDIUM),
        ("HKDF", {"underlying_hash": "unverified"}, Tier.UNKNOWN),
        ("CMAC", {"underlying_cipher": "AES", "key_size": 256}, Tier.SAFE),
        ("GMAC", {"underlying_cipher": "AES", "key_size": 128}, Tier.MEDIUM),
        ("CMAC", {"underlying_cipher": "AES"}, Tier.MEDIUM),
        ("CMAC", {"underlying_cipher": "RSA"}, Tier.UNKNOWN),
        ("SHA-256", {"output_size": 128}, Tier.UNKNOWN),
    ],
)
def test_underlying_algorithms_and_truncated_outputs(name, extra, tier, kb):
    assert result(kb, name, parameters=extra).tier == tier


@pytest.mark.parametrize(
    "kind,extra",
    [
        (KindHint.PLAINTEXT, {}),
        (KindHint.LIBRARY, {}),
        (KindHint.PROTOCOL_VERSION, {}),
        (KindHint.ALGORITHM, {"hygiene_only": True}),
    ],
)
def test_exclusions_visible_unknown_and_unscored(kind, extra, kb):
    row = result(kb, "AES256", kind_hint=kind, extra=extra)
    assert row.tier == Tier.UNKNOWN and not row.scoreable and row.exclusions
    assert row.to_asset().finding_ids == ["evidence"]


def test_insecure_rng_excluded(kb):
    row = result(kb, "INSECURE-RNG", usage=Usage.RNG)
    assert row.tier == Tier.UNKNOWN and row.classically_broken and not row.scoreable
    assert any("random" in a.action for a in row.recommendations)


def test_deterministic_expiry_uses_dump_before_scan_time(kb):
    extra = {
        "not_after": "2026-11-01T00:00:00Z",
        "source_timestamp": "2026-01-01T00:00:00Z",
        "cert_status": "ISSUED",
        "in_use_by": ["listener"],
        "certificate_state": "encrypted",
    }
    start = datetime(2026, 12, 1, tzinfo=timezone.utc)
    source = finding("RSA2048", kind_hint=KindHint.CERTIFICATE, extra=extra)
    before = source.model_dump_json()
    row = classify(decompose(source, kb).root, kb, scan_started_at=start)
    assert "expired" not in row.rationale and "within 90" not in row.rationale
    assert row.node.normalized.finding is source and source.model_dump_json() == before
    no_dump = source.model_copy(update={"extra": {k: v for k, v in extra.items() if k != "source_timestamp"}})
    expired = classify(decompose(no_dump, kb).root, kb, scan_started_at=start)
    assert "expired, ISSUED" in expired.rationale
    assert any("Renew" in a.action for a in expired.recommendations)
    assert expired == classify(decompose(no_dump, kb).root, kb, scan_started_at=start)


def test_expiry_near_missing_invalid_and_naive(kb):
    row = result(
        kb, "RSA", extra={"not_after": "2026-11-01T00:00:00Z", "source_timestamp": "2026-10-01T00:00:00Z"}
    )
    assert "within 90" in row.rationale
    missing = result(kb, "RSA", extra={"not_after": "2026-11-01T00:00:00Z"})
    assert "explicit scan start" in missing.rationale
    invalid = result(kb, "RSA", extra={"not_after": "2026-11-01"})
    assert "not a valid" in invalid.rationale
    with pytest.raises(ValueError, match="timezone"):
        classify(decompose(finding("RSA"), kb).root, kb, scan_started_at=datetime(2026, 10, 1))


def test_hygiene_context_does_not_change_quantum_policy(kb):
    row = result(
        kb,
        "AES256",
        extra={
            "origin": "AWS_CLOUDHSM",
            "multi_region": True,
            "rotation_status": False,
            "state": "PendingDeletion",
            "hand_rolled": True,
        },
    )
    assert row.tier == Tier.SAFE and row.scoreable
    for text in [
        "HSM backing",
        "Multi-region",
        "rotation",
        "pending deletion",
        "not an implementation audit",
    ]:
        assert text in row.rationale
    external = result(kb, "AES256", extra={"origin": "EXTERNAL"})
    assert "external origin" in external.rationale
    imported = result(kb, "RSA", extra={"origin": "IMPORTED"})
    assert "imported" in imported.rationale
    pbkdf = result(kb, "PBKDF2-HMAC-SHA256", extra={"hand_rolled": True, "iterations": 1000})
    assert pbkdf.tier == Tier.SAFE and "threshold" in pbkdf.rationale


def test_private_records_and_public_payloads_retain_metadata(kb):
    raw = finding(
        "TLS_AES_256_GCM_SHA384",
        kind_hint=KindHint.CIPHER_SUITE,
        confidence=0.7,
        negotiated=False,
        session_id="session",
        extra={"state": "configured", "unknown_owner": {"keep": None}},
    )
    before = raw.model_dump_json()
    row = classify(decompose(raw, kb).root, kb)
    # A TLS 1.3 suite carries no key exchange or authentication: its tier is its components'.
    assert row.tier == Tier.SAFE and not row.scoreable
    for child in row.walk():
        assert child.node.normalized.finding is raw and child.confidence == 0.7
        asset = child.to_asset()
        assert asset.negotiated is False and asset.finding_ids == [raw.id]
        assert asset.risk_points == asset.max_points == 0
    with pytest.raises(FrozenInstanceError):
        row.tier = Tier.SAFE
    asset = row.to_asset()
    asset.occurrences[0].file = "modified"
    assert raw.model_dump_json() == before
    assert row.to_asset().components == [c.node.node_id for c in row.children]
    assert all(c.to_asset().component_of == [row.node.node_id] for c in row.children)


@pytest.mark.parametrize("name", ["SHA-384", "HMAC-SHA256", "PBKDF2-HMAC-SHA256", "AES256GCM"])
@pytest.mark.parametrize("language", ["python", "java", "go"])
def test_appendix_d_safe_decoy_subset(name, language, kb):
    row = result(
        kb, name, language=language, extra={"hand_rolled": language == "go" and name.startswith("PBKDF2")}
    )
    assert row.tier == Tier.SAFE and row.scoreable and not row.classically_broken
    assert not any(a.target_algorithm is not None for a in row.recommendations)


@pytest.mark.parametrize(
    "name,tier,broken",
    [
        ("diffie-hellman-group1-sha1", Tier.CRITICAL, True),
        ("diffie-hellman-group14-sha1", Tier.CRITICAL, True),
        ("diffie-hellman-group16-sha512", Tier.CRITICAL, False),
        ("curve25519-sha256", Tier.CRITICAL, False),
        ("mlkem768x25519-sha256", Tier.SAFE, False),
        ("sntrup761x25519-sha512", Tier.SAFE, False),
        ("ssh-rsa", Tier.CRITICAL, True),
        ("rsa-sha2-256", Tier.CRITICAL, False),
        ("ssh-ed25519", Tier.CRITICAL, False),
    ],
)
def test_ssh_classification_subset(name, tier, broken, kb):
    row = result(kb, name, location=Location(source_type=SourceType.SSH))
    assert row.tier == tier and row.classically_broken == broken
    if row.node.kind == "hybrid":
        assert sum(r.scoreable for r in row.walk()) == 1


def test_ssh_rsa_blob_not_signature(kb):
    row = result(kb, "ssh-rsa", kind_hint=KindHint.KEY, location=Location(source_type=SourceType.KEYFILE))
    assert row.tier == Tier.CRITICAL and not row.classically_broken
    assert not any(r.node.normalized.identity.algorithm_id == "SHA-1" for r in row.walk())


@pytest.mark.parametrize(
    "name,broken",
    [("TLS 1.0", True), ("TLS 1.1", True), ("SSLv3", True), ("TLS 1.3", False), ("0x0301", False)],
)
def test_version_hygiene_only_no_guessed_numeric_policy(name, broken, kb):
    row = result(kb, name, kind_hint=KindHint.PROTOCOL_VERSION)
    assert row.tier == Tier.UNKNOWN and not row.scoreable and row.classically_broken == broken


def test_usage_specific_mac_advice(kb):
    row = result(kb, "SHA-1", usage=Usage.MAC)
    assert not row.classically_broken
    assert row.recommendations[0].target_algorithm == "HMAC-SHA-384"


def test_unknown_namespace_and_registry_conflicts(kb):
    from quantumtrace.engine.normalize import RegistryResolution

    class BadResolver:
        def resolve(self, kind, codepoint):
            return RegistryResolution(kind, "0xEE01", "X25519", True, "fixture:wrong-code")

    raw = finding("0xEE00", kind_hint=KindHint.GROUP, usage=Usage.KEY_EXCHANGE)
    row = classify(decompose(raw, kb, registry=BadResolver()).root, kb)
    assert row.tier == Tier.UNKNOWN and not row.hndl_exposed and row.oid is None
    assert row.scoreable and row.node.normalized.finding is raw


def test_arbitrary_metadata_not_promoted_to_parameters(kb):
    row = result(kb, "HMAC", extra={"underlying_hash": "SHA-256"})
    assert row.tier == Tier.UNKNOWN
    assert row.node.normalized.finding.extra["underlying_hash"] == "SHA-256"


def test_group14_classical_weakness_is_hash_not_dh_size(kb):
    row = result(kb, "diffie-hellman-group14-sha1")
    dh = next(c for c in row.children if c.node.role == "key_exchange")
    digest = next(c for c in row.children if c.node.role == "kex_hash")
    assert not dh.classically_broken and dh.to_asset().key_size == 2048
    assert digest.classically_broken and row.classically_broken
    assert "SHA-1" in row.rationale and "classical weakness" in row.rationale


def test_unsupported_cipher_sizes_and_kdf_cipher_evidence(kb):
    assert result(kb, "AES", key_size=200).tier == Tier.UNKNOWN
    assert result(kb, "bcrypt", parameters={"underlying_cipher": "AES", "key_size": 128}).tier == Tier.MEDIUM
    assert result(kb, "bcrypt", parameters={"underlying_cipher": "unverified"}).tier == Tier.UNKNOWN


@pytest.mark.parametrize("observable,tier", [(False, Tier.UNKNOWN), (None, Tier.UNKNOWN), (True, Tier.SAFE)])
def test_auth_observability_independent_from_raw_certificate_state(observable, tier, kb):
    hybrid = result(
        kb,
        "X25519MLKEM768",
        usage=Usage.KEY_EXCHANGE,
        extra={"certificate_state": "encrypted", "authentication_observable": observable},
    )
    auth = result(kb, "ML-DSA-65", usage=Usage.SIGNATURE)
    summary = summarize_verdict(
        [hybrid, auth], require_authentication=True, authentication_observable=observable
    )
    assert summary.tier == tier
    assert hybrid.node.normalized.finding.extra["certificate_state"] == "encrypted"


def test_truncation_withholds_standardized_oid_and_safe_mac_policy(kb):
    digest = result(kb, "SHA-256", parameters={"output_size": 128})
    assert digest.tier == Tier.UNKNOWN and digest.oid is None
    mac = result(kb, "HMAC-SHA256", parameters={"output_size": 64})
    assert mac.tier == Tier.UNKNOWN and not mac.classically_broken


def test_certificate_signature_hygiene_and_subject_parameters_scoped(kb):
    row = result(
        kb,
        "RSA_2048",
        kind_hint=KindHint.CERTIFICATE,
        key_size=2048,
        extra={
            "signature_algorithm": "SHA1WITHRSA",
            "not_after": "2026-11-01T00:00:00Z",
            "source_timestamp": "2026-10-01T00:00:00Z",
        },
    )
    assert row.tier == Tier.CRITICAL and row.classically_broken
    assert row.to_asset().asset_type == "certificate"
    assert not row.scoreable
    assert all(child.to_asset().asset_type == "algorithm" for child in row.children)
    digest = next(r for r in row.walk() if r.node.normalized.identity.algorithm_id == "SHA-1")
    assert "certificate signature" in digest.rationale and digest.to_asset().key_size is None
    assert any("Renew" in a.action for a in row.recommendations)


@pytest.mark.parametrize(
    "key,not_after,expected",
    [
        ("RSA", "2030-12-31T23:59:59Z", False),
        ("RSA", "2031-01-01T00:00:00Z", True),
        ("RSA", "2031-01-01T00:30:00+01:00", False),
        ("RSA", "2045-06-01T00:00:00+00:00", True),
        ("RSA", "2045-06-01T00:00:00", False),
        ("ML-DSA-65", "2045-06-01T00:00:00Z", False),
    ],
)
def test_beyond_2030_validity_is_migration_context_only(key, not_after, expected, kb):
    def classified(when):
        node = decompose(
            finding(
                key,
                kind_hint=KindHint.CERTIFICATE,
                usage=Usage.AUTHENTICATION,
                key_size=2048 if key == "RSA" else None,
                extra={"key_algorithm": key, "not_after": not_after},
                location=Location(source_type=SourceType.PCAP, file="capture.pcap"),
            ),
            kb,
        ).root
        return classify(node, kb, scan_started_at=when)

    early = classified(datetime(2026, 9, 14, tzinfo=timezone.utc))
    late = classified(datetime(2029, 1, 1, tzinfo=timezone.utc))
    for row in (early, late):
        assert any("before 2031" in advice.action for advice in row.recommendations) is expected
        assert ("beyond 2030" in row.rationale) is expected
    assert early.tier == late.tier
    assert not any("before 2031" in advice.action for advice in early.maintenance)


def test_policy_components_are_labelled_by_suite_not_unresolved():
    from pathlib import Path

    from quantumtrace.pipeline import run

    path = Path(__file__).resolve().parents[1] / "cloud-posture/load_balancer_listeners.json"
    policies = [a for a in run([path]).assets if a.canonical_name == "ELBSecurityPolicy-TLS13-1-2-2021-06"]
    assert policies and all("unresolved" not in a.rationale for a in policies)
    assert all("cipher_suite=TLS_AES_256_GCM_SHA384 (SAFE)" in a.rationale for a in policies)


@pytest.mark.parametrize("name", ["EC", "EdDSA", "XDH", "DHKEM"])
def test_unobserved_use_or_variant_keeps_known_shor_tier(name, kb):
    assert result(kb, name, usage=Usage.UNKNOWN).tier == Tier.CRITICAL


def test_pbkdf2_follows_its_observed_underlying_hash(kb):
    assert result(kb, "PBKDF2-HMAC-MD5", usage=Usage.KDF).tier == Tier.MEDIUM
    assert result(kb, "PBKDF2-HMAC-SHA3_256", usage=Usage.KDF).tier == Tier.SAFE


def test_migration_text_never_names_an_unobserved_use(kb):
    unknown = result(kb, "Ed25519", usage=Usage.UNKNOWN)
    known = result(kb, "Ed25519", usage=Usage.SIGNATURE)
    assert [a.action for a in unknown.recommendations if a.action.startswith("Migrate")] == [
        "Migrate to ML-DSA-65."
    ]
    assert "Migrate signature to ML-DSA-65." in [a.action for a in known.recommendations]


def test_block_cipher_rationale_states_policy_not_a_wrong_observation(kb):
    (row,) = result(kb, "AES/ECB/PKCS5Padding", usage=Usage.ENCRYPTION, key_size=128).children
    assert "Unknown key size" not in row.rationale and "SIV" not in row.rationale
    assert "tier follows the observed key size" in row.rationale and "ECB" in row.rationale


@pytest.mark.parametrize(
    "suite,tier",
    [
        ("TLS_AES_256_GCM_SHA384", Tier.SAFE),
        ("TLS_CHACHA20_POLY1305_SHA256", Tier.SAFE),
        ("TLS_AES_128_GCM_SHA256", Tier.MEDIUM),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Tier.CRITICAL),
    ],
)
def test_tls13_suites_take_component_tier_and_leave_authentication_to_sessions(suite, tier, kb):
    row = result(kb, suite, kind_hint=KindHint.CIPHER_SUITE, usage=Usage.UNKNOWN)
    assert row.tier == tier and not row.scoreable
    assert ("Authentication is UNKNOWN" in row.rationale) is (tier == Tier.CRITICAL)


def test_disabled_tls_verification_gets_tailored_hygiene_warning(kb):
    row = result(
        kb,
        "InsecureSkipVerify",
        extra={"hygiene_only": True, "hygiene_flags": ["tls_verify_disabled"]},
    )
    assert "certificate verification is disabled" in row.rationale
    assert "Observed hygiene context: tls_verify_disabled" not in row.rationale
    assert [a.action for a in row.recommendations] == ["Enable TLS certificate and hostname verification."]
    assert row.tier == Tier.UNKNOWN and not row.scoreable


@pytest.mark.parametrize("name", ["TLS 1.0", "TLSv1", "TLS 1.1", "SSLv3"])
def test_obsolete_protocol_versions_from_code_are_broken_hygiene(name, kb):
    row = result(kb, name, kind_hint=KindHint.PROTOCOL_VERSION, usage=Usage.UNKNOWN)
    assert row.classically_broken and not row.scoreable
    assert any("Migrate obsolete transport" in a.action for a in row.recommendations)


@pytest.mark.parametrize("name", ["HMAC-SHA1", "HMAC-MD5"])
def test_weak_mac_migration_cites_the_hmac_standard(kb, name):
    row = result(kb, name, usage=Usage.MAC)
    advice = [a for a in row.recommendations if a.target_algorithm == "HMAC-SHA384"]
    assert [(a.action, a.standard) for a in advice] == [
        ("Use a maintained HMAC-SHA384 implementation.", "NIST FIPS 198-1")
    ]


def test_sha1_signature_hash_advice_replaces_the_digest_not_the_signature(kb):
    row = result(kb, "SHA-1", usage=Usage.SIGNATURE)
    assert [
        (a.action, a.target_algorithm, a.standard) for a in row.recommendations if a.target_algorithm
    ] == [("Use SHA-384 as the signature hash.", "SHA-384", "NIST FIPS 180-4")]


def test_ssh_rsa_sha1_part_recommends_rfc8332_and_rsa_part_ml_dsa(kb):
    ssh = Location(source_type=SourceType.SSH, file="capture.pcap", flow="flow")
    root = classify(decompose(finding("ssh-rsa", usage=Usage.SIGNATURE, location=ssh), kb).root, kb)
    advice = {
        (row.node.normalized.identity.algorithm_id, a.target_algorithm, a.standard)
        for row in root.walk()
        for a in row.recommendations
        if a.target_algorithm
    }
    assert ("SHA-1", "rsa-sha2-512", "IETF RFC 8332") in advice
    assert ("RSA", "ML-DSA-65", "NIST FIPS 204") in advice
    assert not any(target == "SHA-384" for _, target, _ in advice)


@pytest.mark.parametrize(
    "name,usage", [("RSA2048", Usage.SIGNATURE), ("ssh-rsa", Usage.SIGNATURE), ("SHA-1", Usage.SIGNATURE)]
)
def test_replacement_standard_never_becomes_the_assets_own_pqc_standard(kb, name, usage):
    row = result(kb, name, usage=usage)
    assert row.recommendations and all(row.pqc_standard is None for row in row.walk())
