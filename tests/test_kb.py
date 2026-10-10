"""Offline policy, resource and invalid-input checks for the M1 knowledge base."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from importlib import resources
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from quantumtrace.kb.loader import KnowledgeBaseError, load_kb, load_scoring
from quantumtrace.models import Tier, Usage


@pytest.fixture
def kb_directory(tmp_path: Path) -> Path:
    for name in ("algorithms.yaml", "scoring.yaml"):
        tmp_path.joinpath(name).write_text(resources.files("quantumtrace.kb").joinpath(name).read_text())
    return tmp_path


def change_algorithm(directory: Path, identifier: str, **updates: object) -> None:
    path = directory / "algorithms.yaml"
    entries = yaml.safe_load(path.read_text())
    next(entry for entry in entries if entry["id"] == identifier).update(updates)
    path.write_text(yaml.safe_dump(entries))


@pytest.mark.parametrize(
    "identifier",
    [
        "RSA",
        "DSA",
        "DH",
        "ECDH",
        "X25519",
        "X448",
        "ECDSA",
        "Ed25519",
        "Ed448",
        "SM2",
        "ElGamal",
        "ECIES",
        "AES",
        "ChaCha20",
        "ChaCha20-Poly1305",
        "3DES",
        "DES",
        "RC4",
        "RC2",
        "Blowfish",
        "IDEA",
        "Camellia",
        "SEED",
        "MD5",
        "MD4",
        "SHA-1",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA-512/224",
        "SHA-512/256",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "SHAKE128",
        "SHAKE256",
        "BLAKE2",
        "BLAKE3",
        "HMAC",
        "Poly1305",
        "CMAC",
        "GMAC",
        "PBKDF2",
        "HKDF",
        "scrypt",
        "bcrypt",
        "Argon2",
        "ML-KEM",
        "ML-DSA",
        "SLH-DSA",
        "FN-DSA",
        "LMS",
        "HSS",
        "XMSS",
        "HQC",
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "SecP384r1MLKEM1024",
        "X25519Kyber768Draft00",
        "SecP256r1Kyber768Draft00",
    ],
)
def test_required_families_have_policy_and_sources(identifier: str) -> None:
    entry = load_kb().get(identifier)
    assert entry.primitive_by_usage and entry.sources
    assert entry.tier is not None or "unknown" in entry.tier_by_key_size


@pytest.mark.parametrize(
    ("alias", "expected"),
    [
        ("RSASSA-PSS", "RSA"),
        ("rsa_2048", "RSA"),
        ("ecdh_ephemeral", "ECDH"),
        ("ECDHE", "ECDH"),
        ("FFDHE", "DH"),
        ("PRIME256V1", "ECDH"),
        ("HmacSHA256", "HMAC-SHA256"),
        ("PBKDF2WithHmacSHA256", "PBKDF2"),
        ("PBKDF2-HMAC-SHA256", "PBKDF2"),
        ("AES/ECB/PKCS5Padding", "AES"),
        ("AES/GCM/NoPadding", "AES"),
        ("SHA1withRSA", "SHA1withRSA"),
        ("ECC_NIST_P256", "ECDSA"),
        ("HMAC_256", "HMAC-SHA256"),
        ("diffie-hellman-group1-sha1", "diffie-hellman-group1-sha1"),
        ("ssh-rsa", "ssh-rsa"),
        ("rsa-sha2-512", "rsa-sha2-512"),
        ("mlkem768x25519-sha256", "mlkem768x25519-sha256"),
        ("sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512"),
        ("SYMMETRIC_DEFAULT", "KMS-SYMMETRIC-DEFAULT"),
    ],
)
def test_agreed_raw_aliases(alias: str, expected: str) -> None:
    entry = load_kb().by_alias(alias)
    assert entry is not None and entry.id == expected


def test_parameter_mode_and_usage_policy() -> None:
    kb = load_kb()
    aes = kb.get("AES")
    assert dict(aes.tier_by_key_size) == {
        "128": Tier.MEDIUM,
        "192": Tier.MEDIUM,
        "256": Tier.SAFE,
        "unknown": Tier.MEDIUM,
    }
    assert aes.primitive_by_mode["gcm"] == "ae"
    assert aes.primitive_by_usage["default"] == "block-cipher"
    assert aes.nist_quantum_level is None  # key bits are not a security-category assertion
    assert kb.get("RSA").primitive_by_usage[Usage.SIGNATURE] == "signature"
    assert kb.get("RSA").primitive_by_usage[Usage.KEY_EXCHANGE] == "pke"
    assert kb.get("SHA-1").classically_broken_if.usages == (
        Usage.HASH,
        Usage.SIGNATURE,
        Usage.AUTHENTICATION,
    )
    assert not kb.get("HMAC-SHA1").classically_broken
    assert kb.get("ML-KEM").nist_quantum_level_by_param["768"] == 3
    assert kb.get("ML-DSA").param_map["3"] == "65"
    assert len(kb.get("SLH-DSA").parameter_sets) == 12


def test_standards_status_and_verified_oids() -> None:
    kb = load_kb()
    for identifier, standard in [("ML-KEM", "203"), ("ML-DSA", "204"), ("SLH-DSA", "205")]:
        entry = kb.get(identifier)
        assert entry.pqc_standard == f"NIST FIPS {standard}"
        assert entry.standards_status == "final"
        assert entry.deprecated_aliases
    assert kb.get("ML-KEM").oids["768"] == "2.16.840.1.101.3.4.4.2"
    assert kb.get("ML-DSA").oids["65"] == "2.16.840.1.101.3.4.3.18"
    for identifier in ("FN-DSA", "HQC"):
        entry = kb.get(identifier)
        assert entry.standards_status == "in_development"
        assert entry.pqc_standard is None and entry.oid is None and entry.nist_quantum_level is None
    assert kb.get("X25519Kyber768Draft00").deprecated_pqc_draft
    assert kb.get("X25519MLKEM768").tier == Tier.SAFE
    assert kb.get("X25519MLKEM768").pqc_standard is None
    assert kb.get("X25519MLKEM768").components[0].algorithm_id == "X25519"
    assert kb.get("X25519").tier == Tier.CRITICAL
    assert kb.get("KMS-SYMMETRIC-DEFAULT").tier == Tier.UNKNOWN


def test_ssh_composites_keep_parameter_and_hash_semantics() -> None:
    kb = load_kb()
    group1 = kb.get("diffie-hellman-group1-sha1")
    assert group1.components[0].key_size == 1024 and group1.classically_broken
    group16 = kb.get("diffie-hellman-group16-sha512")
    assert group16.components[0].key_size == 4096
    assert kb.get("ssh-rsa").components[1].algorithm_id == "SHA-1"
    assert kb.get("rsa-sha2-512").components[1].algorithm_id == "SHA-512"
    assert kb.get("ssh-rsa").components[1].usage == Usage.SIGNATURE


def test_scoring_contract_defaults_and_json_copy() -> None:
    scoring = load_scoring()
    payload = scoring.as_dict()
    assert payload["tier_weights"] == {"CRITICAL": 10, "MEDIUM": 4, "UNKNOWN": 2, "SAFE": 0}
    assert payload["exposure"] == {
        "negotiated_key_exchange": 1.5,
        "public_loadbalancer_policy": 1.5,
        "negotiated_other": 1.2,
        "kms_enabled": 1.2,
        "production": 1.0,
        "offered_only": 0.4,
        "kms_inactive": 0.3,
        "test_only": 0.3,
    }
    assert payload["occurrence"] == {"cap": 31, "log_divisor": 5}
    assert payload["hndl_floor"] == {"score": 60, "condition": "hndl_exposed_and_negotiated"}
    assert payload["broken_multiplier"] == 1.5 and payload["aes_192_tier"] == "MEDIUM"
    assert [(band["minimum"], band["maximum"]) for band in payload["grade_bands"]] == [
        (0, 10),
        (11, 25),
        (26, 40),
        (41, 60),
        (61, 80),
        (81, 100),
    ]
    json.dumps(payload, allow_nan=False)
    payload["tier_weights"]["CRITICAL"] = 0
    assert scoring.tier_weights[Tier.CRITICAL] == 10


def test_loaded_data_is_deeply_immutable() -> None:
    kb = load_kb()
    with pytest.raises(TypeError):
        kb.algorithms["RSA"] = kb.get("AES")
    with pytest.raises(TypeError):
        kb.get("RSA").replacement[Usage.SIGNATURE] = None
    with pytest.raises(ValidationError):
        kb.get("RSA").replacement[Usage.SIGNATURE].algorithm_id = "RSA"
    with pytest.raises(TypeError):
        kb.scoring.tier_weights[Tier.CRITICAL] = 0
    with pytest.raises(FrozenInstanceError):
        kb.patterns = ()


def test_package_loading_outside_cwd_and_unknown_lookup(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    kb = load_kb()
    assert list(kb.algorithms) == sorted(kb.algorithms)
    assert kb.by_alias("not an algorithm") is None and kb.by_alias("0x11EC") is None
    with pytest.raises(KeyError):
        kb.get("missing")


def test_optional_registry_presence_does_not_invent_data(kb_directory: Path) -> None:
    (kb_directory / "tls_registry.yaml").write_text("{}")
    kb = load_kb(kb_directory)
    assert kb.optional_registries == {"tls_registry.yaml": True, "cloud_registry.yaml": False}
    assert kb.by_alias("0x0201") is None


@pytest.mark.parametrize(
    "updates",
    [
        {"tier": "GOOD"},
        {"threat": "bad"},
        {"primitive_by_usage": {"default": "aes"}},
        {"primitive_by_usage": {"not_usage": "pke"}},
        {"primitive_by_usage": {}},
        {"invented": 3},
        {"patterns": ["("]},
        {"patterns": ["^($"]},
        {"patterns": ["^(?P<wrong>rsa)$"]},
        {"oid": "1.99.1"},
        {"oid": "1.2.01"},
        {"nist_quantum_level": 0},
        {"replacement": {"default": {"algorithm_id": "missing"}}},
        {"replacement": {"default": {"algorithm_id": "ML-KEM", "parameter_set": "bad"}}},
        {"replacement": {"default": {"algorithm_id": "AES", "key_size": 64}}},
        {"replacement": {"default": {"algorithm_id": "AES", "mode": "siv"}}},
        {"components": [{"algorithm_id": "RSA"}]},
        {"classically_broken_if": {}},
        {"sources": []},
        {"classically_broken": "false"},
        {"aliases": ["SHA-256"]},
        {"deprecated_aliases": ["unknown"]},
        {"parameter_sets": ["same", "same"]},
        {"nist_quantum_level_by_param": {"missing": 3}},
    ],
)
def test_rejects_invalid_algorithm_policies(kb_directory: Path, updates: dict) -> None:
    change_algorithm(kb_directory, "RSA", **updates)
    with pytest.raises(KnowledgeBaseError, match="algorithms.yaml"):
        load_kb(kb_directory)


@pytest.mark.parametrize(
    "update",
    [
        {"tier_weights": {"CRITICAL": 10}},
        {"exposure": {"production": 1}},
        {"broken_multiplier": 0},
        {"broken_multiplier": True},
        {"occurrence": {"cap": 31, "log_divisor": 0}},
        {"hndl_floor": {"score": 101, "condition": "hndl_exposed_and_negotiated"}},
        {"hndl_floor": {"score": 60, "condition": "offered"}},
        {"grade_bands": []},
        {"aes_192_tier": "CRITICAL"},
        {"extra": 1},
        {"broken_multiplier": float("nan")},
    ],
)
def test_rejects_invalid_scoring(kb_directory: Path, update: dict) -> None:
    path = kb_directory / "scoring.yaml"
    data = yaml.safe_load(path.read_text())
    data.update(update)
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(KnowledgeBaseError, match="scoring.yaml"):
        load_scoring(kb_directory)


def test_duplicate_ids_yaml_keys_and_empty_lists_fail(kb_directory: Path) -> None:
    path = kb_directory / "algorithms.yaml"
    entries = yaml.safe_load(path.read_text())
    path.write_text(yaml.safe_dump(entries + [entries[0]]))
    with pytest.raises(KnowledgeBaseError, match="duplicate algorithm ID"):
        load_kb(kb_directory)
    path.write_text("- {id: RSA, id: AES}")
    with pytest.raises(KnowledgeBaseError, match="duplicate YAML key"):
        load_kb(kb_directory)
    path.write_text("[]")
    with pytest.raises(KnowledgeBaseError, match="nonempty list"):
        load_kb(kb_directory)


def test_missing_required_data_fails_explicitly(tmp_path: Path, kb_directory: Path) -> None:
    with pytest.raises(KnowledgeBaseError, match="algorithms.yaml"):
        load_kb(tmp_path / "missing")
    (kb_directory / "scoring.yaml").unlink()
    with pytest.raises(KnowledgeBaseError, match="scoring.yaml"):
        load_kb(kb_directory)


def test_pattern_parameters_are_compiled_and_bounded() -> None:
    rules = load_kb().patterns
    match = next(
        rule.expression.fullmatch("aes256gcm")
        for rule in rules
        if rule.algorithm_id == "AES" and rule.expression.fullmatch("aes256gcm")
    )
    assert match.groupdict() == {"size": "256", "mode": "gcm"}
    assert not any(rule.expression.fullmatch("aes256gcmgarbage") for rule in rules)
