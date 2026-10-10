from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner

FIXTURES = Path(__file__).parent / "fixtures" / "code"
KIT = Path(__file__).parent.parent / "sample-repos" / "go"


def scan_path(path: Path, root: Path) -> list[Finding]:
    results = list(CodeScanner().scan(path, root))
    assert all(isinstance(r, Finding) for r in results), results
    return results


def scan_fixture(name: str) -> list[Finding]:
    """Scan one fixture with the shipped rules. Paths are relative to FIXTURES, so none is a test path."""
    return scan_path(FIXTURES / "go" / name, FIXTURES)


def by_line(findings: list[Finding]) -> dict[int, Finding]:
    """Findings by line; the crypto.<HASH> constant that shares a signature line is left out."""
    return {f.location.line: f for f in findings if f.usage.value != "hash"}


def summary(findings: list[Finding]) -> list[tuple[str, int, int | None, str | None]]:
    return [(f.raw_name, f.location.line, f.key_size, f.mode) for f in findings]


@pytest.mark.parametrize(
    "fixture, expected",
    [
        (
            "hashes.go",
            [
                ("md5", 12, None, None),
                ("sha1", 16, None, None),
                ("sha1", 20, None, None),
                ("sha256", 25, None, None),
                ("sha224", 29, None, None),
                ("sha384", 33, None, None),
                ("sha512", 37, None, None),
                ("SHA1", 41, None, None),
            ],
        ),
        (
            "mac_kdf.go",
            [
                ("HMAC-sha256", 14, None, None),
                ("HMAC-sha1", 20, None, None),
                ("HMAC-sha384", 26, None, None),
                ("HMAC-sha256", 34, None, None),
                ("PBKDF2-HMAC-sha256", 42, None, None),
                ("PBKDF2-HMAC-SHA256", 48, None, None),
                ("PBKDF2-HMAC-SHA256", 55, None, None),
            ],
        ),
        ("mac_kdf_stdlib.go", [("PBKDF2-HMAC-sha512", 9, None, None)]),
        (
            "signatures.go",
            [
                ("RSA", 13, 2048, None),
                ("RSA", 17, 3072, None),
                ("SHA256", 21, None, None),
                ("RSA", 21, 2048, None),
                ("SHA256", 25, None, None),
                ("RSA", 25, 2048, None),
                ("SHA256", 29, None, None),
                ("RSA", 29, 2048, None),
                ("SHA256", 49, None, None),
                ("RSA", 49, None, None),
                ("Ed25519", 53, None, None),
                ("Ed25519", 57, None, None),
            ],
        ),
        (
            "ciphers.go",
            [
                ("hard-coded symmetric key", 11, None, None),
                ("AES", 20, 256, "GCM"),
                ("AES", 33, 128, "ECB"),
                ("AES", 45, None, None),
                ("AES", 62, None, "CBC"),
                ("AES", 72, None, None),
                ("AES", 82, None, "CTR"),
            ],
        ),
        ("rng_math.go", [("math/rand", 10, None, None), ("math/rand", 15, None, None)]),
        ("rng_alias.go", [("math/rand", 4, None, None)]),
        ("imports_only.go", [("sha1", 4, None, None), ("sha256", 5, None, None)]),
        ("rng_crypto.go", []),
    ],
)
def test_fixture_raw_names_lines_sizes_and_modes(fixture, expected):
    assert summary(scan_fixture(fixture)) == expected


def test_findings_are_go_code_findings_outside_test_paths():
    findings = scan_fixture("hashes.go")
    assert {f.language for f in findings} == {"go"}
    assert not any(f.in_test_code for f in findings)
    assert all(f.location.file == "go/hashes.go" for f in findings)
    assert all(f.kind_hint.value == "algorithm" and f.usage.value == "hash" for f in findings)


# ---------------------------------------------------------------- AES: key size and mode


def test_gcm_wrapper_sets_mode_and_the_size_comes_through_the_flow_link():
    found = by_line(scan_fixture("ciphers.go"))[20]
    assert (found.mode, found.key_size) == ("GCM", 256)
    assert found.extra["key_size_source"] == "flow"
    assert found.extra["resolved_from_line"] == 9
    assert "mode_source" not in found.extra
    assert found.confidence == 0.8


def test_block_encrypt_loop_without_chaining_is_ecb_by_block_loop_evidence():
    found = by_line(scan_fixture("ciphers.go"))[33]
    assert (found.mode, found.key_size) == ("ECB", 128)
    assert found.extra["mode_source"] == "block_loop"
    assert found.extra["key_size_source"] == "flow"
    assert found.extra["resolved_from_line"] == 11
    assert found.confidence == 0.8


@pytest.mark.parametrize("line", [45, 72])
def test_manual_chaining_and_a_single_block_leave_mode_none(line):
    found = by_line(scan_fixture("ciphers.go"))[line]
    assert found.mode is None
    assert "mode_source" not in found.extra
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"
    assert found.confidence == 0.5


@pytest.mark.parametrize("line, mode", [(62, "CBC"), (82, "CTR")])
def test_explicit_cipher_wrappers_set_their_mode_without_block_loop_source(line, mode):
    found = by_line(scan_fixture("ciphers.go"))[line]
    assert found.mode == mode
    assert "mode_source" not in found.extra


def test_aes_with_an_imported_key_keeps_the_mode_but_no_size():
    found = by_line(scan_fixture("ciphers.go"))[62]
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"


# ---------------------------------------------------------------- RSA and Ed25519


def test_rsa_generation_reads_literal_and_constant_sizes():
    findings = by_line(scan_fixture("signatures.go"))
    assert (findings[13].key_size, findings[13].extra["key_size_source"]) == (2048, "literal")
    assert (findings[17].key_size, findings[17].extra["key_size_source"]) == (3072, "constant")
    assert findings[17].extra["resolved_from_line"] == 10
    assert findings[13].usage.value == "unknown"


def test_rsa_sign_and_verify_take_the_generated_size_through_a_flow_link():
    findings = by_line(scan_fixture("signatures.go"))
    for line, padding in ((21, "PKCS1v15"), (25, "PKCS1v15"), (29, "PSS")):
        found = findings[line]
        assert (found.raw_name, found.key_size, found.usage.value) == ("RSA", 2048, "signature")
        assert found.padding == padding
        assert found.extra["key_size_source"] == "flow"
        assert found.confidence == 0.8


def test_rsa_signature_with_an_imported_key_stays_unresolved():
    found = by_line(scan_fixture("signatures.go"))[49]
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"
    assert found.confidence == 0.5


def test_ed25519_findings_are_signature_without_size_expectation():
    findings = by_line(scan_fixture("signatures.go"))
    for line in (53, 57):
        assert findings[line].usage.value == "signature"
        assert findings[line].key_size is None
        assert "key_size_source" not in findings[line].extra
        assert findings[line].confidence == 1.0


# ---------------------------------------------------------------- MAC and KDF


def test_hmac_names_the_hash_and_a_loop_without_xor_stays_plain_hmac():
    findings = scan_fixture("mac_kdf.go")
    plain = [f for f in findings if f.raw_name.startswith("HMAC-")]
    assert [f.location.line for f in plain] == [14, 20, 26, 34]
    assert all(f.usage.value == "mac" for f in plain)
    assert not any("hand_rolled" in f.extra for f in plain)


def test_hand_rolled_pbkdf2_is_a_kdf_with_the_hand_rolled_marker():
    rolled = [f for f in scan_fixture("mac_kdf.go") if f.extra.get("hand_rolled")]
    assert [f.location.line for f in rolled] == [48, 55]
    for found in rolled:
        assert (found.raw_name, found.usage.value) == ("PBKDF2-HMAC-SHA256", "kdf")
        assert found.extra["hand_rolled"] is True
        assert found.key_size is None


def test_library_pbkdf2_is_not_marked_hand_rolled():
    for name, line in (("mac_kdf.go", 42), ("mac_kdf_stdlib.go", 9)):
        found = by_line(scan_fixture(name))[line]
        assert found.usage.value == "kdf"
        assert "hand_rolled" not in found.extra


# ---------------------------------------------------------------- RNG


def test_math_rand_calls_are_hygiene_only_and_rand_reader_is_not_a_call():
    findings = scan_fixture("rng_math.go")
    assert [f.location.line for f in findings] == [10, 15]
    for found in findings:
        assert found.extra["hygiene_only"] is True
        assert found.extra["hygiene_flags"] == ["insecure_rng"]
        assert (found.usage.value, found.kind_hint.value) == ("rng", "algorithm")
        assert found.confidence == 1.0


def test_crypto_rand_and_constant_time_compare_emit_nothing():
    assert scan_fixture("rng_crypto.go") == []


def test_aliased_math_rand_survives_only_as_an_import_only_finding():
    (found,) = scan_fixture("rng_alias.go")
    assert found.confidence == 0.6
    assert found.extra["hygiene_flags"] == ["insecure_rng"]


# ---------------------------------------------------------------- import-only findings


def test_import_only_findings_are_at_0_6_and_only_where_no_call_was_detected():
    findings = scan_fixture("imports_only.go")
    assert [(f.raw_name, f.confidence, f.location.line) for f in findings] == [
        ("sha1", 0.6, 4),
        ("sha256", 0.6, 5),
    ]
    assert findings[0].location.snippet == 'h1 "crypto/sha1"'


@pytest.mark.parametrize(
    "fixture",
    ["hashes.go", "mac_kdf.go", "mac_kdf_stdlib.go", "signatures.go", "ciphers.go", "rng_math.go"],
)
def test_a_call_finding_wins_over_the_import_of_the_same_package(fixture):
    findings = scan_fixture(fixture)
    assert not any(f.confidence == 0.6 for f in findings)


def test_sha256_imported_only_for_hmac_and_pbkdf2_produces_no_sha256_asset():
    for name in ("mac_kdf.go", "mac_kdf_stdlib.go"):
        assert "sha256" not in {f.raw_name for f in scan_fixture(name)}


# ---------------------------------------------------------------- starter kit (Appendix D.4, M1M3-08)


@pytest.mark.parametrize(
    "scenario, expected",
    [
        ("member-directory", [("md5", 10, None, None)]),
        ("release-feed", [("sha1", 10, None, None)]),
        (
            "invoice-service",
            [
                ("RSA", 13, 1024, None),
                ("sha1", 17, None, None),
                ("SHA1", 18, None, None),
                ("RSA", 18, 1024, None),
                ("sha1", 22, None, None),
                ("SHA1", 23, None, None),
                ("RSA", 23, 1024, None),
            ],
        ),
        (
            "agent-enrollment",
            [
                ("Ed25519", 11, None, None),
                ("Ed25519", 20, None, None),
                ("Ed25519", 21, None, None),
                ("Ed25519", 25, None, None),
            ],
        ),
        ("config-sync", [("sha384", 13, None, None), ("HMAC-sha256", 22, None, None)]),
        (
            "auth-gateway",
            [("PBKDF2-HMAC-SHA256", 25, None, None), ("PBKDF2-HMAC-SHA256", 34, None, None)],
        ),
        (
            "batch-pipeline",
            [
                ("hard-coded symmetric key", 10, None, None),
                ("AES", 22, 128, "ECB"),
                ("math/rand", 36, None, None),
            ],
        ),
        ("telemetry-relay", [("AES", 23, 256, "GCM"), ("AES", 40, 256, "GCM")]),
    ],
)
def test_starter_kit_go_files_match_appendix_d4_with_the_agreed_corrections(scenario, expected):
    findings = scan_path(KIT / scenario / "main.go", KIT)
    assert summary(findings) == expected


@pytest.mark.parametrize("scenario", ["config-sync", "auth-gateway", "telemetry-relay", "agent-enrollment"])
def test_safe_decoys_produce_no_md5_sha1_or_ecb_finding(scenario):
    findings = scan_path(KIT / scenario / "main.go", KIT)
    assert not {f.raw_name for f in findings} & {"md5", "sha1", "SHA1", "MD5", "math/rand"}
    assert not any(f.mode == "ECB" for f in findings)


def test_kit_aes_flow_lines_and_block_loop_evidence():
    ecb = [f for f in scan_path(KIT / "batch-pipeline" / "main.go", KIT) if f.raw_name == "AES"][0]
    assert ecb.extra["mode_source"] == "block_loop"
    assert ecb.extra["resolved_from_line"] == 10
    for found in scan_path(KIT / "telemetry-relay" / "main.go", KIT):
        assert found.extra["resolved_from_line"] == 12
        assert found.extra["key_size_source"] == "flow"


HARDCODED = "hard-coded symmetric key"
LITERAL_BYTES = ("0123456789ABCDEF", "fedcba9876543210", "shared-signing-key", "inline-key", "hop-key")


def hardcoded(name: str) -> dict[int, Finding]:
    return {f.location.line: f for f in scan_fixture(name) if f.raw_name == HARDCODED}


def test_hardcoded_key_fires_only_for_literals_reaching_an_aes_sink():
    assert sorted(hardcoded("hardcoded_keys.go")) == [10, 11, 21]


def test_hardcoded_key_shape_is_redacted_hygiene_only_and_has_no_key_bytes():
    found = hardcoded("hardcoded_keys.go")
    assert found
    for finding in found.values():
        assert (finding.kind_hint.value, finding.usage.value) == ("key", "encryption")
        assert finding.key_size is None
        assert finding.extra["hygiene_only"] is True
        assert finding.extra["hygiene_flags"] == ["hardcoded_key"]
        assert "<redacted>" in finding.location.snippet
        assert not any(text in repr(finding.model_dump()) for text in LITERAL_BYTES)


def test_hardcoded_key_through_a_call_site_hop_is_capped_at_0_8():
    found = hardcoded("hardcoded_keys.go")
    for line in (11,):
        assert found[line].confidence == 0.8
    assert {f.confidence for line, f in found.items() if line not in (11,)} == {1.0}


def test_hardcoded_key_kit_batch_pipeline_is_reported_at_the_literal():
    results = [f for f in scan_path(KIT / "batch-pipeline" / "main.go", KIT) if f.raw_name == HARDCODED]
    assert [f.location.line for f in results] == [10]
    assert results[0].location.snippet == "var exportKey = []byte(<redacted>)"


def test_hardcoded_key_kit_hmac_decoy_is_outside_the_rule():
    results = scan_path(KIT / "config-sync" / "main.go", KIT)
    assert not [f for f in results if f.raw_name == HARDCODED]
