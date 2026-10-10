from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan_fixture(name: str) -> list[Finding]:
    """Scan one fixture with the shipped rules. Paths are relative to FIXTURES, so none is a test path."""
    path = FIXTURES / "python" / name
    results = list(CodeScanner().scan(path, FIXTURES))
    assert all(isinstance(r, Finding) for r in results), results
    return results


def summary(findings: list[Finding]) -> list[tuple[str, int, int | None, str | None]]:
    return [(f.raw_name, f.location.line, f.key_size, f.mode) for f in findings]


@pytest.mark.parametrize(
    "fixture, expected",
    [
        (
            "hash_calls.py",
            [
                ("md5", 8, None, None),
                ("sha1", 12, None, None),
                ("sha384", 16, None, None),
                ("sha256", 20, None, None),
                ("MD5", 24, None, None),
            ],
        ),
        (
            "mac_kdf.py",
            [
                ("HMAC-sha256", 12, None, None),
                ("HMAC-sha512", 16, None, None),
                ("HMAC-sha1", 20, None, None),
                ("PBKDF2-HMAC-SHA256", 24, None, None),
                ("PBKDF2-HMAC-SHA1", 29, None, None),
            ],
        ),
        (
            "rsa_keys.py",
            [
                ("RSA", 7, 1024, None),
                ("RSA", 11, 3072, None),
                ("RSA", 15, 2048, None),
                ("RSA", 19, 4096, None),
            ],
        ),
        (
            "ed25519_keys.py",
            [("Ed25519", 6, None, None), ("Ed25519", 10, None, None)],
        ),
        (
            "aes_ciphers.py",
            [
                ("hard-coded symmetric key", 6, None, None),
                ("AES", 11, 128, "ECB"),
                ("AES", 16, None, "CBC"),
                ("AESGCM", 25, 256, "GCM"),
            ],
        ),
        (
            "rng_calls.py",
            [("random.getrandbits", 7, None, None), ("random.randbytes", 11, None, None)],
        ),
    ],
)
def test_fixture_raw_names_lines_sizes_and_modes(fixture, expected):
    assert summary(scan_fixture(fixture)) == expected


def test_findings_are_python_code_findings_outside_test_paths():
    findings = scan_fixture("hash_calls.py")
    assert {f.language for f in findings} == {"python"}
    assert not any(f.in_test_code for f in findings)
    assert all(f.location.file == "python/hash_calls.py" for f in findings)
    assert {f.detector for f in findings} == {
        "code.python.regex:PY_HASHLIB",
        "code.python.regex:PY_CRYPTOGRAPHY_HASH",
    }


def test_hash_decoys_and_comments_produce_nothing():
    rows = (FIXTURES / "python" / "hash_calls.py").read_text(encoding="utf-8").splitlines()
    decoys = {n for n, row in enumerate(rows, 1) if "compare_digest" in row or row.startswith("#")}
    assert len(decoys) == 2
    assert not decoys & {f.location.line for f in scan_fixture("hash_calls.py")}


def test_hash_class_inside_pbkdf2_is_not_reported_twice():
    names = [f.raw_name for f in scan_fixture("mac_kdf.py")]
    assert "SHA256" not in names and "SHA1" not in names


def test_rsa_key_size_sources():
    sources = {f.location.line: f.extra["key_size_source"] for f in scan_fixture("rsa_keys.py")}
    assert sources == {7: "literal", 11: "constant", 15: "literal", 19: "literal"}
    constant = next(f for f in scan_fixture("rsa_keys.py") if f.location.line == 11)
    assert constant.extra["resolved_from_line"] == 3


def test_rsa_sign_and_verify_take_the_generated_size_through_a_flow_link():
    by_line = {(f.raw_name, f.location.line): f for f in scan_fixture("rsa_flow.py")}
    for line in (11, 16):
        found = by_line[("RSA", line)]
        assert (found.key_size, found.usage.value, found.padding) == (1024, "signature", "PKCS1v15")
        assert found.extra["key_size_source"] == "flow"
        assert found.confidence == 0.8
    assert by_line[("SHA1", 11)].key_size is None
    assert by_line[("SHA1", 16)].key_size is None


def test_rsa_sign_of_an_unlinked_key_stays_unresolved():
    found = next(f for f in scan_fixture("rsa_flow.py") if f.raw_name == "RSA" and f.location.line == 23)
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"
    assert found.confidence == 0.5


def test_ed25519_sign_without_padding_is_not_rsa():
    names = {f.raw_name for f in scan_fixture("ed25519_keys.py")}
    assert names == {"Ed25519"}


def test_aes_size_from_parameter_default_and_flow():
    by_line = {f.location.line: f for f in scan_fixture("aes_ciphers.py")}
    default = by_line[11]
    assert default.extra["key_size_source"] == "param_default"
    assert default.extra["resolved_from_line"] == 6
    assert default.confidence == 1.0
    flowed = by_line[25]
    assert flowed.extra["key_size_source"] == "flow"
    assert flowed.extra["resolved_from_line"] == 7
    assert flowed.confidence == 0.8


def test_aes_with_unknown_key_size_is_unresolved_and_not_guessed():
    unknown = next(f for f in scan_fixture("aes_ciphers.py") if f.location.line == 16)
    assert unknown.key_size is None
    assert unknown.mode == "CBC"
    assert unknown.extra["key_size_source"] == "unresolved"
    assert unknown.confidence == 0.5


def test_os_urandom_and_secrets_emit_no_finding():
    findings = scan_fixture("rng_calls.py")
    assert {f.location.line for f in findings} == {7, 11}
    assert all(f.extra["hygiene_only"] is True for f in findings)
    assert all(f.extra["hygiene_flags"] == ["insecure_rng"] for f in findings)
    assert all(f.usage.value == "rng" and f.kind_hint.value == "algorithm" for f in findings)


HARDCODED = "hard-coded symmetric key"
LITERAL_BYTES = ("0123456789ABCDEF", "fedcba9876543210", "shared-signing-key", "inline-key", "hop-key")


def hardcoded(name: str) -> dict[int, Finding]:
    return {f.location.line: f for f in scan_fixture(name) if f.raw_name == HARDCODED}


def test_hardcoded_key_fires_only_for_literals_reaching_an_aes_sink():
    assert sorted(hardcoded("hardcoded_keys.py")) == [9, 10, 11, 26]


def test_hardcoded_key_shape_is_redacted_hygiene_only_and_has_no_key_bytes():
    found = hardcoded("hardcoded_keys.py")
    assert found
    for finding in found.values():
        assert (finding.kind_hint.value, finding.usage.value) == ("key", "encryption")
        assert finding.key_size is None
        assert finding.extra["hygiene_only"] is True
        assert finding.extra["hygiene_flags"] == ["hardcoded_key"]
        assert "<redacted>" in finding.location.snippet
        assert not any(text in repr(finding.model_dump()) for text in LITERAL_BYTES)


def test_hardcoded_key_through_a_call_site_hop_is_capped_at_0_8():
    found = hardcoded("hardcoded_keys.py")
    for line in (11,):
        assert found[line].confidence == 0.8
    assert {f.confidence for line, f in found.items() if line not in (11,)} == {1.0}


def test_hardcoded_key_kit_report_export_is_reported_at_the_literal():
    path = Path(__file__).parent.parent / "sample-repos" / "python" / "report_export.py"
    results = [f for f in CodeScanner().scan(path, path.parent) if f.raw_name == HARDCODED]
    assert [(f.location.line, f.location.snippet) for f in results] == [(5, "EXPORT_KEY = <redacted>")]


def test_hardcoded_key_kit_hmac_decoy_is_outside_the_rule():
    path = Path(__file__).parent.parent / "sample-repos" / "python" / "artifact_manifest.py"
    assert not [f for f in CodeScanner().scan(path, path.parent) if f.raw_name == HARDCODED]
