from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan_fixture(name: str) -> list[Finding]:
    """Scan one fixture with the shipped rules. Paths are relative to FIXTURES, so none is a test path."""
    path = FIXTURES / "java" / name
    results = list(CodeScanner().scan(path, FIXTURES))
    assert all(isinstance(r, Finding) for r in results), results
    return results


def by_line(findings: list[Finding]) -> dict[int, Finding]:
    return {f.location.line: f for f in findings}


def summary(findings: list[Finding]) -> list[tuple[str, int, int | None, str | None]]:
    return [(f.raw_name, f.location.line, f.key_size, f.mode) for f in findings]


@pytest.mark.parametrize(
    "fixture, expected",
    [
        (
            "Hashes.java",
            [
                ("MD5", 6, None, None),
                ("SHA-1", 10, None, None),
                ("SHA-384", 14, None, None),
                ("SHA-256", 18, None, None),
            ],
        ),
        (
            "MacKdf.java",
            [
                ("HmacSHA256", 9, None, None),
                ("HmacSHA1", 15, None, None),
                ("PBKDF2WithHmacSHA256", 22, None, None),
                ("PBKDF2WithHmacSHA1", 27, None, None),
            ],
        ),
        (
            "Signatures.java",
            [
                ("RSA", 12, 2048, None),
                ("SHA256withRSA", 18, 2048, None),
                ("SHA256withRSA", 25, 2048, None),
                ("SHA256withRSA", 32, None, None),
                ("Ed25519", 39, None, None),
                ("Ed25519", 43, None, None),
                ("SHA256withECDSA", 50, None, None),
            ],
        ),
        (
            "Ciphers.java",
            [
                ("AES/ECB/PKCS5Padding", 16, 128, "ECB"),
                ("AES/GCM/NoPadding", 28, 256, "GCM"),
                ("AES/GCM/NoPadding", 34, 256, "GCM"),
                ("AES", 40, None, None),
                ("AES", 46, None, None),
                ("AES/CBC/PKCS5Padding", 52, None, "CBC"),
                ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", 58, None, None),
            ],
        ),
        ("RandomCalls.java", [("java.util.Random", 8, None, None)]),
    ],
)
def test_fixture_raw_names_lines_sizes_and_modes(fixture, expected):
    assert summary(scan_fixture(fixture)) == expected


def test_findings_are_java_code_findings_outside_test_paths():
    findings = scan_fixture("Hashes.java")
    assert {f.language for f in findings} == {"java"}
    assert not any(f.in_test_code for f in findings)
    assert all(f.location.file == "java/Hashes.java" for f in findings)
    assert {f.detector for f in findings} == {"code.java.regex:JAVA_MESSAGE_DIGEST"}


def test_digest_decoys_and_comments_produce_nothing():
    rows = (FIXTURES / "java" / "Hashes.java").read_text(encoding="utf-8").splitlines()
    decoys = {n for n, row in enumerate(rows, 1) if "isEqual" in row or row.strip().startswith("//")}
    assert len(decoys) == 2
    assert not decoys & {f.location.line for f in scan_fixture("Hashes.java")}


def test_rsa_generation_reads_the_size_from_the_following_initialize_call():
    generation = by_line(scan_fixture("Signatures.java"))[12]
    assert (generation.raw_name, generation.key_size) == ("RSA", 2048)
    assert generation.extra["key_size_source"] == "lookahead"
    assert generation.extra["resolved_from_line"] == 9
    assert generation.confidence == 0.8


def test_rsa_sign_and_verify_take_the_generated_size_through_a_flow_link():
    findings = by_line(scan_fixture("Signatures.java"))
    for line in (18, 25):
        found = findings[line]
        assert (found.raw_name, found.key_size, found.usage.value) == ("SHA256withRSA", 2048, "signature")
        assert found.extra["key_size_source"] == "flow"
        assert found.confidence == 0.8


def test_rsa_signature_with_an_imported_key_stays_unresolved():
    found = by_line(scan_fixture("Signatures.java"))[32]
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"
    assert found.confidence == 0.5


def test_non_rsa_signatures_carry_no_size_expectation():
    findings = by_line(scan_fixture("Signatures.java"))
    for line in (39, 43, 50):
        assert findings[line].key_size is None
        assert "key_size_source" not in findings[line].extra
        assert findings[line].confidence == 1.0


def test_explicit_transform_through_a_constant_sets_mode_padding_and_size_lines():
    found = by_line(scan_fixture("Ciphers.java"))[16]
    assert (found.mode, found.padding) == ("ECB", "PKCS5Padding")
    assert found.extra["key_size_source"] == "flow"
    assert found.extra["resolved_from_line"] == 9
    assert found.confidence == 0.8


def test_aes_256_from_key_generator_reaches_literal_and_constant_transforms():
    findings = by_line(scan_fixture("Ciphers.java"))
    for line in (28, 34):
        assert findings[line].key_size == 256
        assert findings[line].extra["key_size_source"] == "flow"
        assert findings[line].extra["resolved_from_line"] == 12


@pytest.mark.parametrize("line", [40, 46])
def test_bare_aes_and_custom_provider_leave_mode_none(line):
    found = by_line(scan_fixture("Ciphers.java"))[line]
    assert found.raw_name == "AES"
    assert found.mode is None
    assert "mode_source" not in found.extra
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"
    assert found.confidence == 0.5


def test_aes_with_an_imported_key_keeps_its_explicit_mode_but_no_size():
    found = by_line(scan_fixture("Ciphers.java"))[52]
    assert (found.mode, found.key_size) == ("CBC", None)
    assert found.extra["key_size_source"] == "unresolved"
    assert found.confidence == 0.5


def test_rsa_transform_sets_no_mode_and_expects_no_aes_size():
    found = by_line(scan_fixture("Ciphers.java"))[58]
    assert (found.mode, found.padding, found.key_size) == (None, None, None)
    assert "key_size_source" not in found.extra
    assert found.confidence == 1.0


def test_secure_random_emits_no_finding_and_new_random_is_hygiene_only():
    findings = scan_fixture("RandomCalls.java")
    assert [f.location.line for f in findings] == [8]
    found = findings[0]
    assert found.extra["hygiene_only"] is True
    assert found.extra["hygiene_flags"] == ["insecure_rng"]
    assert (found.usage.value, found.kind_hint.value) == ("rng", "algorithm")
