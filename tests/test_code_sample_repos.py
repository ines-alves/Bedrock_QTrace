"""Diff of the 24 starter-kit files against Appendix D.4 with the M1M3-08 corrections (M3D-04).

The expected rows are written from D.4 and M1M3-08, not from scanner output. A finding matches a row
when file, raw_name, key_size, mode and hygiene flag are equal and the lines are within LINE_TOLERANCE.
Matching is one to one: a finding satisfies one row and a row one finding. Rows are never merged or
loosened to fit a result. Tier, threat and score are the engine's, so they are not compared here.

Raw names for Python and Go are the scanner's as-seen names; the M1M3 item that lists them is pending.
"""

from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner

KIT = Path(__file__).parent.parent / "sample-repos"
LINE_TOLERANCE = 2
SUFFIXES = {".py", ".java", ".go"}

Row = tuple[int, str, int | None, str | None, str | None]


def r(
    line: int, raw_name: str, key_size: int | None = None, mode: str | None = None, flag: str | None = None
) -> Row:
    return (line, raw_name, key_size, mode, flag)


HARDCODED = "hard-coded symmetric key"

# Appendix D.4 (lines 1-based), with M1M3-08: PBKDF2 anchors, Ed25519 Verify repeats, AES key flow lines,
# RSA size line, hard-coded AES key at the literal (3 files only, the HMAC decoys are outside the rule).
EXPECTED: dict[str, list[Row]] = {
    # MD5 password hash
    "python/legacy_accounts.py": [r(5, "md5")],
    "java/CustomerDirectory.java": [r(8, "MD5")],
    "go/member-directory/main.go": [r(10, "md5")],
    # SHA-1 checksum
    "python/update_feed.py": [r(5, "sha1")],
    "java/PatchFeed.java": [r(8, "SHA-1")],
    "go/release-feed/main.go": [r(10, "sha1")],
    # RSA-1024 + SHA-1 signing
    "python/license_token.py": [
        r(6, "RSA", 1024),
        r(11, "SHA1"),
        r(11, "RSA", 1024),
        r(16, "SHA1"),
        r(16, "RSA", 1024),
    ],
    "java/ReceiptSigner.java": [
        r(12, "RSA", 1024),
        r(18, "SHA1withRSA", 1024),
        r(25, "SHA1withRSA", 1024),
    ],
    "go/invoice-service/main.go": [
        r(13, "RSA", 1024),
        r(17, "sha1"),
        r(18, "SHA1"),
        r(18, "RSA", 1024),
        r(22, "sha1"),
        r(23, "SHA1"),
        r(23, "RSA", 1024),
    ],
    # Ed25519 signing (Go L4 is the import, see NOT_EMITTED)
    "python/webhook_signature.py": [r(5, "Ed25519")],
    "java/DeviceAttestation.java": [r(12, "Ed25519"), r(17, "Ed25519"), r(24, "Ed25519")],
    "go/agent-enrollment/main.go": [
        r(11, "Ed25519"),
        r(20, "Ed25519"),
        r(21, "Ed25519"),
        r(25, "Ed25519"),
    ],
    # SHA-384 + HMAC-SHA256 (SAFE decoys); the HMAC key literals produce no hard-coded key finding
    "python/artifact_manifest.py": [r(6, "sha384"), r(14, "HMAC-sha256")],
    "java/ConfigSync.java": [r(10, "SHA-384"), r(20, "HmacSHA256")],
    "go/config-sync/main.go": [r(13, "sha384"), r(22, "HMAC-sha256")],
    # PBKDF2-HMAC-SHA256 (SAFE decoys); Go is hand-rolled, span L19-L44, hmac.New at L25 and L34
    "python/member_credentials.py": [r(13, "PBKDF2-HMAC-SHA256"), r(18, "PBKDF2-HMAC-SHA256")],
    "java/IdentityVault.java": [r(22, "PBKDF2WithHmacSHA256")],
    "go/auth-gateway/main.go": [r(25, "PBKDF2-HMAC-SHA256"), r(34, "PBKDF2-HMAC-SHA256")],
    # AES-128-ECB + insecure RNG + hard-coded AES key (literal lines 5, 9, 10)
    "python/report_export.py": [
        r(5, HARDCODED, flag="hardcoded_key"),
        r(11, "AES", 128, "ECB"),
        r(17, "random.getrandbits", flag="insecure_rng"),
    ],
    "java/BatchExporter.java": [
        r(9, HARDCODED, flag="hardcoded_key"),
        r(14, "AES/ECB/PKCS5Padding", 128, "ECB"),
        r(21, "java.util.Random", flag="insecure_rng"),
    ],
    "go/batch-pipeline/main.go": [
        r(10, HARDCODED, flag="hardcoded_key"),
        r(22, "AES", 128, "ECB"),
        r(36, "math/rand", flag="insecure_rng"),
    ],
    # AES-256-GCM (SAFE decoys); the 256 comes from a key generation elsewhere in the file (M1M3-08)
    "python/secure_transfer.py": [r(16, "AESGCM", 256, "GCM"), r(21, "AESGCM", 256, "GCM")],
    "java/SessionCipher.java": [
        r(30, "AES/GCM/NoPadding", 256, "GCM"),
        r(39, "AES/GCM/NoPadding", 256, "GCM"),
    ],
    "go/telemetry-relay/main.go": [r(23, "AES", 256, "GCM"), r(40, "AES", 256, "GCM")],
}

# D.4 lines for which the scanner emits no finding, by design. Each is asserted absent within the tolerance,
# so a rule change that starts emitting one flips the test and has to be decided.
NOT_EMITTED: list[tuple[str, int, str]] = [
    (
        "go/agent-enrollment/main.go",
        4,
        'import "crypto/ed25519": call findings at L11, L20, L21, L25 win over import-only',
    ),
    (
        "go/batch-pipeline/main.go",
        7,
        'import "math/rand": the call finding at L36 wins over the import-only finding',
    ),
    (
        "go/telemetry-relay/main.go",
        27,
        "cipher.NewGCM in encrypt: D.4 context line, the AES finding is at aes.NewCipher (L23)",
    ),
    (
        "go/telemetry-relay/main.go",
        44,
        "cipher.NewGCM in decrypt: D.4 context line, the AES finding is at aes.NewCipher (L40)",
    ),
    (
        "java/SessionCipher.java",
        18,
        'KeyGenerator.getInstance("AES"): source of the 256 bits, not an occurrence; findings at L30 and L39',
    ),
    (
        "java/SessionCipher.java",
        19,
        "generator.init(KEY_BITS, ...): source of the 256 bits, not an occurrence; findings at L30 and L39",
    ),
]


def kit_files() -> list[str]:
    return sorted(p.relative_to(KIT).as_posix() for p in KIT.rglob("*") if p.suffix in SUFFIXES)


def scan_kit(rel: str) -> list[Finding]:
    results = list(CodeScanner().scan(KIT / rel, KIT))
    assert all(isinstance(f, Finding) for f in results), results
    return results


def row_of(finding: Finding) -> Row:
    flags = finding.extra.get("hygiene_flags")
    flag = flags[0] if flags else None
    return (finding.location.line, finding.raw_name, finding.key_size, finding.mode, flag)


def diff(expected: list[Row], found: list[Row]) -> tuple[list[Row], list[Row]]:
    """One to one match within LINE_TOLERANCE; returns (missing rows, unexpected findings)."""
    unused = list(found)
    missing: list[Row] = []
    for want in expected:
        candidates = [
            got for got in unused if got[1:] == want[1:] and abs(got[0] - want[0]) <= LINE_TOLERANCE
        ]
        if not candidates:
            missing.append(want)
            continue
        unused.remove(min(candidates, key=lambda got: (abs(got[0] - want[0]), got[0])))
    return missing, unused


def test_kit_has_exactly_the_24_expected_files():
    files = kit_files()
    assert len(files) == 24
    assert files == sorted(EXPECTED)


@pytest.mark.parametrize("rel", sorted(EXPECTED))
def test_kit_file_matches_appendix_d4_with_the_agreed_corrections(rel):
    missing, unexpected = diff(EXPECTED[rel], [row_of(f) for f in scan_kit(rel)])
    assert not missing, f"{rel}: expected rows with no finding: {missing}"
    assert not unexpected, f"{rel}: findings with no expected row: {unexpected}"


@pytest.mark.parametrize(
    "rel, line, reason", NOT_EMITTED, ids=[f"{rel}:{line}" for rel, line, _ in NOT_EMITTED]
)
def test_d4_lines_that_are_not_emitted_stay_absent(rel, line, reason):
    near = [row_of(f) for f in scan_kit(rel) if abs(f.location.line - line) <= LINE_TOLERANCE]
    assert not near, f"{rel}:{line} ({reason}) now has findings: {near}"


def test_kit_findings_use_root_relative_paths_and_none_is_test_code():
    for rel in sorted(EXPECTED):
        for finding in scan_kit(rel):
            assert finding.location.file == rel
            assert not finding.in_test_code
