"""Go precision (session 19 problems 2 and 3): hand-rolled PBKDF2 evidence and math/rand next to crypto/rand."""

from pathlib import Path

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

KIT = Path(__file__).parent.parent / "sample-repos"


def scan(source: str) -> list[Finding]:
    return scan_source(source, "app.go", "go", load_rules("go"))


def names(findings: list[Finding]) -> list[tuple[str, int]]:
    return [(f.raw_name, f.location.line) for f in findings]


# ---------------------------------------------------------------- hand-rolled PBKDF2

PLAIN_HMAC_AND_COMPARE = """package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

func verify(key, msg, tag []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	want := mac.Sum(nil)
	var diff byte
	for i := range want {
		diff |= want[i] ^ tag[i]
	}
	return diff == 0
}
"""

MASKED_LOOP_WITHOUT_FEEDBACK = """package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

func seal(key, data, mask []byte) []byte {
	mac := hmac.New(sha256.New, key)
	for i := range data {
		data[i] ^= mask[i]
	}
	mac.Write(data)
	return mac.Sum(nil)
}
"""

HAND_ROLLED_SHA1 = """package main

import (
	"crypto/hmac"
	"crypto/sha1"
)

func derive(password, salt []byte, iter int) []byte {
	mac := hmac.New(sha1.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	t := append([]byte(nil), u...)
	for n := 1; n < iter; n++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for k := range t {
			t[k] = t[k] ^ u[k]
		}
	}
	return t
}
"""


def test_plain_hmac_with_constant_time_compare_loop_is_hmac_not_pbkdf2() -> None:
    (finding,) = scan(PLAIN_HMAC_AND_COMPARE)
    assert finding.raw_name == "HMAC-sha256"
    assert finding.confidence == 1.0
    assert "hand_rolled" not in finding.extra


def test_xor_loop_without_hmac_output_feedback_is_plain_hmac() -> None:
    (finding,) = scan(MASKED_LOOP_WITHOUT_FEEDBACK)
    assert finding.raw_name == "HMAC-sha256"
    assert "hand_rolled" not in finding.extra


def test_hand_rolled_sha1_with_reset_idiom_is_pbkdf2_at_most_08() -> None:
    (finding,) = scan(HAND_ROLLED_SHA1)
    assert finding.raw_name == "PBKDF2-HMAC-SHA1"
    assert finding.extra["hand_rolled"] is True
    assert finding.confidence <= 0.8


def test_kit_auth_gateway_keeps_both_pbkdf2_occurrences() -> None:
    path = KIT / "go" / "auth-gateway" / "main.go"
    found = [r for r in CodeScanner().scan(path, KIT) if isinstance(r, Finding)]
    hand_rolled = [f for f in found if f.raw_name == "PBKDF2-HMAC-SHA256"]
    assert [f.location.line for f in hand_rolled] == [25, 34]
    assert all(f.extra["hand_rolled"] is True and f.confidence <= 0.8 for f in hand_rolled)
    assert not [f for f in found if f.raw_name.startswith("HMAC")]


def test_kit_config_sync_plain_hmac_stays_hmac() -> None:
    path = KIT / "go" / "config-sync" / "main.go"
    found = [r for r in CodeScanner().scan(path, KIT) if isinstance(r, Finding)]
    assert [f.raw_name for f in found if f.kind_hint.value == "algorithm" and f.usage.value == "mac"] == [
        "HMAC-sha256"
    ]
    assert not [f for f in found if f.extra.get("hand_rolled")]


# ---------------------------------------------------------------- math/rand next to crypto/rand

ALIASED_MATH_WITH_CRYPTO = """package main

import (
	"crypto/rand"
	mrand "math/rand"
)

func token() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

func jitter() int {
	return mrand.Intn(100)
}
"""

PLAIN_MATH_WITH_ALIASED_CRYPTO = """package main

import (
	crand "crypto/rand"
	"math/rand"
)

func token() []byte {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	return b
}

func pick(n int) int {
	return rand.Intn(n)
}
"""

CRYPTO_ONLY = """package main

import "crypto/rand"

func token() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}
"""


def test_aliased_math_rand_with_crypto_rand_is_reported() -> None:
    (finding,) = scan(ALIASED_MATH_WITH_CRYPTO)
    assert finding.raw_name == "math/rand"
    assert finding.extra["hygiene_flags"] == ["insecure_rng"]
    assert finding.location.line == 5


def test_plain_math_rand_with_aliased_crypto_rand_flags_only_the_math_call() -> None:
    findings = scan(PLAIN_MATH_WITH_ALIASED_CRYPTO)
    assert names(findings) == [("math/rand", 15)]


def test_crypto_rand_alone_emits_nothing() -> None:
    assert scan(CRYPTO_ONLY) == []
