import re
from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, _parse_rule, mask_comments, scan_source
from quantumtrace.scanners.code.python_ast import resolve_aliases

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan_gaps() -> list[Finding]:
    results = list(CodeScanner().scan(FIXTURES / "python" / "gaps.py", FIXTURES))
    assert all(isinstance(r, Finding) for r in results), results
    return results


def test_gaps_fixture_findings():
    got = [(f.raw_name, f.location.line, f.mode, f.extra["rule"]) for f in scan_gaps()]
    assert got == [
        ("md5", 13, None, "PY_HASHLIB_NEW"),
        ("SHA256", 17, None, "PY_HASHLIB_NEW"),
        ("unresolved", 21, None, "PY_HASHLIB_NEW_UNRESOLVED"),
        ("HMAC-sha1", 33, None, "PY_HMAC_STRING"),
        ("HMAC-sha256", 37, None, "PY_HMAC_STRING"),
        ("HMAC-sha512", 41, None, "PY_HMAC"),
        ("AES", 45, "ECB", "PY_AES_CIPHER"),
        ("AES", 49, "CBC", "PY_AES_CIPHER"),
        ("PBKDF2-HMAC-SHA1", 53, None, "PY_PBKDF2"),
        ("PBKDF2-HMAC-SHA256", 57, None, "PY_PBKDF2"),
    ]


def test_hashlib_new_constant_carries_the_constant_line():
    finding = next(f for f in scan_gaps() if f.location.line == 17)
    assert finding.extra["resolved_from_line"] == 8
    assert finding.confidence == 1.0


def test_hashlib_new_unknown_name_emits_nothing_and_unresolved_is_reported_unnamed():
    findings = scan_gaps()
    assert not {f.location.line for f in findings} & {25, 29}
    (unresolved,) = [f for f in findings if f.location.line == 21]
    assert (unresolved.raw_name, unresolved.confidence) == ("unresolved", 0.5)


def test_hmac_string_message_is_not_taken_as_the_digest():
    names = [f.raw_name for f in scan_gaps() if f.location.line == 41]
    assert names == ["HMAC-sha512"]


def test_positional_pbkdf2_is_reported_once_as_the_composite():
    names = [f.raw_name for f in scan_gaps() if f.location.line >= 52]
    assert names == ["PBKDF2-HMAC-SHA1", "PBKDF2-HMAC-SHA256"]


def test_keyword_modes_are_stated_by_the_call_and_size_stays_unresolved():
    ciphers = [f for f in scan_gaps() if f.raw_name == "AES"]
    assert [f.mode for f in ciphers] == ["ECB", "CBC"]
    assert all(f.key_size is None and f.confidence <= 0.5 for f in ciphers)


# ---------------------------------------------------------------- positional PBKDF2 rewrite


def resolve(source: str) -> str:
    return resolve_aliases(source, mask_comments(source, "python"))


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            "k = PBKDF2HMAC(hashes.SHA1(), 32, s, 1)\n",
            "k = PBKDF2HMAC(algorithm=hashes.SHA1(), 32, s, 1)\n",
        ),
        (
            "k = PBKDF2HMAC(\n    hashes.SHA256(),\n    32,\n)\n",
            "k = PBKDF2HMAC(\n    algorithm=hashes.SHA256(),\n    32,\n)\n",
        ),
        (
            "from cryptography.hazmat.primitives.hashes import SHA1\nk = PBKDF2HMAC(SHA1(), 32)\n",
            "from cryptography.hazmat.primitives.hashes import SHA1\nk = PBKDF2HMAC(algorithm=hashes.SHA1(), 32)\n",
        ),
        (
            "from x.pbkdf2 import PBKDF2HMAC as P\nk = P(hashes.MD5(), 32)\n",
            "from x.pbkdf2 import PBKDF2HMAC as P\nk = PBKDF2HMAC(algorithm=hashes.MD5(), 32)\n",
        ),
    ],
)
def test_positional_algorithm_gets_the_keyword(source: str, expected: str):
    result = resolve(source)
    assert re.sub(r"\s+", " ", result) == re.sub(r"\s+", " ", expected)
    assert result.count("\n") == source.count("\n")


@pytest.mark.parametrize(
    "source",
    [
        "k = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32)\n",
        "k = PBKDF2HMAC(length=32, algorithm=hashes.SHA1())\n",
        "k = PBKDF2HMAC(get_hash(), 32)\n",
        "k = PBKDF2HMAC(hashes.SHA1)\n",
        "k = PBKDF2HMAC(**opts)\n",
        "def PBKDF2HMAC(a, b):\n    pass\nk = PBKDF2HMAC(hashes.SHA1(), 32)\n",
        "k = Other(hashes.SHA1(), 32)\n",
    ],
)
def test_other_calls_are_left_alone(source: str):
    masked = mask_comments(source, "python")
    assert resolve_aliases(source, masked) is masked


def test_positional_rewrite_and_syntax_error_fallback():
    source = "k = PBKDF2HMAC(hashes.SHA1(), 32\n"
    masked = mask_comments(source, "python")
    assert resolve_aliases(source, masked) is masked


# ---------------------------------------------------------------- values_must_match


def rule(**extra):
    base = {
        "id": "T",
        "language": "python",
        "pattern": r"\bnew\((?P<name_ref>[A-Za-z_]\w*)\)",
        "raw_name": "{name}",
        "kind_hint": "algorithm",
        "usage": "hash",
    }
    return _parse_rule({**base, **extra}, "test")


def scan(src: str, r):
    return [f.raw_name for f in scan_source(src, "t.py", "python", [r])]


def test_values_must_match_keeps_only_matching_resolved_values():
    r = rule(values_must_match={"name": "(?i)md5|sha1"})
    assert scan('A = "md5"\nnew(A)\n', r) == ["md5"]
    assert scan('A = "blake2b"\nnew(A)\n', r) == []
    assert scan("new(UNKNOWN)\n", r) == []


def test_without_values_must_match_an_unresolved_name_is_kept_at_half_confidence():
    findings = scan_source("new(UNKNOWN)\n", "t.py", "python", [rule()])
    assert [(f.raw_name, f.confidence, f.extra["unresolved_argument"]) for f in findings] == [
        ("unresolved", 0.5, "UNKNOWN")
    ]


def test_values_must_match_is_validated():
    with pytest.raises(ValueError, match="values_must_match"):
        rule(values_must_match=["name"])
    with pytest.raises(ValueError, match="invalid regex"):
        rule(values_must_match={"name": "("})
