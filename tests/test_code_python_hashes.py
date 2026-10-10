"""PY_CRYPTOGRAPHY_HASH inside and outside PBKDF2HMAC (session 19 problem 4)."""

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import load_rules, scan_source

HEAD = (
    "from cryptography.hazmat.primitives import hashes\n"
    "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
    "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
)


def scan(body: str, head: str = HEAD) -> list[Finding]:
    return scan_source(head + body, "app.py", "python", load_rules("python"))


def names(findings: list[Finding]) -> list[tuple[str, int]]:
    return [(f.raw_name, f.location.line) for f in findings]


def test_hkdf_algorithm_keyword_reports_the_hash() -> None:
    findings = scan("kdf = HKDF(algorithm=hashes.SHA1(), length=32, salt=None, info=b'x')\n")
    assert names(findings) == [("SHA1", 4)]


def test_hkdf_algorithm_keyword_with_spaces_reports_the_hash() -> None:
    findings = scan("kdf = HKDF(algorithm = hashes.SHA384(), length=32, salt=None, info=b'x')\n")
    assert names(findings) == [("SHA384", 4)]


def test_pbkdf2_algorithm_with_spaces_is_one_finding() -> None:
    findings = scan("kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length=32, salt=s, iterations=600000)\n")
    assert names(findings) == [("PBKDF2-HMAC-SHA256", 4)]


def test_pbkdf2_algorithm_keyword_is_one_finding() -> None:
    findings = scan("kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=s, iterations=1000)\n")
    assert names(findings) == [("PBKDF2-HMAC-SHA1", 4)]


def test_pbkdf2_algorithm_on_its_own_line_is_one_finding() -> None:
    body = "kdf = PBKDF2HMAC(\n    length=32,\n    salt=s,\n    algorithm=hashes.SHA512(),\n    iterations=1,\n)\n"
    assert names(scan(body)) == [("PBKDF2-HMAC-SHA512", 4)]


def test_positional_pbkdf2_hash_is_one_finding() -> None:
    findings = scan("kdf = PBKDF2HMAC(hashes.SHA1(), 32, s, 1000)\n")
    assert names(findings) == [("PBKDF2-HMAC-SHA1", 4)]


def test_hash_next_to_pbkdf2_on_another_statement_is_still_reported() -> None:
    body = (
        "kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=600000)\n"
        "other = HKDF(algorithm=hashes.SHA1(), length=16, salt=None, info=None)\n"
    )
    assert names(scan(body)) == [("PBKDF2-HMAC-SHA256", 4), ("SHA1", 5)]


def test_unparsable_file_keeps_the_pbkdf2_suppression() -> None:
    body = "print 'legacy'\nkdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=1)\n"
    assert names(scan(body)) == [("PBKDF2-HMAC-SHA256", 5)]


def test_aliased_hashes_module_follows_the_same_rule() -> None:
    head = (
        "from cryptography.hazmat.primitives import hashes as H\n"
        "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
        "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
    )
    body = (
        "a = PBKDF2HMAC(algorithm=H.SHA256(), length=32, salt=s, iterations=1)\n"
        "b = HKDF(algorithm=H.SHA1(), length=16, salt=None, info=None)\n"
    )
    assert names(scan(body, head)) == [("PBKDF2-HMAC-SHA256", 4), ("SHA1", 5)]


def test_oaep_hash_is_reported_like_a_pss_hash() -> None:
    """Decided with the user (session 20): the OAEP and MGF1 hash is a finding, not a special case."""
    head = HEAD + "from cryptography.hazmat.primitives.asymmetric import padding\n"
    body = "ct = pub.encrypt(m, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1()))\n"
    found = [f for f in scan(body, head) if f.usage.value == "hash"]
    assert names(found) == [("SHA1", 5)]
