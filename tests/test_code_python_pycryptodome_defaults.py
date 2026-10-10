"""PyCryptodome library defaults are reported with parameter_source library_default (session 26 ruling)."""

from pathlib import Path

import pytest

from quantumtrace.engine import analyze
from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "code"


def scan_fixture(name: str) -> list[Finding]:
    path = FIXTURES / "python" / name
    return [f for f in CodeScanner().scan(path, FIXTURES) if isinstance(f, Finding)]


def scan(source: str) -> list[Finding]:
    return scan_source(source, "app.py", "python", load_rules("python"))


def row(f: Finding) -> tuple[int, str, float, int | None, str | None]:
    return (
        f.location.line,
        f.raw_name,
        f.confidence,
        f.extra.get("iterations"),
        f.extra.get("parameter_source"),
    )


def test_defaults_and_explicit_values_in_the_fixture() -> None:
    assert [row(f) for f in scan_fixture("pycryptodome_defaults.py")] == [
        (6, "HMAC-MD5", 0.8, None, "library_default"),
        (10, "HMAC-MD5", 0.8, None, "library_default"),
        (14, "HMAC-MD5", 0.8, None, "library_default"),
        (18, "HMAC-SHA256", 1.0, None, None),
        (22, "HMAC-SHA256", 1.0, None, None),
        (30, "PBKDF2-HMAC-SHA1", 0.8, 1000, "library_default"),
        (34, "PBKDF2-HMAC-SHA1", 0.8, 600000, "library_default"),
        (38, "PBKDF2-HMAC-SHA1", 0.8, 2000, "library_default"),
        (42, "PBKDF2-HMAC-SHA256", 0.8, 1000, "library_default"),
        (46, "PBKDF2-HMAC-SHA256", 1.0, 8000, None),
        (58, "PBKDF2-HMAC-SHA1", 0.8, None, "library_default"),
    ]


def test_star_arguments_and_prf_emit_no_default() -> None:
    found = scan_fixture("pycryptodome_defaults.py")
    assert {f.location.line for f in found}.isdisjoint({26, 50, 54})


def test_only_the_library_default_value_is_used() -> None:
    for f in scan_fixture("pycryptodome_defaults.py"):
        assert f.extra.get("parameter_source") in (None, "library_default")
        assert f.library == "pycryptodome"


def test_default_needs_a_pycryptodome_mention() -> None:
    src = "import hmac\nfrom mylib import PBKDF2\na = PBKDF2(password, salt)\nb = hmac.HMAC.new(key, msg)\n"
    assert scan(src) == []


def test_other_libraries_never_carry_parameter_source() -> None:
    for name in ("pbkdf2_hashlib.py", "pbkdf2_iterations.py"):
        for f in scan_fixture(name):
            if f.library != "pycryptodome":
                assert "parameter_source" not in f.extra


def test_a_rule_cannot_set_another_parameter_source(tmp_path: Path) -> None:
    (tmp_path / "python.yaml").write_text(
        "- id: X\n  language: python\n  pattern: 'foo\\('\n  raw_name: MD5\n  kind_hint: algorithm\n"
        "  usage: hash\n  parameter_source: guessed\n"
    )
    with pytest.raises(ValueError, match="parameter_source"):
        load_rules("python", tmp_path)


def test_through_the_engine() -> None:
    assets, _ = analyze(scan_fixture("pycryptodome_defaults.py"))
    assert {a.canonical_name for a in assets} == {"PBKDF2", "HMAC-MD5", "HMAC-SHA256"}
    assert not any(a.canonical_name == "Unknown" for a in assets)
