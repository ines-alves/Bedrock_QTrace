import re
from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, load_rules

FIXTURES = Path(__file__).parent / "fixtures" / "code"
NOT_SET = "not set"

PYTHON_EXPECTED = {
    "literal": 1000,
    "keyword": 600_000,
    "constant": 210_000,
    "computed": NOT_SET,
    "from_environment": NOT_SET,
    "param_default": 300_000,
    "one_hop": 50_000,
    "sites_agree": 7000,
    "sites_disagree": NOT_SET,
    "two_hops": NOT_SET,
    "cryptography_keyword": 2000,
    "cryptography_positional": 5000,
    "pycryptodome_keyword": 4000,
    "pycryptodome_positional": 8000,
    "pycryptodome_default_count": NOT_SET,
}

JAVA_EXPECTED = {
    "literal": 10000,
    "constant": 600_000,
    "computed": NOT_SET,
    "parameter": 65536,
    "two_specs": NOT_SET,
    "without_length": 4096,
}

GO_EXPECTED = {
    "literal": 4096,
    "constant": 210_000,
    "computed": NOT_SET,
    "viaParameter": 100000,
    "handRolled": 10000,
    "handRolledFixed": NOT_SET,
}


def by_function(relative: str, definition: str) -> dict[str, list[Finding]]:
    path = FIXTURES / relative
    results = list(CodeScanner().scan(path, FIXTURES))
    assert all(isinstance(r, Finding) for r in results), results
    lines = path.read_text().split("\n")
    grouped: dict[str, list[Finding]] = {}
    for finding in results:
        assert isinstance(finding, Finding)
        for index in range(finding.location.line - 1, -1, -1):
            m = re.search(definition, lines[index])
            if m:
                grouped.setdefault(m.group(1), []).append(finding)
                break
    return grouped


def values(grouped: dict[str, list[Finding]]) -> dict[str, object]:
    return {
        name: (found[0].extra["iterations"] if found[0].extra.get("iterations") is not None else NOT_SET)
        for name, found in grouped.items()
    }


def test_python_iterations():
    got = values(by_function("python/pbkdf2_iterations.py", r"^def (\w+)\("))
    assert got == PYTHON_EXPECTED


def test_java_iterations():
    got = values(by_function("java/PbkdfIterations.java", r"^\s+byte\[\] (\w+)\("))
    assert got == JAVA_EXPECTED


def test_go_iterations():
    got = values(by_function("go/pbkdf2_iterations.go", r"^func (\w+)\("))
    assert got == GO_EXPECTED


def test_go_stdlib_hash_first_signature():
    got = values(by_function("go/pbkdf2_iterations_stdlib.go", r"^func (\w+)\("))
    assert got == {"stdlib": 600_000}


def test_iterations_is_an_int_and_never_zero_or_bool():
    seen = []
    for relative, definition in (
        ("python/pbkdf2_iterations.py", r"^def (\w+)\("),
        ("java/PbkdfIterations.java", r"^\s+byte\[\] (\w+)\("),
        ("go/pbkdf2_iterations.go", r"^func (\w+)\("),
    ):
        for findings in by_function(relative, definition).values():
            for finding in findings:
                if "iterations" in finding.extra:
                    seen.append(finding.extra["iterations"])
    assert seen
    assert all(type(value) is int and value > 0 for value in seen)


def test_iterations_does_not_change_confidence_or_identity():
    grouped = by_function("python/pbkdf2_iterations.py", r"^def (\w+)\(")
    assert grouped["literal"][0].confidence == 1.0
    assert grouped["one_hop"][0].confidence == 1.0
    assert grouped["literal"][0].raw_name == grouped["computed"][0].raw_name


def test_hand_rolled_keeps_its_cap_and_flag():
    grouped = by_function("go/pbkdf2_iterations.go", r"^func (\w+)\(")
    for finding in grouped["handRolled"]:
        assert finding.confidence == 0.8
        assert finding.extra["hand_rolled"] is True
        assert finding.extra["iterations"] == 10000


@pytest.mark.parametrize(
    "spec",
    [
        "{}",
        "{arg: -1}",
        "{arg: 2, loop_param: true}",
        "{bogus: 1}",
    ],
)
def test_malformed_iterations_spec_is_rejected(tmp_path, spec):
    (tmp_path / "go.yaml").write_text(
        "- id: X\n  language: go\n  pattern: 'foo\\((?P<call>)'\n  raw_name: X\n"
        f"  kind_hint: algorithm\n  usage: kdf\n  iterations: {spec}\n"
    )
    with pytest.raises(ValueError, match="iterations"):
        load_rules.__wrapped__("go", tmp_path)


def test_call_group_is_required_without_callee(tmp_path):
    (tmp_path / "go.yaml").write_text(
        "- id: X\n  language: go\n  pattern: 'foo\\('\n  raw_name: X\n"
        "  kind_hint: algorithm\n  usage: kdf\n  iterations: {arg: 1}\n"
    )
    with pytest.raises(ValueError, match="call"):
        load_rules.__wrapped__("go", tmp_path)
