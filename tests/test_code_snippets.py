"""Snippets never carry a string literal the rule did not capture (M3toAll 4, M3M4-06)."""

import re
from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

SECRET = "SENTINEL_KEY_9f3a"
KIT = Path(__file__).parent.parent / "sample-repos"
FIXTURES = Path(__file__).parent / "fixtures" / "code"
LITERAL = re.compile(r"[bB]?\"[^\"]*\"")


def scan(language: str, source: str) -> list[Finding]:
    return scan_source(source, f"app.{language}", language, load_rules(language))


def snippets(findings: list[Finding]) -> list[str]:
    return [f.location.snippet for f in findings]


@pytest.mark.parametrize(
    "language, source",
    [
        ("python", f'import hmac, hashlib\nsig = hmac.new(b"{SECRET}", msg, hashlib.sha256).hexdigest()\n'),
        ("python", f'import hmac\nsig = hmac.new(key=b"{SECRET}", msg=m, digestmod="sha256")\n'),
        ("python", f'import hmac\nsig = hmac.new(\n    b"{SECRET}",\n    msg, "sha1")\n'),
        (
            "go",
            f'package main\nimport ("crypto/hmac"; "crypto/sha256")\n'
            f'func f() {{ m := hmac.New(sha256.New, []byte("{SECRET}")) }}\n',
        ),
        (
            "java",
            "class A { void f() throws Exception {\n"
            f'  Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec("{SECRET}".getBytes(), "HmacSHA256"));\n'
            "}}\n",
        ),
    ],
)
def test_inline_hmac_key_never_reaches_a_snippet(language: str, source: str) -> None:
    findings = scan(language, source)
    assert findings
    assert SECRET not in "".join(snippets(findings))


def test_python_hmac_key_literal_is_replaced_and_digest_name_kept() -> None:
    (finding,) = scan("python", f'import hmac\nsig = hmac.new(key=b"{SECRET}", msg=m, digestmod="sha256")\n')
    assert finding.location.snippet == 'sig = hmac.new(key=<redacted>, msg=m, digestmod="sha256")'


def test_go_hmac_key_literal_is_replaced() -> None:
    source = (
        'package main\nimport ("crypto/hmac"; "crypto/sha256")\n'
        f'func f() {{ m := hmac.New(sha256.New, []byte("{SECRET}")) }}\n'
    )
    (finding,) = scan("go", source)
    assert finding.location.snippet == "func f() { m := hmac.New(sha256.New, []byte(<redacted>)) }"


def test_captured_transform_and_algorithm_stay_readable() -> None:
    java = (
        'class A { void f() throws Exception { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); } }\n'
    )
    (finding,) = scan("java", java)
    assert '"AES/ECB/PKCS5Padding"' in finding.location.snippet
    py = 'import hashlib\nh = hashlib.new("md5", b"payload-text")\n'
    (finding,) = scan("python", py)
    assert finding.location.snippet == 'h = hashlib.new("md5", <redacted>)'


def test_uncaptured_literal_next_to_a_captured_one_is_redacted() -> None:
    java = (
        "class A { void f() throws Exception {\n"
        f'  Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"); log("{SECRET}");\n'
        "}}\n"
    )
    (finding,) = scan("java", java)
    assert (
        finding.location.snippet == 'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"); log(<redacted>);'
    )


def kit_files() -> list[Path]:
    return sorted(p for p in KIT.rglob("*") if p.suffix in {".py", ".java", ".go"})


def literal_values(findings: list[Finding]) -> list[tuple[Finding, str]]:
    return [
        (f, m.group(0).lstrip("bB")[1:-1]) for f in findings for m in LITERAL.finditer(f.location.snippet)
    ]


def test_every_kept_literal_is_part_of_the_finding_evidence() -> None:
    """Kit and fixtures: a literal left in a snippet equals the raw name or a field the rule produced."""
    scanner = CodeScanner()
    checked = 0
    for root, paths in ((KIT, kit_files()), (FIXTURES, sorted(FIXTURES.rglob("*.*")))):
        for path in paths:
            if path.suffix not in {".py", ".java", ".go"}:
                continue
            for result in scanner.scan(path, root):
                if not isinstance(result, Finding):
                    continue
                for finding, text in literal_values([result]):
                    evidence = " ".join(
                        str(v)
                        for v in (
                            finding.raw_name,
                            finding.mode,
                            finding.padding,
                            finding.curve,
                            finding.library,
                        )
                        if v
                    )
                    assert text.lower() in evidence.lower() or text.lower() in finding.raw_name.lower(), (
                        path.name,
                        finding.location.line,
                        finding.location.snippet,
                    )
                    checked += 1
    assert checked > 0


def test_go_import_only_snippet_keeps_the_package_path() -> None:
    (finding,) = scan("go", 'package main\nimport "crypto/md5"\n')
    assert finding.location.snippet == 'import "crypto/md5"'
