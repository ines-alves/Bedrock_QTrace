"""Library findings from requirements*.txt, pom.xml and go.mod (M3D-07).

Expected values are written from the fixture files and the agreed shape (M3M4-05, M1 decisions for
M3D-07), not from scanner output. The fixtures carry fake credentials in URLs; no message may echo them.
"""

from pathlib import Path

import pytest

from quantumtrace.models import Finding, KindHint, ScanError, Usage
from quantumtrace.scanners.base import REGISTRY
from quantumtrace.scanners.code.manifests import ManifestScanner, load_libraries

FIXTURES = Path(__file__).parent / "fixtures" / "code"
KIT = Path(__file__).parent.parent / "sample-repos"
SCANNER = ManifestScanner()


def scan(rel: str, root: Path = FIXTURES):
    out = list(SCANNER.scan(root / rel, root))
    return (
        [x for x in out if isinstance(x, Finding)],
        [x for x in out if isinstance(x, ScanError)],
    )


def rows(findings: list[Finding]) -> list[tuple[int | None, str]]:
    return [(f.location.line, f.raw_name) for f in findings]


def test_registered_and_can_handle():
    assert any(s.name == "code.manifest" for s in REGISTRY)
    for name in ("requirements.txt", "requirements-dev.txt", "dev_requirements.txt", "pom.xml", "go.mod"):
        assert SCANNER.can_handle(Path("x") / name)
    for name in ("go.sum", "pyproject.toml", "requirements.md", "build.gradle", "notes.txt", "main.go"):
        assert not SCANNER.can_handle(Path("x") / name)


def test_allowlist_loads_exact_identities():
    libs = load_libraries()
    assert "cryptography" in libs["python"]
    assert "org.bouncycastle:bcprov-jdk18on" in libs["java"]
    assert "golang.org/x/crypto" in libs["go"]
    assert "org.bouncycastle" not in libs["java"]


class TestRequirements:
    def test_findings(self):
        findings, _ = scan("manifests/requirements.txt")
        assert rows(findings) == [
            (6, "cryptography==46.0.5"),
            (7, "PyJWT"),
            (8, "Pycryptodome==3.20.0"),
            (9, "paramiko"),
            (10, "argon2_cffi==23.1.0"),
            (14, "bcrypt"),
        ]

    def test_shape(self):
        findings, _ = scan("manifests/requirements.txt")
        for f in findings:
            assert f.kind_hint is KindHint.LIBRARY
            assert f.usage is Usage.UNKNOWN
            assert f.language == "python"
            assert f.detector == "code.python.manifest"
            assert f.confidence == 1.0
            assert f.extra == {"rule": "PY_LIBRARY"}
            assert f.location.file == "manifests/requirements.txt"
            assert not f.in_test_code
        assert findings[0].library == "cryptography"

    def test_unpinned_keeps_constraint_in_snippet_without_version(self):
        findings, _ = scan("manifests/requirements.txt")
        by_name = {f.raw_name: f for f in findings}
        assert by_name["PyJWT"].location.snippet == "PyJWT>=2.8,<3"
        assert by_name["bcrypt"].location.snippet == "bcrypt==4.*"
        assert by_name["Pycryptodome==3.20.0"].location.line == 8

    def test_non_crypto_package_is_not_reported(self):
        findings, _ = scan("manifests/requirements.txt")
        assert all("flask" not in f.raw_name for f in findings)

    def test_unsupported_constructs_are_errors_without_secrets(self):
        _, errors = scan("manifests/requirements.txt")
        assert [e.message.split(":")[0] for e in errors] == [
            "line 3",
            "line 4",
            "line 12",
            "line 13",
        ]
        assert "included requirements file" in errors[0].message
        assert "editable" in errors[1].message
        assert "pynacl" in errors[2].message
        for error in errors:
            assert error.detector == "code.python.manifest"
            assert "secret" not in error.message and "invalid" not in error.message

    def test_test_path_sets_in_test_code(self):
        findings, _ = scan("manifests/tests/requirements-dev.txt")
        assert rows(findings) == [(1, "cryptography==42.0.0")]
        assert findings[0].in_test_code

    def test_name_normalization(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("Argon2.CFFI==1.0\nPy_JWT==2\n", encoding="utf-8")
        findings = [f for f in SCANNER.scan(path, tmp_path) if isinstance(f, Finding)]
        assert rows(findings) == [(1, "Argon2.CFFI==1.0")]

    def test_not_a_pin(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text(
            "cryptography>=46,==46.0.5\ncryptography~=46.0\ncryptography===46.0.5\n", encoding="utf-8"
        )
        findings = [f for f in SCANNER.scan(path, tmp_path) if isinstance(f, Finding)]
        assert [f.raw_name for f in findings] == ["cryptography", "cryptography", "cryptography"]


class TestPom:
    def test_findings(self):
        findings, _ = scan("manifests/pom.xml")
        assert rows(findings) == [
            (23, "org.bouncycastle:bcprov-jdk18on==1.78.1"),
            (28, "org.bouncycastle:bcpkix-jdk18on==1.78.1"),
            (33, "io.jsonwebtoken:jjwt-api"),
            (38, "com.nimbusds:nimbus-jose-jwt"),
            (43, "com.auth0:java-jwt"),
        ]

    def test_management_and_plugin_dependencies_are_not_declarations(self):
        findings, _ = scan("manifests/pom.xml")
        assert all("tink" not in f.raw_name for f in findings)

    def test_snippet_keeps_declared_version(self):
        findings, _ = scan("manifests/pom.xml")
        by_line = {f.location.line: f for f in findings}
        assert by_line[23].location.snippet == "org.bouncycastle:bcprov-jdk18on:${bc.version}"
        assert by_line[33].location.snippet == "io.jsonwebtoken:jjwt-api:[0.11,0.12)"
        assert by_line[43].location.snippet == "com.auth0:java-jwt"

    def test_unresolved_property_never_becomes_a_version(self):
        findings, _ = scan("manifests/pom.xml")
        nimbus = next(f for f in findings if f.library == "com.nimbusds:nimbus-jose-jwt")
        assert nimbus.raw_name == "com.nimbusds:nimbus-jose-jwt"
        assert "managed" in nimbus.location.snippet

    def test_unresolved_coordinates_are_an_error(self):
        _, errors = scan("manifests/pom.xml")
        assert len(errors) == 1
        assert errors[0].message == "line 47: dependency coordinates use an unresolved property"

    def test_shape(self):
        findings, _ = scan("manifests/pom.xml")
        for f in findings:
            assert f.language == "java"
            assert f.detector == "code.java.manifest"
            assert f.extra == {"rule": "JAVA_LIBRARY"}
            assert f.kind_hint is KindHint.LIBRARY

    def test_malformed_xml_is_a_scan_error(self):
        findings, errors = scan("manifests/broken/pom.xml")
        assert findings == []
        assert len(errors) == 1
        assert errors[0].detector == "code.java.manifest"
        assert "XML" in errors[0].message


class TestGoMod:
    def test_findings(self):
        findings, _ = scan("manifests/go.mod")
        assert rows(findings) == [
            (5, "golang.org/x/crypto==v0.31.0"),
            (8, "github.com/cloudflare/circl==v1.5.0"),
            (9, "github.com/golang-jwt/jwt/v5==v5.2.1"),
        ]

    def test_indirect_comment_is_kept_in_snippet(self):
        findings, _ = scan("manifests/go.mod")
        assert findings[1].location.snippet.endswith("// indirect")

    def test_replace_of_allowlisted_module_is_an_error_others_are_not(self):
        _, errors = scan("manifests/go.mod")
        assert [e.message for e in errors] == ["line 13: replace directive not applied: golang.org/x/crypto"]

    def test_shape(self):
        findings, _ = scan("manifests/go.mod")
        for f in findings:
            assert f.language == "go"
            assert f.detector == "code.go.manifest"
            assert f.extra == {"rule": "GO_LIBRARY"}


class TestKit:
    def test_exactly_one_library_finding_in_the_kit(self):
        found = []
        errors = []
        for path in sorted(KIT.rglob("*")):
            if path.is_file() and SCANNER.can_handle(path):
                for item in SCANNER.scan(path, KIT):
                    (found if isinstance(item, Finding) else errors).append(item)
        assert errors == []
        assert [(f.location.file, f.location.line, f.raw_name) for f in found] == [
            ("python/requirements.txt", 1, "cryptography==46.0.5")
        ]
        assert found[0].library == "cryptography"
        assert found[0].language == "python"


def test_oversize_file_is_a_scan_error(tmp_path, monkeypatch):
    path = tmp_path / "go.mod"
    path.write_text("module x\n", encoding="utf-8")
    monkeypatch.setattr("quantumtrace.scanners.code.manifests.MAX_FILE_BYTES", 3)
    out = list(SCANNER.scan(path, tmp_path))
    assert len(out) == 1 and isinstance(out[0], ScanError)


def test_output_is_deterministic():
    first = [f.model_dump() for f in scan("manifests/pom.xml")[0]]
    second = [f.model_dump() for f in scan("manifests/pom.xml")[0]]
    assert first == second
    assert len({f["id"] for f in first}) == len(first)


@pytest.mark.parametrize("rel", ["manifests/requirements.txt", "manifests/pom.xml", "manifests/go.mod"])
def test_findings_sorted_by_line(rel):
    lines = [f.location.line for f in scan(rel)[0]]
    assert lines == sorted(lines)
