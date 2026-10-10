import textwrap
from pathlib import Path

import pytest

from quantumtrace.models import ScanError, SourceType
from quantumtrace.scanners.code import engine
from quantumtrace.scanners.code.engine import (
    CodeScanner,
    Constants,
    load_rules,
    mask_comments,
    scan_source,
)


def rules_for(tmp_path: Path, language: str, yaml_text: str):
    (tmp_path / f"{language}.yaml").write_text(textwrap.dedent(yaml_text), encoding="utf-8")
    return load_rules(language, tmp_path)


def scan(tmp_path: Path, language: str, yaml_text: str, source: str, file: str = "app/mod.src"):
    rules = rules_for(tmp_path, language, yaml_text)
    return scan_source(textwrap.dedent(source), file, language, rules)


PY_RSA = """
- id: PY_RSA
  language: python
  pattern: >-
    rsa\\.generate_private_key\\([^)]*key_size\\s*=\\s*(?:(?P<key_size>\\d+)|(?P<key_size_ref>[A-Za-z_]\\w*))
  raw_name: RSA
  kind_hint: algorithm
  usage: signature
  library: cryptography
"""


# ---------------------------------------------------------------- rule loading


@pytest.mark.parametrize(
    "body, message",
    [
        ("- {id: A, language: python, pattern: x, kind_hint: algorithm, usage: hash}", "raw_name"),
        ("- {id: A, language: python, pattern: x, raw_name: X, kind_hint: nope, usage: hash}", "nope"),
        ("- {id: A, language: python, pattern: '(', raw_name: X, kind_hint: algorithm, usage: hash}",
         "regex"),
        ("- {id: A, language: python, pattern: x, raw_name: X, kind_hint: algorithm, usage: hash, bogus: 1}",
         "unknown keys"),
        ("- {id: A, language: java, pattern: x, raw_name: X, kind_hint: algorithm, usage: hash}", "language"),
        (
            "- {id: A, language: python, pattern: x, raw_name: X, kind_hint: algorithm, usage: hash}\n"
            "- {id: A, language: python, pattern: y, raw_name: Y, kind_hint: algorithm, usage: hash}",
            "duplicate",
        ),
    ],
)
def test_invalid_rule_files_are_rejected(tmp_path, body, message):
    with pytest.raises(ValueError, match=message):
        rules_for(tmp_path, "python", body)


# ---------------------------------------------------------------- comment masking


@pytest.mark.parametrize(
    "language, source, kept, blanked",
    [
        ("python", 'x = 1  # rsa.generate_private_key\n', "x = 1", "rsa.generate"),
        ("python", 'url = "a#b"\n', 'url = "a#b"', None),
        ("python", '"""rsa.generate_private_key(key_size=1024)"""\nx = 1\n', "x = 1", "rsa.generate"),
        ("python", 'x = """keep # this"""\n', 'x = """keep # this"""', None),
        ("java", "int a = 1; // MD5\n", "int a = 1;", "MD5"),
        ("java", 'String s = "http://x"; // c\n', 'String s = "http://x";', "// c"),
        ("java", "/* MD5\n SHA1 */ int a;\n", "int a;", "SHA1"),
        ("java", "char c = '\"'; // c\n", "char c = '\"';", "// c"),
        ("go", "x := `a // b` // c\n", "x := `a // b`", "// c"),
        ("go", "h := md5.Sum(x) /* old */\n", "h := md5.Sum(x)", "old"),
    ],
)
def test_mask_comments(language, source, kept, blanked):
    masked = mask_comments(source, language)
    assert len(masked) == len(source)
    assert masked.count("\n") == source.count("\n")
    assert kept in masked
    if blanked:
        assert blanked not in masked


def test_comment_only_match_produces_no_finding(tmp_path):
    findings = scan(
        tmp_path,
        "python",
        PY_RSA,
        """
        # rsa.generate_private_key(key_size=1024)
        '''
        rsa.generate_private_key(key_size=512)
        '''
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        """,
    )
    assert [(f.raw_name, f.location.line, f.key_size) for f in findings] == [("RSA", 6, 2048)]


# ---------------------------------------------------------------- constants


def test_python_constants_and_param_defaults():
    src = textwrap.dedent(
        '''
        KEY_LEN = 32
        EXPORT_KEY = b"0123456789ABCDEF"
        ALIAS = KEY_LEN

        def encrypt(data, key: bytes = EXPORT_KEY, other=None):
            return key

        def plain(key):
            return key
        '''
    )
    consts = Constants(mask_comments(src, "python"), "python")
    assert consts.resolve("KEY_LEN", 1) == (32, "constant")
    assert consts.resolve("ALIAS", 1) == (32, "constant")
    assert consts.resolve("key", 6) == (b"0123456789ABCDEF", "param_default")
    assert consts.resolve("key", 9) is None
    assert consts.resolve("other", 6) is None


def test_java_constants():
    src = textwrap.dedent(
        """
        class A {
            private static final byte[] EXPORT_KEY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
            private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
            private static final int KEY_BITS = 256;
            static final int ITERATIONS = 600_000;
        }
        """
    )
    consts = Constants(mask_comments(src, "java"), "java")
    assert consts.resolve("EXPORT_KEY", 1) == ("0123456789ABCDEF", "constant")
    assert consts.resolve("TRANSFORMATION", 1) == ("AES/ECB/PKCS5Padding", "constant")
    assert consts.resolve("KEY_BITS", 1) == (256, "constant")
    assert consts.resolve("ITERATIONS", 1) == (600000, "constant")


def test_go_constants():
    src = textwrap.dedent(
        """
        const keyLen = 32
        const (
            iterations = 600_000
            saltLen    = 16
        )
        var exportKey = []byte("0123456789ABCDEF")
        var typed int = 7
        """
    )
    consts = Constants(mask_comments(src, "go"), "go")
    assert consts.resolve("keyLen", 1) == (32, "constant")
    assert consts.resolve("iterations", 1) == (600000, "constant")
    assert consts.resolve("saltLen", 1) == (16, "constant")
    assert consts.resolve("exportKey", 1) == ("0123456789ABCDEF", "constant")
    assert consts.resolve("typed", 1) == (7, "constant")


# ---------------------------------------------------------------- key size resolution


def test_key_size_literal_and_constant_reference(tmp_path):
    findings = scan(
        tmp_path,
        "python",
        PY_RSA,
        """
        BITS = 3072
        a = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        b = rsa.generate_private_key(public_exponent=65537, key_size=BITS)
        """,
    )
    got = [(f.location.line, f.key_size, f.extra["key_size_source"], f.confidence) for f in findings]
    assert got == [(3, 1024, "literal", 1.0), (4, 3072, "constant", 1.0)]


AES_PY = """
- id: PY_AES
  language: python
  pattern: 'algorithms\\.AES\\(\\s*(?P<key_size_ref>\\w+)\\s*\\)'
  raw_name: AES
  kind_hint: algorithm
  usage: encryption
  key_size_from_length: true
"""


def test_key_length_resolved_through_parameter_default(tmp_path):
    findings = scan(
        tmp_path,
        "python",
        AES_PY,
        """
        EXPORT_KEY = b"0123456789ABCDEF"

        def encrypt(plaintext, key: bytes = EXPORT_KEY):
            return Cipher(algorithms.AES(key), modes.ECB())
        """,
    )
    assert [(f.key_size, f.extra["key_size_source"]) for f in findings] == [(128, "param_default")]


GO_KEY_SOURCE_AND_SINK = """
- id: GO_KEY_MAKE
  language: go
  pattern: 'make\\(\\[\\]byte,\\s*(?P<key_size_ref>\\w*[Kk]ey\\w*)\\)'
  raw_name: AES-KEY
  kind_hint: key
  usage: encryption
  key_size_unit: bytes
  provides_key_size: AES
  emit: false
- id: GO_AES
  language: go
  pattern: 'aes\\.NewCipher\\('
  raw_name: AES
  kind_hint: algorithm
  usage: encryption
  inherit_key_size: AES
"""


def test_file_scope_inference_gives_single_key_size(tmp_path):
    findings = scan(
        tmp_path,
        "go",
        GO_KEY_SOURCE_AND_SINK,
        """
        const keyLen = 32

        func gen() []byte { return make([]byte, keyLen) }
        func enc(key []byte) { block, _ := aes.NewCipher(key) }
        """,
    )
    assert [(f.raw_name, f.location.line, f.key_size) for f in findings] == [("AES", 5, 256)]
    assert findings[0].extra["key_size_source"] == "file_scope"
    assert findings[0].confidence == 0.8


def test_file_scope_inference_is_ambiguous_with_two_sizes(tmp_path):
    findings = scan(
        tmp_path,
        "go",
        GO_KEY_SOURCE_AND_SINK,
        """
        const keyLen = 32
        const exportKeyLen = 16

        func a() []byte { return make([]byte, keyLen) }
        func b() []byte { return make([]byte, exportKeyLen) }
        func enc(key []byte) { block, _ := aes.NewCipher(key) }
        """,
    )
    assert len(findings) == 1
    assert findings[0].key_size is None
    assert findings[0].extra["key_size_source"] == "ambiguous"
    assert findings[0].confidence == 0.5


def test_file_scope_inference_unresolved_without_sources(tmp_path):
    findings = scan(tmp_path, "go", GO_KEY_SOURCE_AND_SINK, "func enc(key []byte) { aes.NewCipher(key) }\n")
    assert findings[0].key_size is None
    assert findings[0].extra["key_size_source"] == "unresolved"
    assert findings[0].confidence == 0.5


JAVA_KPG = """
- id: JAVA_KPG
  language: java
  pattern: 'KeyPairGenerator\\.getInstance\\(\\s*"(?P<algo>[A-Za-z0-9-]+)"'
  raw_name: '{algo}'
  kind_hint: algorithm
  usage: key_exchange
  lookahead_pattern: '\\.initialize\\(\\s*(?:(?P<key_size>\\d+)|(?P<key_size_ref>[A-Za-z_]\\w*))'
  lookahead_lines: 5
"""


def test_lookahead_fallback_reports_line_of_match(tmp_path):
    findings = scan(
        tmp_path,
        "java",
        JAVA_KPG,
        """
        class A {
            void f() throws Exception {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(1024);
            }
        }
        """,
    )
    assert [(f.raw_name, f.location.line, f.key_size) for f in findings] == [("RSA", 4, 1024)]
    assert findings[0].extra["key_size_source"] == "lookahead"
    assert findings[0].confidence == 0.8


def test_lookahead_does_not_reach_beyond_window(tmp_path):
    filler = "\n".join(["        int x;"] * 7)
    findings = scan(
        tmp_path,
        "java",
        JAVA_KPG,
        'KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n'
        + filler
        + "\n        g.initialize(1024);\n",
    )
    assert findings[0].key_size is None
    assert findings[0].extra["key_size_source"] == "unresolved"


JAVA_CIPHER = """
- id: JAVA_CIPHER
  language: java
  pattern: 'Cipher\\.getInstance\\(\\s*(?:"(?P<transform>[^"]+)"|(?P<transform_ref>[A-Za-z_]\\w*))\\s*\\)'
  raw_name: '{transform}'
  kind_hint: algorithm
  usage: encryption
  mode: '{mode}'
  padding: '{padding}'
  refine:
    from: transform
    pattern: '^(?P<algo>[^/]+)(?:/(?P<mode>[^/]+))?(?:/(?P<padding>[^/]+))?$'
"""


def test_transformation_constant_is_resolved_and_split(tmp_path):
    findings = scan(
        tmp_path,
        "java",
        JAVA_CIPHER,
        """
        class A {
            private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
            void f() { Cipher c = Cipher.getInstance(TRANSFORMATION); }
        }
        """,
    )
    (f,) = findings
    assert (f.raw_name, f.mode, f.padding) == ("AES/ECB/PKCS5Padding", "ECB", "PKCS5Padding")
    assert f.location.line == 4


def test_unresolved_reference_keeps_identifier_and_lowers_confidence(tmp_path):
    findings = scan(tmp_path, "java", JAVA_CIPHER, "Cipher c = Cipher.getInstance(cfg);\n")
    (f,) = findings
    assert f.raw_name == "cfg"
    assert f.confidence == 0.5
    assert f.extra["unresolved"] == ["transform"]


# ---------------------------------------------------------------- finding shape


SHA1 = """
- id: PY_SHA1
  language: python
  pattern: 'hashlib\\.sha1\\('
  raw_name: SHA-1
  kind_hint: algorithm
  usage: hash
  library: hashlib
"""


def test_finding_fields_and_test_code_flag(tmp_path):
    src = "import hashlib\n\n\ndef c(d):\n    return hashlib.sha1(d).hexdigest()\n"
    (prod,) = scan(tmp_path, "python", SHA1, src, file="app/update_feed.py")
    (test,) = scan(tmp_path, "python", SHA1, src, file="tests/test_feed.py")
    assert prod.location.source_type is SourceType.CODE
    assert (prod.raw_name, prod.location.line, prod.location.file, prod.language) == (
        "SHA-1",
        5,
        "app/update_feed.py",
        "python",
    )
    assert prod.detector == "code.python.regex:PY_SHA1"
    assert prod.library == "hashlib"
    assert prod.in_test_code is False
    assert test.in_test_code is True


def test_snippet_is_truncated_to_200_chars(tmp_path):
    src = "x = hashlib.sha1(" + "a" * 400 + ")\n"
    (f,) = scan(tmp_path, "python", SHA1, src)
    assert len(f.location.snippet) == 200


def test_output_is_sorted_and_ids_are_stable_and_unique(tmp_path):
    src = "a = hashlib.sha1(x); b = hashlib.sha1(y)\nc = hashlib.sha1(z)\n"
    first = scan(tmp_path, "python", SHA1, src)
    second = scan(tmp_path, "python", SHA1, src)
    assert [f.id for f in first] == [f.id for f in second]
    assert [f.location.line for f in first] == [1, 2]
    assert len({f.id for f in first}) == len(first)


# ---------------------------------------------------------------- scanner class


def test_scanner_can_handle_and_relative_paths(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "python.yaml").write_text(textwrap.dedent(SHA1), encoding="utf-8")
    root = tmp_path / "repo"
    (root / "svc").mkdir(parents=True)
    target = root / "svc" / "feed.py"
    target.write_text("h = hashlib.sha1(b)\n", encoding="utf-8")

    scanner = CodeScanner(rules_dir=rules_dir)
    assert scanner.can_handle(target)
    assert scanner.can_handle(Path("A.java"))
    assert scanner.can_handle(Path("main.go"))
    assert not scanner.can_handle(Path("notes.txt"))
    (f,) = list(scanner.scan(target, root))
    assert f.location.file == "svc/feed.py"


def test_scanner_reports_missing_rules_as_scan_error(tmp_path):
    target = tmp_path / "a.go"
    target.write_text("package main\n", encoding="utf-8")
    results = list(CodeScanner(rules_dir=tmp_path / "none").scan(target, tmp_path))
    assert len(results) == 1 and isinstance(results[0], ScanError)


def test_scanner_skips_oversized_files(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_FILE_BYTES", 5)
    target = tmp_path / "a.py"
    target.write_text("x = 1234567890\n", encoding="utf-8")
    results = list(CodeScanner(rules_dir=tmp_path).scan(target, tmp_path))
    assert len(results) == 1 and isinstance(results[0], ScanError)
