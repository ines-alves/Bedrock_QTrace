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
        (
            "- {id: A, language: python, pattern: '(', raw_name: X, kind_hint: algorithm, usage: hash}",
            "regex",
        ),
        (
            "- {id: A, language: python, pattern: x, raw_name: X, kind_hint: algorithm, "
            "usage: hash, bogus: 1}",
            "unknown keys",
        ),
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
        ("python", "x = 1  # rsa.generate_private_key\n", "x = 1", "rsa.generate"),
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
        """
        KEY_LEN = 32
        EXPORT_KEY = b"0123456789ABCDEF"
        ALIAS = KEY_LEN

        def encrypt(data, key: bytes = EXPORT_KEY, other=None):
            return key

        def plain(key):
            return key
        """
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


def test_byte_unit_applies_to_literal_sizes(tmp_path):
    rule = """
    - id: PY_URANDOM
      language: python
      pattern: 'os\\.urandom\\(\\s*(?P<key_size>\\d+)\\)'
      raw_name: KEY
      kind_hint: key
      usage: encryption
      key_size_unit: bytes
    """
    findings = scan(tmp_path, "python", rule, "k = os.urandom(32)\n")
    assert [(f.key_size, f.extra["key_size_source"]) for f in findings] == [(256, "literal")]


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
  pattern: 'aes\\.NewCipher\\((?P<key_arg>\\w+)\\)'
  raw_name: AES
  kind_hint: algorithm
  usage: encryption
  key_size_from_length: true
  inherit_key_size: AES
"""

GO_PRODUCER_AND_CONSUMER = """
const keyLen = 32

func generateKey() []byte {
    key := make([]byte, keyLen)
    return key
}

func encrypt(key, plaintext []byte) {
    block, _ := aes.NewCipher(key)
}
"""


def go_flow(tmp_path, source):
    return scan(tmp_path, "go", GO_KEY_SOURCE_AND_SINK, GO_PRODUCER_AND_CONSUMER + source)


def sink(findings):
    assert len(findings) == 1
    return findings[0]


def test_flow_links_producer_binding_and_consumer(tmp_path):
    found = sink(go_flow(tmp_path, "func main() {\n    key := generateKey()\n    encrypt(key, nil)\n}\n"))
    assert (found.raw_name, found.key_size, found.confidence) == ("AES", 256, 0.8)
    assert found.extra["key_size_source"] == "flow"
    assert found.extra["resolved_from_line"] == 2


def test_flow_follows_a_same_function_allocation(tmp_path):
    findings = scan(
        tmp_path,
        "go",
        GO_KEY_SOURCE_AND_SINK,
        """
        const keyLen = 16

        func run() {
            key := make([]byte, keyLen)
            block, _ := aes.NewCipher(key)
        }
        """,
    )
    assert (sink(findings).key_size, findings[0].extra["key_size_source"]) == (128, "flow")


def test_unused_allocation_and_imported_key_stay_unresolved(tmp_path):
    findings = scan(
        tmp_path,
        "go",
        GO_KEY_SOURCE_AND_SINK,
        """
        const keyLen = 32

        func spare() {
            _ = make([]byte, keyLen)
        }

        func encrypt(importedKey []byte) {
            block, _ := aes.NewCipher(importedKey)
        }
        """,
    )
    found = sink(findings)
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"
    assert found.confidence == 0.5


def test_allocation_that_is_not_the_consumed_key_does_not_link(tmp_path):
    source = (
        "func main() {\n    key := generateKey()\n    encrypt(key, nil)\n"
        "    encrypt(fromElsewhere(), nil)\n}\n"
    )
    found = sink(go_flow(tmp_path, source))
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"


def test_distinct_keys_of_different_sizes_are_ambiguous(tmp_path):
    source = """
const shortKeyLen = 16
func generateShortKey() []byte {
    key := make([]byte, shortKeyLen)
    return key
}
func main() {
    a := generateKey()
    b := generateShortKey()
    encrypt(a, nil)
    encrypt(b, nil)
}
"""
    found = sink(go_flow(tmp_path, source))
    assert found.key_size is None
    assert found.extra["key_size_source"] == "ambiguous"
    assert found.confidence == 0.5


def test_distinct_keys_sharing_a_size_both_link_to_that_size(tmp_path):
    source = (
        "func main() {\n    a := generateKey()\n    b := generateKey()\n"
        "    encrypt(a, nil)\n    encrypt(b, nil)\n}\n"
    )
    found = sink(go_flow(tmp_path, source))
    assert (found.key_size, found.extra["key_size_source"]) == (256, "flow")


def test_reassigned_binding_does_not_link(tmp_path):
    source = "func main() {\n    key := generateKey()\n    key = other()\n    encrypt(key, nil)\n}\n"
    found = sink(go_flow(tmp_path, source))
    assert found.key_size is None
    assert found.extra["key_size_source"] == "unresolved"


def test_flow_resolves_a_file_scope_literal_key_by_its_length(tmp_path):
    findings = scan(
        tmp_path,
        "go",
        GO_KEY_SOURCE_AND_SINK,
        """
        var exportKey = []byte("0123456789ABCDEF")

        func encrypt(data, key []byte) {
            block, _ := aes.NewCipher(key)
        }

        func main() {
            encrypt(nil, exportKey)
        }
        """,
    )
    found = sink(findings)
    assert (found.key_size, found.extra["key_size_source"], found.extra["resolved_from_line"]) == (
        128,
        "flow",
        2,
    )


PY_FLOW = """
- id: PY_URANDOM
  language: python
  pattern: 'os\\.urandom\\(\\s*(?P<key_size_ref>[A-Za-z_]\\w*)'
  raw_name: AES-KEY
  kind_hint: key
  usage: encryption
  key_size_unit: bytes
  provides_key_size: AES
  emit: false
- id: PY_AESGCM
  language: python
  pattern: 'AESGCM\\((?P<key_arg>[A-Za-z_]\\w*)\\)'
  raw_name: AES
  kind_hint: algorithm
  usage: encryption
  mode: GCM
  inherit_key_size: AES
"""


def test_python_flow_through_a_returned_call_and_keyword_argument(tmp_path):
    findings = scan(
        tmp_path,
        "python",
        PY_FLOW,
        """
        KEY_LEN = 32

        def generate_key():
            return os.urandom(KEY_LEN)

        def encrypt(key, data):
            return AESGCM(key).encrypt(data)

        if __name__ == "__main__":
            k = generate_key()
            encrypt(data=b"x", key=k)
        """,
    )
    found = sink(findings)
    assert (found.key_size, found.extra["key_size_source"], found.extra["resolved_from_line"]) == (
        256,
        "flow",
        2,
    )


JAVA_FLOW = """
- id: JAVA_KEYGEN_INIT
  language: java
  pattern: '\\.init\\(\\s*(?:(?P<key_size>\\d+)|(?P<key_size_ref>[A-Za-z_]\\w*))'
  raw_name: AES-KEY
  kind_hint: key
  usage: encryption
  provides_key_size: AES
  emit: false
- id: JAVA_CIPHER
  language: java
  pattern: 'Cipher\\.getInstance\\(\\s*"(?P<t>[^"]+)"'
  raw_name: '{t}'
  kind_hint: algorithm
  usage: encryption
  key_arg_pattern: 'cipher\\.init\\([^,]+,\\s*(?P<key_arg>\\w+)'
  inherit_key_size: AES
"""


def test_java_flow_uses_the_key_argument_found_after_the_match(tmp_path):
    findings = scan(
        tmp_path,
        "java",
        JAVA_FLOW,
        """
        class S {
            static final int KEY_BITS = 256;
            static SecretKey generateKey() throws Exception {
                KeyGenerator generator = KeyGenerator.getInstance("AES");
                generator.init(KEY_BITS);
                return generator.generateKey();
            }
            static byte[] encrypt(SecretKey key, byte[] data) throws Exception {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher.doFinal(data);
            }
            public static void main(String[] a) throws Exception {
                SecretKey key = generateKey();
                encrypt(key, null);
            }
        }
        """,
    )
    found = sink(findings)
    assert (found.raw_name, found.key_size, found.extra["key_size_source"]) == (
        "AES/GCM/NoPadding",
        256,
        "flow",
    )


GO_MODES = """
- id: GO_AES
  language: go
  pattern: 'aes\\.NewCipher\\('
  raw_name: AES
  kind_hint: algorithm
  usage: encryption
  mode_cases:
    - mode: GCM
      requires: ['cipher\\.NewGCM\\(']
    - mode: ECB
      mode_source: block_loop
      requires: ['for\\b[^\\n]*\\{[^}]*block\\.Encrypt\\(']
      forbids: ['NewCBC', 'NewCTR', 'NewCFB', 'NewOFB', '\\^', 'XORBytes']
"""


@pytest.mark.parametrize(
    "body, mode, source",
    [
        ("block, _ := aes.NewCipher(k)\n    gcm, _ := cipher.NewGCM(block)", "GCM", None),
        (
            "block, _ := aes.NewCipher(k)\n    for i := 0; i < n; i += 16 {\n"
            "        block.Encrypt(d[i:], s[i:])\n    }",
            "ECB",
            "block_loop",
        ),
        (
            "block, _ := aes.NewCipher(k)\n    for i := 0; i < n; i += 16 {\n"
            "        block.Encrypt(d[i:], s[i:])\n        d[i] ^= prev[i]\n    }",
            None,
            None,
        ),
        (
            "block, _ := aes.NewCipher(k)\n    mode := cipher.NewCBCEncrypter(block, iv)\n"
            "    for i := 0; i < n; i++ {\n        block.Encrypt(d, s)\n    }",
            None,
            None,
        ),
        ("block, _ := aes.NewCipher(k)", None, None),
    ],
)
def test_mode_needs_affirmative_evidence_in_the_enclosing_function(tmp_path, body, mode, source):
    findings = scan(tmp_path, "go", GO_MODES, f"func f() {{\n    {body}\n}}\n")
    found = sink(findings)
    assert found.mode == mode
    assert found.extra.get("mode_source") == source
    if mode:
        assert found.confidence == 0.8


def test_mode_cases_do_not_read_other_functions(tmp_path):
    findings = scan(
        tmp_path,
        "go",
        GO_MODES,
        "func a() {\n    aes.NewCipher(k)\n}\nfunc b() {\n    cipher.NewGCM(x)\n}\n",
    )
    assert sink(findings).mode is None


HYGIENE_RULE = """
- id: PY_KEY_LITERAL
  language: python
  pattern: '^(?P<name>[A-Z_]+KEY)\\s*=\\s*b"[^"]*"'
  raw_name: hard-coded symmetric key
  kind_hint: key
  usage: encryption
  redact: true
  extra:
    hygiene_only: true
    hygiene_flags: [hardcoded_key]
"""


def test_static_extra_and_snippet_redaction(tmp_path):
    findings = scan(tmp_path, "python", HYGIENE_RULE, 'EXPORT_KEY = b"0123456789ABCDEF"\n')
    found = sink(findings)
    assert found.extra["hygiene_only"] is True
    assert found.extra["hygiene_flags"] == ["hardcoded_key"]
    assert found.location.snippet == "EXPORT_KEY = <redacted>"
    assert "0123456789ABCDEF" not in found.model_dump_json()


@pytest.mark.parametrize(
    "key", ["rule", "key_size_source", "unresolved", "resolved_from_line", "mode_source"]
)
def test_rule_extra_cannot_override_engine_keys(tmp_path, key):
    body = (
        "- {id: A, language: python, pattern: x, raw_name: X, kind_hint: algorithm, "
        f"usage: hash, extra: {{{key}: 1}}}}"
    )
    with pytest.raises(ValueError, match="extra"):
        rules_for(tmp_path, "python", body)


CONDITION_RULE = """
- id: GO_RAND
  language: go
  pattern: '\\brand\\.Read\\('
  raw_name: math/rand
  kind_hint: algorithm
  usage: rng
  requires: ['"math/rand"']
  forbids: ['"crypto/rand"']
"""

FUNCTION_RULE = """
- id: GO_LOOP_MAC
  language: go
  pattern: '\\bhmac\\.New\\('
  raw_name: loop-mac
  kind_hint: algorithm
  usage: mac
  scope: function
  requires: ['\\^=']
  forbids: ['\\bpbkdf2\\b']
"""


def test_file_scope_requires_and_forbids(tmp_path):
    insecure = 'import (\n\t"math/rand"\n)\nfunc f() {\n\trand.Read(b)\n}\n'
    secure = 'import (\n\t"crypto/rand"\n)\nfunc f() {\n\trand.Read(b)\n}\n'
    both = 'import (\n\t"math/rand"\n\t"crypto/rand"\n)\nfunc f() {\n\trand.Read(b)\n}\n'
    assert [f.location.line for f in scan(tmp_path, "go", CONDITION_RULE, insecure)] == [5]
    assert scan(tmp_path, "go", CONDITION_RULE, secure) == []
    assert scan(tmp_path, "go", CONDITION_RULE, both) == []


def test_function_scope_conditions_read_only_the_enclosing_function(tmp_path):
    source = (
        "func plain() {\n"
        "\tmac := hmac.New(h, k)\n"
        "}\n"
        "func loop() {\n"
        "\tmac := hmac.New(h, k)\n"
        "\tt[0] ^= u[0]\n"
        "}\n"
    )
    assert [f.location.line for f in scan(tmp_path, "go", FUNCTION_RULE, source)] == [5]


def test_conditions_must_be_regex_lists_and_scope_is_validated(tmp_path):
    base = "- {id: A, language: go, pattern: x, raw_name: X, kind_hint: algorithm, usage: hash, "
    with pytest.raises(ValueError, match="requires"):
        rules_for(tmp_path, "go", base + "requires: abc}")
    with pytest.raises(ValueError, match="scope"):
        rules_for(tmp_path, "go", base + "scope: line}")


def test_literal_key_needs_a_key_arg_or_literal_group(tmp_path):
    base = "- {id: A, language: go, raw_name: X, kind_hint: key, usage: encryption, literal_key: AES, "
    with pytest.raises(ValueError, match="literal_key"):
        rules_for(tmp_path, "go", base + "pattern: 'aes[.]New[(]x[)]'}")
    assert rules_for(tmp_path, "go", base + "pattern: 'aes[.]New[(](?P<key_arg>\\w+)[)]'}")


LITERAL_RULE = (
    "- {id: HK, language: go, pattern: 'aes[.]New[(](?P<key_arg>[A-Za-z_]\\w*)[)]', raw_name: K, "
    "kind_hint: key, usage: encryption, literal_key: AES, redact: true}"
)


def test_literal_key_moves_to_the_literal_line_through_call_sites(tmp_path):
    source = (
        'var k0 = []byte("0123456789ABCDEF")\n'
        "func a(k []byte) {\n"
        "\taes.New(k)\n"
        "}\n"
        "func b(k []byte) {\n"
        "\ta(k)\n"
        "}\n"
        "func c() {\n"
        "\tb(k0)\n"
        "}\n"
    )
    found = scan(tmp_path, "go", LITERAL_RULE, source)
    assert [(f.location.line, f.confidence) for f in found] == [(1, 0.8)]
    assert found[0].location.snippet == "var k0 = []byte(<redacted>)"


def test_literal_key_ignores_an_untraceable_call_site_for_the_whole_parameter(tmp_path):
    source = (
        'var k0 = []byte("0123456789ABCDEF")\n'
        "func a(k []byte) {\n"
        "\taes.New(k)\n"
        "}\n"
        "func c() {\n"
        "\ta(k0)\n"
        "\ta(loadKey())\n"
        "}\n"
    )
    assert scan(tmp_path, "go", LITERAL_RULE, source) == []


def test_resolved_from_line_for_constant_and_parameter_default(tmp_path):
    findings = scan(
        tmp_path,
        "python",
        PY_RSA,
        """
        BITS = 2048

        def make(size=BITS):
            return rsa.generate_private_key(public_exponent=65537, key_size=BITS)
        """,
    )
    assert (sink(findings).key_size, findings[0].extra["resolved_from_line"]) == (2048, 2)


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


ABSORB_RULES = """
- {id: OUTER, language: go, pattern: 'wrap[(](?:[^()]|[(][^()]*[)])*?inner[(][)]', raw_name: WRAP, kind_hint: algorithm, usage: kdf}
- {id: INNER, language: go, pattern: 'inner[(][)]', raw_name: INNER, kind_hint: algorithm, usage: hash, absorbed_by: [OUTER]}
"""


def test_absorbed_by_drops_a_hit_inside_the_match_of_the_named_rule(tmp_path):
    source = "x := wrap(a,\n    b, inner())\ny := inner()\n"
    found = scan(tmp_path, "go", ABSORB_RULES, source)
    assert [(f.raw_name, f.location.line) for f in found] == [("WRAP", 1), ("INNER", 3)]


def test_absorbed_by_keeps_the_hit_when_the_absorbing_rule_does_not_match(tmp_path):
    found = scan(tmp_path, "go", ABSORB_RULES, "x := other(inner())\n")
    assert [f.raw_name for f in found] == ["INNER"]


def test_absorbed_by_is_validated(tmp_path):
    base = "- {id: A, language: go, pattern: x, raw_name: X, kind_hint: algorithm, usage: hash, "
    with pytest.raises(ValueError, match="absorbed_by"):
        rules_for(tmp_path, "go", base + "absorbed_by: B}")
    with pytest.raises(ValueError, match="unknown rule"):
        rules_for(tmp_path, "go", base + "absorbed_by: [B]}")
