import re
from pathlib import Path

import pytest

from quantumtrace.models import Finding, Usage
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, mask_comments, scan_source
from quantumtrace.scanners.code.python_ast import BARE_MEMBERS, QUALIFIERS, resolve_aliases

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "code"
RULES = load_rules("python")


def resolve(text: str) -> str:
    return resolve_aliases(text, mask_comments(text, "python"))


def scan(text: str, file: str = "app.py") -> list[Finding]:
    return scan_source(text, file, "python", RULES)


def summary(findings: list[Finding]) -> list[tuple[str, int]]:
    return [(f.raw_name, f.location.line) for f in findings]


# ---------------------------------------------------------------- rewriting


@pytest.mark.parametrize(
    "source, expected",
    [
        ("import hashlib as h\nh.md5(b'')\n", "import hashlib as h\nhashlib.md5(b'')\n"),
        ("from hashlib import md5\nmd5(b'')\n", "from hashlib import md5\nhashlib.md5(b'')\n"),
        ("from hashlib import md5 as m\nm(b'')\n", "from hashlib import md5 as m\nhashlib.md5(b'')\n"),
        (
            "from cryptography.hazmat.primitives.asymmetric import rsa as R\nR.generate_private_key()\n",
            "from cryptography.hazmat.primitives.asymmetric import rsa as R\nrsa.generate_private_key()\n",
        ),
        (
            "from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as g\ng()\n",
            "from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as g\n"
            "rsa.generate_private_key()\n",
        ),
        (
            "from cryptography.hazmat.primitives.hashes import SHA1\nSHA1()\n",
            "from cryptography.hazmat.primitives.hashes import SHA1\nhashes.SHA1()\n",
        ),
        (
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM as G\nG(k)\n",
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM as G\nAESGCM(k)\n",
        ),
        (
            "import cryptography.hazmat.primitives.asymmetric.rsa\n"
            "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key()\n",
            "import cryptography.hazmat.primitives.asymmetric.rsa\nrsa.generate_private_key()\n",
        ),
        (
            "import hashlib as h\nx = '\u00e9'; h.md5(b'')\n",
            "import hashlib as h\nx = '\u00e9'; hashlib.md5(b'')\n",
        ),
        ("import hashlib as h\n# h.md5(b'')\nh.sha1(b'')\n", None),
    ],
)
def test_rewrite(source: str, expected: str | None) -> None:
    result = resolve(source)
    if expected is None:
        assert "hashlib.sha1" in result
        assert "h.md5" not in result
    else:
        assert result == expected
    assert result.count("\n") == source.count("\n")


def test_no_alias_returns_same_object() -> None:
    text = "import hashlib\nhashlib.md5(b'')\n"
    masked = mask_comments(text, "python")
    assert resolve_aliases(text, masked) is masked


def test_strings_are_not_rewritten() -> None:
    text = "import hashlib as h\nx = 'h.md5('\nh.md5(b'')\n"
    assert resolve(text).split("\n")[1] == "x = 'h.md5('"


# ---------------------------------------------------------------- strict skips


@pytest.mark.parametrize(
    "source",
    [
        "import hashlib as h\ndef f(d):\n    h = d\n    return h.md5()\n",
        "import hashlib as h\nh = None\nh.md5()\n",
        "import hashlib as h\ndef f(h):\n    return h.md5()\n",
        "import hashlib as h\nfor h in range(3):\n    h.md5()\n",
        "import hashlib as h\nwith open('x') as h:\n    h.md5()\n",
        "import hashlib as h\nimport zlib as h\nh.md5()\n",
        "import hashlib as h\nhashlib = None\nh.md5()\n",
        "import hashlib as h\nclass h:\n    pass\nh.md5()\n",
        "from . import hashlib as h\nh.md5()\n",
        "from hashlib import *\nmd5(b'')\n",
    ],
)
def test_conflicting_bindings_are_not_rewritten(source: str) -> None:
    assert resolve(source) == mask_comments(source, "python")
    assert scan(source) == []


def test_same_import_twice_is_rewritten() -> None:
    text = "def a():\n    import hashlib as h\n    return h.md5()\n\n\ndef b():\n    import hashlib as h\n    return h.sha1()\n"
    assert summary(scan(text)) == [("md5", 3), ("sha1", 8)]


def test_syntax_error_falls_back_to_regex_only() -> None:
    text = 'import hashlib\nimport hashlib as h\nprint "x"\nhashlib.md5("a")\nh.sha1("b")\n'
    assert resolve(text) == mask_comments(text, "python")
    assert summary(scan(text)) == [("md5", 4)]


# ---------------------------------------------------------------- end to end


def test_alias_fixture_findings() -> None:
    path = FIXTURES / "python" / "aliases.py"
    results = list(CodeScanner().scan(path, FIXTURES))
    assert all(isinstance(r, Finding) for r in results), results
    found = sorted((r.raw_name, r.location.line, r.key_size, r.mode, r.padding) for r in results)
    assert found == sorted(
        [
            ("hard-coded symmetric key", 16, None, None, None),
            ("md5", 20, None, None, None),
            ("md5", 24, None, None, None),
            ("sha1", 28, None, None, None),
            ("SHA256", 32, None, None, None),
            ("random.getrandbits", 36, None, None, None),
            ("Ed25519", 40, None, None, None),
            ("RSA", 44, 1024, None, None),
            ("SHA256", 45, None, None, None),
            ("RSA", 45, 1024, None, "PKCS1v15"),
            ("AES", 49, 128, "ECB", None),
            ("AESGCM", 54, 128, "GCM", None),
        ]
    )


def test_aliased_rsa_generation_gets_flow_usage() -> None:
    path = FIXTURES / "python" / "aliases.py"
    results = [r for r in CodeScanner().scan(path, FIXTURES) if isinstance(r, Finding)]
    generation = next(r for r in results if r.raw_name == "RSA" and r.location.line == 44)
    assert generation.usage is Usage.SIGNATURE
    assert generation.extra["usage_source"] == "flow"
    assert generation.extra["key_size_source"] == "constant"


def test_aliased_and_canonical_spelling_give_the_same_findings() -> None:
    canonical = (
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import padding, rsa\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "hashlib.sha1(b'')\n"
        "key.sign(b'', padding.PKCS1v15(), hashes.SHA256())\n"
    )
    aliased = (
        "import hashlib as h\n"
        "from cryptography.hazmat.primitives.asymmetric import padding as P, rsa as R\n"
        "from cryptography.hazmat.primitives import hashes as H\n"
        "key = R.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "h.sha1(b'')\n"
        "key.sign(b'', P.PKCS1v15(), H.SHA256())\n"
    )

    def shape(findings: list[Finding]) -> list[tuple[object, ...]]:
        return [
            (f.raw_name, f.location.line, f.usage, f.key_size, f.padding, f.confidence, f.extra)
            for f in findings
        ]

    assert shape(scan(aliased)) == shape(scan(canonical))


# ---------------------------------------------------------------- pins


def test_no_rewrite_on_kit_and_existing_fixtures() -> None:
    files = sorted((REPO / "sample-repos" / "python").glob("*.py"))
    files += [
        p
        for p in sorted((FIXTURES / "python").glob("*.py"))
        if p.name not in ("aliases.py", "gaps.py", "pbkdf2_hashlib.py", "pbkdf2_iterations.py", "scrypt.py")
    ]
    assert len(files) >= 9
    for path in files:
        text = path.read_text(encoding="utf-8")
        masked = mask_comments(text, "python")
        assert resolve_aliases(text, masked) is masked, path.name


def test_qualifiers_cover_prefixes_used_by_python_rules() -> None:
    text = (REPO / "src" / "quantumtrace" / "scanners" / "code" / "rules" / "python.yaml").read_text(
        encoding="utf-8"
    )
    used = set(re.findall(r"(?:\\b)?([A-Za-z_][A-Za-z0-9_]*)\\\.", text))
    assert {"hashlib", "rsa", "hashes"} <= used
    assert used <= QUALIFIERS | BARE_MEMBERS, sorted(used - QUALIFIERS - BARE_MEMBERS)
