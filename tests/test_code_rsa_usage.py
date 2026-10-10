import textwrap
from pathlib import Path

import pytest

from quantumtrace.models import Finding
from quantumtrace.scanners.code.engine import CodeScanner, load_rules, scan_source

KIT = Path(__file__).parent.parent / "sample-repos"
GENERATION_RULES = {"PY_RSA_GENERATE", "PY_RSA_GENERATE_POSITIONAL", "JAVA_KEYPAIR_RSA", "GO_RSA_GENERATE"}
FILES = {"python": "app/keys.py", "java": "app/Keys.java", "go": "app/keys.go"}

LANGS = {
    "python": {
        "head": """
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def make():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
        "head_two": """
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def make_a():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_b():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
        "sign": """

def sign(key, message):
    return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
""",
        "verify": """

def verify(key, signature, message):
    return key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
""",
        "encrypt": """

def encrypt(key, message):
    return key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), label=None))
""",
        "encrypt_alt": """

def encrypt(key, message):
    return key.encrypt(message, padding.PKCS1v15())
""",
        "imported": """

def sign_imported(imported_key, message):
    return imported_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
""",
        "tail": "",
    },
    "java": {
        "head": """
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;

public final class Keys {

    static KeyPair make() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
""",
        "head_two": """
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;

public final class Keys {

    static KeyPair makeA() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static KeyPair makeB() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
""",
        "sign": """
    static byte[] sign(PrivateKey key, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(message);
        return signature.sign();
    }
""",
        "verify": """
    static boolean verify(PublicKey key, byte[] message, byte[] sig) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(message);
        return signature.verify(sig);
    }
""",
        "encrypt": """
    static byte[] encrypt(PublicKey key, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }
""",
        "encrypt_alt": """
    static byte[] encrypt(PublicKey key, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }
""",
        "imported": """
    static byte[] signImported(PrivateKey importedKey, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(importedKey);
        return signature.sign();
    }
""",
        "tail": "}\n",
    },
    "go": {
        "head": """
package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func newKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
""",
        "head_two": """
package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func makeA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func makeB() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
""",
        "sign": """
func sign(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
}
""",
        "verify": """
func verify(pub *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}
""",
        "encrypt": """
func encrypt(key *rsa.PrivateKey, message []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, message, nil)
}
""",
        "encrypt_alt": """
func encrypt(key *rsa.PrivateKey, message []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, message)
}
""",
        "imported": """
func signImported(imported *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, imported, crypto.SHA256, digest)
}
""",
        "tail": "",
    },
}

# Each case: the sink functions the file defines, the body of run() per language, the expected usage of
# every generation in line order. A file defines only the sinks it calls: an RSA sink that is never
# called has no demonstrated flow and, by design, blocks the inference for the whole file.
RUN = {
    "python": "\n\ndef run():\n{body}",
    "java": "\n    static void run() throws Exception {{\n{body}    }}\n",
    "go": "\nfunc run(digest []byte) error {{\n{body}}}\n",
}

BODIES = {
    "sign": {
        "python": "    key = make()\n    return sign(key, b'x')\n",
        "java": "        KeyPair pair = make();\n        sign(pair.getPrivate(), new byte[0]);\n",
        "go": "\tkey, err := newKey()\n\tif err != nil {\n\t\treturn err\n\t}\n"
        "\t_, err = sign(key, digest)\n\treturn err\n",
    },
    "sign_verify": {
        "python": "    key = make()\n    token = sign(key, b'x')\n"
        "    return verify(key.public_key(), token, b'x')\n",
        "java": "        KeyPair pair = make();\n        byte[] sig = sign(pair.getPrivate(), new byte[0]);\n"
        "        verify(pair.getPublic(), new byte[0], sig);\n",
        "go": "\tkey, err := newKey()\n\tif err != nil {\n\t\treturn err\n\t}\n"
        "\tsig, err := sign(key, digest)\n\tif err != nil {\n\t\treturn err\n\t}\n"
        "\treturn verify(&key.PublicKey, digest, sig)\n",
    },
    "encrypt": {
        "python": "    key = make()\n    return encrypt(key.public_key(), b'x')\n",
        "java": "        KeyPair pair = make();\n        encrypt(pair.getPublic(), new byte[0]);\n",
        "go": "\tkey, err := newKey()\n\tif err != nil {\n\t\treturn err\n\t}\n"
        "\t_, err = encrypt(key, digest)\n\treturn err\n",
    },
    "sign_encrypt": {
        "python": "    key = make()\n    sign(key, b'x')\n    return encrypt(key.public_key(), b'x')\n",
        "java": "        KeyPair pair = make();\n        sign(pair.getPrivate(), new byte[0]);\n"
        "        encrypt(pair.getPublic(), new byte[0]);\n",
        "go": "\tkey, err := newKey()\n\tif err != nil {\n\t\treturn err\n\t}\n"
        "\tif _, err = sign(key, digest); err != nil {\n\t\treturn err\n\t}\n"
        "\t_, err = encrypt(key, digest)\n\treturn err\n",
    },
    "none": {
        "python": "    return make()\n",
        "java": "        make();\n",
        "go": "\t_, err := newKey()\n\treturn err\n",
    },
    "reassigned": {
        "python": "    key = make()\n    key = make()\n    return sign(key, b'x')\n",
        "java": "        KeyPair pair = make();\n        pair = make();\n"
        "        sign(pair.getPrivate(), new byte[0]);\n",
        "go": "\tkey, err := newKey()\n\tkey, err = newKey()\n\tif err != nil {\n\t\treturn err\n\t}\n"
        "\t_, err = sign(key, digest)\n\treturn err\n",
    },
}

CASES = {
    "sign": (["sign"], "sign", ["signature"]),
    "sign_and_verify": (["sign", "verify"], "sign_verify", ["signature"]),
    "encrypt_only": (["encrypt"], "encrypt", ["unknown"]),
    "sign_and_encrypt_same_key": (["sign", "encrypt"], "sign_encrypt", ["unknown"]),
    "no_consumer": ([], "none", ["unknown"]),
    "reassigned_key": (["sign"], "reassigned", ["unknown"]),
    "imported_key_next_to_one_generation": (["sign", "imported"], "sign", ["unknown"]),
}

TWO_KEY_BODIES = {
    "distinct_keys_sign_and_encrypt": (
        ["sign", "encrypt_alt"],
        {
            "python": "    first = make_a()\n    second = make_b()\n    sign(first, b'x')\n"
            "    return encrypt(second.public_key(), b'x')\n",
            "java": "        KeyPair first = makeA();\n        KeyPair second = makeB();\n"
            "        sign(first.getPrivate(), new byte[0]);\n"
            "        encrypt(second.getPublic(), new byte[0]);\n",
            "go": "\tfirst, err := makeA()\n\tsecond, err2 := makeB()\n\tif err != nil || err2 != nil {\n"
            "\t\treturn err\n\t}\n\tif _, err = sign(first, digest); err != nil {\n\t\treturn err\n\t}\n"
            "\t_, err = encrypt(second, digest)\n\treturn err\n",
        },
        ["signature", "unknown"],
    ),
    "distinct_keys_both_sign_through_separate_sinks": (
        ["sign", "verify"],
        {
            "python": "    first = make_a()\n    second = make_b()\n    sign(first, b'x')\n"
            "    return verify(second.public_key(), b'', b'x')\n",
            "java": "        KeyPair first = makeA();\n        KeyPair second = makeB();\n"
            "        sign(first.getPrivate(), new byte[0]);\n"
            "        verify(second.getPublic(), new byte[0], new byte[0]);\n",
            "go": "\tfirst, err := makeA()\n\tsecond, err2 := makeB()\n\tif err != nil || err2 != nil {\n"
            "\t\treturn err\n\t}\n\tif _, err = sign(first, digest); err != nil {\n\t\treturn err\n\t}\n"
            "\treturn verify(&second.PublicKey, digest, digest)\n",
        },
        ["signature", "signature"],
    ),
    "one_sink_reached_by_two_generations": (
        ["sign"],
        {
            "python": "    first = make_a()\n    second = make_b()\n    sign(first, b'x')\n"
            "    return sign(second, b'x')\n",
            "java": "        KeyPair first = makeA();\n        KeyPair second = makeB();\n"
            "        sign(first.getPrivate(), new byte[0]);\n"
            "        sign(second.getPrivate(), new byte[0]);\n",
            "go": "\tfirst, err := makeA()\n\tsecond, err2 := makeB()\n\tif err != nil || err2 != nil {\n"
            "\t\treturn err\n\t}\n\tif _, err = sign(first, digest); err != nil {\n\t\treturn err\n\t}\n"
            "\t_, err = sign(second, digest)\n\treturn err\n",
        },
        ["unknown", "unknown"],
    ),
}


def build(language: str, head: str, sinks: list[str], body: str) -> str:
    parts = LANGS[language]
    run = RUN[language].format(body=body)
    return parts[head] + "".join(parts[name] for name in sinks) + run + parts["tail"]


def scan_text(language: str, text: str) -> list[Finding]:
    return scan_source(textwrap.dedent(text).lstrip("\n"), FILES[language], language, load_rules(language))


def generations(findings: list[Finding]) -> list[Finding]:
    return sorted((f for f in findings if f.extra["rule"] in GENERATION_RULES), key=lambda f: f.location.line)


@pytest.mark.parametrize("language", ["python", "java", "go"])
@pytest.mark.parametrize("case", sorted(CASES))
def test_rsa_generation_usage_follows_the_demonstrated_sinks(language, case):
    sinks, body, expect = CASES[case]
    found = generations(scan_text(language, build(language, "head", sinks, BODIES[body][language])))
    assert [f.usage.value for f in found] == expect
    assert all(f.key_size == 2048 for f in found)
    for finding in found:
        if finding.usage.value == "signature":
            assert finding.extra["usage_source"] == "flow"
            assert finding.confidence == 0.8
        else:
            assert "usage_source" not in finding.extra


@pytest.mark.parametrize("language", ["python", "java", "go"])
@pytest.mark.parametrize("case", sorted(TWO_KEY_BODIES))
def test_distinct_keys_of_one_size_are_judged_separately(language, case):
    sinks, bodies, expect = TWO_KEY_BODIES[case]
    found = generations(scan_text(language, build(language, "head_two", sinks, bodies[language])))
    assert [(f.key_size, f.usage.value) for f in found] == [(2048, usage) for usage in expect]


@pytest.mark.parametrize("language", ["python", "java", "go"])
@pytest.mark.parametrize("alt", ["encrypt", "encrypt_alt"])
def test_rsa_encrypt_sink_is_an_encryption_finding_that_takes_the_size_by_flow(language, alt):
    text = build(language, "head", [alt], BODIES["encrypt"][language])
    findings = scan_text(language, text)
    sink = next(
        f for f in findings if f.raw_name.startswith("RSA") and f.extra["rule"] not in GENERATION_RULES
    )
    assert (sink.raw_name.split("/")[0], sink.usage.value, sink.key_size) == ("RSA", "encryption", 2048)
    assert sink.extra["key_size_source"] == "flow"


@pytest.mark.parametrize(
    "language, call, padding",
    [
        ("python", "key.decrypt(b'x', padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), label=None))", "OAEP"),
        ("python", "key.public_key().encrypt(b'x', padding.PKCS1v15())", "PKCS1v15"),
        ("go", "rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ct, nil)", "OAEP"),
        ("go", "rsa.DecryptPKCS1v15(rand.Reader, key, ct)", "PKCS1v15"),
        ("go", "rsa.DecryptPKCS1v15SessionKey(rand.Reader, key, ct, session)", "PKCS1v15"),
    ],
)
def test_rsa_encrypt_and_decrypt_sinks_read_the_key_argument_and_padding(language, call, padding):
    source = {
        "python": f"def f(key):\n    return {call}\n",
        "go": f"func f(key *rsa.PrivateKey, ct, session []byte) {{\n\t{call}\n}}\n",
    }[language]
    findings = [f for f in scan_text(language, source) if f.raw_name == "RSA"]
    assert [(f.usage.value, f.padding) for f in findings] == [("encryption", padding)]


def test_usage_observed_directly_on_a_generation_is_preserved(tmp_path):
    rules = """
- id: GEN
  language: python
  pattern: 'make_key\\(\\)'
  raw_name: RSA
  kind_hint: algorithm
  usage: encryption
  key_size: 2048
  provides_key_size: RSA
- id: SINK
  language: python
  pattern: '(?P<key_arg>[A-Za-z_]\\w*)\\.sign\\('
  raw_name: RSA
  kind_hint: algorithm
  usage: signature
  inherit_key_size: RSA
"""
    (tmp_path / "python.yaml").write_text(rules, encoding="utf-8")
    source = "k = make_key()\nk.sign(b'x')\n"
    found = scan_source(source, "app/a.py", "python", load_rules("python", tmp_path))
    generation = next(f for f in found if f.extra["rule"] == "GEN")
    assert generation.usage.value == "encryption"
    assert "usage_source" not in generation.extra
    sink = next(f for f in found if f.extra["rule"] == "SINK")
    assert sink.key_size == 2048


@pytest.mark.parametrize(
    "path, line, size",
    [
        ("python/license_token.py", 6, 1024),
        ("java/ReceiptSigner.java", 12, 1024),
        ("go/invoice-service/main.go", 13, 1024),
    ],
)
def test_kit_rsa_generation_becomes_a_signature_through_its_flow(path, line, size):
    findings = [f for f in CodeScanner().scan(KIT / path, KIT) if isinstance(f, Finding)]
    found = next(f for f in findings if f.raw_name == "RSA" and f.location.line == line)
    assert (found.key_size, found.usage.value) == (size, "signature")
    assert found.extra["usage_source"] == "flow"
    assert found.extra["rule"] in GENERATION_RULES
    assert found.confidence == 0.8
