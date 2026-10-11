"""Key, certificate and keystore files (config/keyfiles.py). Fixtures are generated per test run so no
private key is ever committed; every key below is a throwaway."""

from __future__ import annotations

import base64
import datetime
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x25519
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

from quantumtrace import pipeline
from quantumtrace.models import Finding, KindHint, ScanError, SourceType, Tier, Usage
from quantumtrace.output.cyclonedx import build_cbom, validate_cbom
from quantumtrace.scanners.config.keyfiles import KeyFileScanner

SCANNER = KeyFileScanner()
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)


def _cert(key, digest=hashes.SHA256(), days=365):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.invalid")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=days))
    )
    edwards = isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))
    return builder.sign(key, None if edwards else digest)


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


@pytest.fixture(scope="module")
def keys():
    return {
        "rsa": rsa.generate_private_key(65537, 2048),
        "p256": ec.generate_private_key(ec.SECP256R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "ed448": ed448.Ed448PrivateKey.generate(),
        "dsa": dsa.generate_private_key(2048),
        "x25519": x25519.X25519PrivateKey.generate(),
    }


@pytest.fixture(scope="module")
def files(tmp_path_factory, keys):
    d = tmp_path_factory.mktemp("keys")
    pem, der = s.Encoding.PEM, s.Encoding.DER
    pkcs8, legacy, openssh = (
        s.PrivateFormat.PKCS8,
        s.PrivateFormat.TraditionalOpenSSL,
        s.PrivateFormat.OpenSSH,
    )
    clear, locked = s.NoEncryption(), s.BestAvailableEncryption(b"fixture-password")
    rsa_key, p256, edk = keys["rsa"], keys["p256"], keys["ed25519"]
    c_rsa, c_ec, c_ed = _cert(rsa_key), _cert(p256), _cert(edk)
    c_long = _cert(rsa_key, hashes.SHA384(), days=3650 * 3)
    (d / "server.crt").write_bytes(c_rsa.public_bytes(pem))
    (d / "chain.pem").write_bytes(c_ec.public_bytes(pem) + c_ed.public_bytes(pem) + c_long.public_bytes(pem))
    (d / "server.der").write_bytes(c_rsa.public_bytes(der))
    (d / "rsa.key").write_bytes(rsa_key.private_bytes(pem, legacy, clear))
    (d / "rsa_enc.key").write_bytes(rsa_key.private_bytes(pem, legacy, locked))
    (d / "p256.pem").write_bytes(p256.private_bytes(pem, pkcs8, clear))
    (d / "enc.p8").write_bytes(p256.private_bytes(pem, pkcs8, locked))
    (d / "dsa.key").write_bytes(keys["dsa"].private_bytes(pem, legacy, clear))
    (d / "ed448.pem").write_bytes(keys["ed448"].private_bytes(pem, pkcs8, clear))
    spki = s.PublicFormat.SubjectPublicKeyInfo
    (d / "x25519.pem").write_bytes(keys["x25519"].public_key().public_bytes(pem, spki))
    (d / "pkcs1.pem").write_bytes(rsa_key.public_key().public_bytes(pem, s.PublicFormat.PKCS1))
    (d / "pub.der").write_bytes(p256.public_key().public_bytes(der, spki))
    (d / "dhparam.pem").write_bytes(
        dh.generate_parameters(2, 2048).parameter_bytes(pem, s.ParameterFormat.PKCS3)
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(p256, hashes.SHA384())
    )
    (d / "request.csr").write_bytes(csr.public_bytes(pem))
    (d / "id_ed25519").write_bytes(edk.private_bytes(pem, openssh, clear))
    # An encrypted openssh-key-v1 key, built by hand: only its clear public part is ever read.
    blob = base64.b64decode(
        rsa_key.public_key().public_bytes(s.Encoding.OpenSSH, s.PublicFormat.OpenSSH).split()[1]
    )
    body = b"openssh-key-v1\x00" + _ssh_string(b"aes256-ctr") + _ssh_string(b"bcrypt") + _ssh_string(b"x" * 8)
    body += struct.pack(">I", 1) + _ssh_string(blob) + _ssh_string(b"\x00" * 64)
    lines = base64.b64encode(body).decode()
    (d / "id_rsa").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines[i : i + 70] for i in range(0, len(lines), 70))
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    ssh_line = s.Encoding.OpenSSH, s.PublicFormat.OpenSSH
    (d / "id_ed25519.pub").write_bytes(edk.public_key().public_bytes(*ssh_line) + b" user@example.invalid\n")
    rsa_line = rsa_key.public_key().public_bytes(*ssh_line).decode()
    ec_line = p256.public_key().public_bytes(*ssh_line).decode()
    (d / "authorized_keys").write_text(f'# keys\nfrom="10.0.0.0/8",no-pty {rsa_line} deploy@ci\n{ec_line}\n')
    (d / "known_hosts").write_text(f"|1|abc=|def= {ec_line}\n@cert-authority *.example.invalid {rsa_line}\n")
    rfc4716 = rsa_line.split()[1]
    (d / "ssh2.pub").write_text(
        '---- BEGIN SSH2 PUBLIC KEY ----\nComment: "x"\n'
        + "\n".join(rfc4716[i : i + 70] for i in range(0, len(rfc4716), 70))
        + "\n---- END SSH2 PUBLIC KEY ----\n"
    )
    (d / "bundle.p12").write_bytes(pkcs12.serialize_key_and_certificates(b"a", rsa_key, c_rsa, [c_ec], clear))
    (d / "locked.pfx").write_bytes(pkcs12.serialize_key_and_certificates(b"a", rsa_key, c_rsa, None, locked))
    (d / "bundle.p7b").write_bytes(pkcs7.serialize_certificates([c_rsa, c_ec], pem))

    def utf(text: str) -> bytes:
        return struct.pack(">H", len(text)) + text.encode()

    der_ec, der_rsa, sealed = c_ec.public_bytes(der), c_rsa.public_bytes(der), b"\x30\x03\x02\x01\x00"
    jks = b"\xfe\xed\xfe\xed" + struct.pack(">II", 2, 2)
    jks += (
        struct.pack(">I", 2) + utf("ca") + b"\0" * 8 + utf("X.509") + struct.pack(">I", len(der_ec)) + der_ec
    )
    jks += struct.pack(">I", 1) + utf("server") + b"\0" * 8 + struct.pack(">I", len(sealed)) + sealed
    jks += struct.pack(">I", 1) + utf("X.509") + struct.pack(">I", len(der_rsa)) + der_rsa + b"\0" * 20
    (d / "app.jks").write_bytes(jks)
    (d / "garbage.pem").write_text("not a key\n")
    (d / "pgp.pem").write_text(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"
    )
    return d


def scan(files: Path, name: str) -> tuple[list[Finding], list[ScanError]]:
    out = list(SCANNER.scan(files / name, files))
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, ScanError)]


def rows(findings):
    return [(f.kind_hint, f.raw_name, f.key_size, f.curve, f.usage, f.extra["object"]) for f in findings]


@pytest.mark.parametrize(
    "name,expected",
    [
        ("server.crt", [(KindHint.CERTIFICATE, "RSA", 2048, None, Usage.AUTHENTICATION, "certificate")]),
        ("server.der", [(KindHint.CERTIFICATE, "RSA", 2048, None, Usage.AUTHENTICATION, "certificate")]),
        ("rsa.key", [(KindHint.KEY, "RSA", 2048, None, Usage.UNKNOWN, "private_key")]),
        ("rsa_enc.key", [(KindHint.KEY, "RSA", None, None, Usage.UNKNOWN, "private_key")]),
        ("p256.pem", [(KindHint.KEY, "EC", None, "secp256r1", Usage.UNKNOWN, "private_key")]),
        ("enc.p8", [(KindHint.KEY, "unresolved", None, None, Usage.UNKNOWN, "private_key")]),
        ("dsa.key", [(KindHint.KEY, "DSA", 2048, None, Usage.SIGNATURE, "private_key")]),
        ("ed448.pem", [(KindHint.KEY, "Ed448", None, None, Usage.SIGNATURE, "private_key")]),
        ("x25519.pem", [(KindHint.KEY, "X25519", None, None, Usage.KEY_EXCHANGE, "public_key")]),
        ("pkcs1.pem", [(KindHint.KEY, "RSA", 2048, None, Usage.UNKNOWN, "public_key")]),
        ("pub.der", [(KindHint.KEY, "EC", None, "secp256r1", Usage.UNKNOWN, "public_key")]),
        ("dhparam.pem", [(KindHint.KEY, "DH", 2048, None, Usage.KEY_EXCHANGE, "dh_parameters")]),
        ("request.csr", [(KindHint.KEY, "EC", None, "secp256r1", Usage.UNKNOWN, "certificate_request")]),
        ("id_ed25519", [(KindHint.KEY, "ssh-ed25519", None, None, Usage.SIGNATURE, "private_key")]),
        ("id_rsa", [(KindHint.KEY, "ssh-rsa", 2048, None, Usage.SIGNATURE, "private_key")]),
        ("id_ed25519.pub", [(KindHint.KEY, "ssh-ed25519", None, None, Usage.SIGNATURE, "ssh_public_key")]),
        ("ssh2.pub", [(KindHint.KEY, "ssh-rsa", 2048, None, Usage.SIGNATURE, "ssh_public_key")]),
        ("locked.pfx", [(KindHint.KEY, "unresolved", None, None, Usage.UNKNOWN, "keystore")]),
    ],
)
def test_single_object_files(files, name, expected):
    findings, errors = scan(files, name)
    assert errors == []
    assert rows(findings) == expected
    assert all(f.location.source_type == SourceType.KEYFILE for f in findings)


def test_certificate_chain_keeps_each_certificate_with_its_line_and_signature(files):
    findings, _ = scan(files, "chain.pem")
    got = [(f.location.line, f.raw_name, f.extra["signature_algorithm"]) for f in findings]
    assert got == [
        (1, "EC", "ecdsa-with-SHA256"),
        (10, "Ed25519", "ed25519"),
        (17, "RSA", "sha384WithRSAEncryption"),
    ]
    assert all(f.extra["not_after"] and f.extra["self_signed"] is True for f in findings)


def test_private_keys_are_flagged_and_encryption_is_recorded(files):
    clear, _ = scan(files, "rsa.key")
    locked, _ = scan(files, "rsa_enc.key")
    sshlocked, _ = scan(files, "id_rsa")
    assert (
        clear[0].extra["hygiene_flags"] == ["private_key_material"] and clear[0].extra["encrypted"] is False
    )
    assert locked[0].extra["encrypted"] is True and sshlocked[0].extra["encrypted"] is True


def test_ssh_authorized_keys_and_known_hosts(files):
    auth, _ = scan(files, "authorized_keys")
    hosts, _ = scan(files, "known_hosts")
    assert [(f.location.line, f.raw_name, f.key_size, f.curve) for f in auth] == [
        (2, "ssh-rsa", 2048, None),
        (3, "ecdsa-sha2-nistp256", None, "secp256r1"),
    ]
    assert [(f.raw_name, f.extra.get("marker")) for f in hosts] == [
        ("ecdsa-sha2-nistp256", None),
        ("ssh-rsa", "@cert-authority"),
    ]
    assert all("@" not in f.location.snippet for f in auth)  # key comments (emails) are never shown


def test_containers_pkcs12_pkcs7_and_jks(files):
    p12, _ = scan(files, "bundle.p12")
    p7, _ = scan(files, "bundle.p7b")
    jks, _ = scan(files, "app.jks")
    assert [(f.kind_hint, f.raw_name) for f in p12] == [
        (KindHint.KEY, "RSA"),
        (KindHint.CERTIFICATE, "RSA"),
        (KindHint.CERTIFICATE, "EC"),
    ]
    # PKCS#7 keeps certificates in a DER SET OF, sorted by encoding, so the order is not the input order.
    assert sorted(f.raw_name for f in p7) == ["EC", "RSA"] and len({f.id for f in p7}) == 2
    assert [(f.kind_hint, f.raw_name, f.extra.get("encrypted")) for f in jks] == [
        (KindHint.CERTIFICATE, "EC", None),
        (KindHint.KEY, "RSA", True),
        (KindHint.CERTIFICATE, "RSA", None),
    ]


def test_unrecognized_files_are_coverage_errors(files):
    assert scan(files, "garbage.pem") == ([], scan(files, "garbage.pem")[1])
    assert [e.message for e in scan(files, "garbage.pem")[1]] == [
        "no key, certificate or keystore recognized"
    ]
    assert "OpenPGP keys are not supported" in scan(files, "pgp.pem")[1][0].message


def test_no_private_key_material_reaches_any_output(files, keys):
    result = pipeline.run([files])
    dump = result.model_dump_json()
    for key in (keys["rsa"], keys["p256"], keys["dsa"], keys["ed448"], keys["ed25519"]):
        secret = key.private_bytes(s.Encoding.DER, s.PrivateFormat.PKCS8, s.NoEncryption())
        encoded = base64.b64encode(secret).decode()
        for start in range(0, len(encoded) - 24, 24):
            assert encoded[start : start + 24] not in dump
    assert "user@example.invalid" not in dump and "deploy@ci" not in dump


def test_engine_classifies_key_files_and_cbom_validates(files):
    result = pipeline.run([files])
    by_name = {}
    for asset in result.assets:
        by_name.setdefault(asset.canonical_name, set()).add(asset.tier)
    assert by_name["RSA"] == {Tier.CRITICAL} and by_name["Ed448"] == {Tier.CRITICAL}
    assert Tier.UNKNOWN in by_name["unresolved"]
    actions = {r.action for a in result.assets for r in a.recommendations}
    assert (
        "Remove the private key from the repository or image, rotate it and keep it in a secret store."
        in actions
    )
    assert any(action.startswith("Identify the key's use") for action in actions)
    assert validate_cbom(build_cbom(result)) == []
    assert {e.message for e in result.errors} >= {"no key, certificate or keystore recognized"}


def test_empty_key_file_is_neither_a_finding_nor_an_error(tmp_path):
    (tmp_path / "blank_rsa.key").write_bytes(b"")
    assert list(SCANNER.scan(tmp_path / "blank_rsa.key", tmp_path)) == []


def _blob(*fields: bytes) -> str:
    return base64.b64encode(b"".join(_ssh_string(f) for f in fields)).decode()


def test_ssh1_hybrid_pq_and_fido_certificate_public_keys(tmp_path):
    modulus = str((1 << 1023) + 12345)
    (tmp_path / "rsa1.pub").write_text(f"1024 65537 {modulus} old@host\n")
    mldsa = _blob(b"ssh-mldsa44-ed25519", b"\x01" * 1344)
    (tmp_path / "pq.pub").write_text(f"ssh-mldsa44-ed25519 {mldsa} pq@host\n")
    fido = _blob(b"sk-ssh-ed25519-cert-v01@openssh.com", b"nonce", b"\x02" * 32)
    (tmp_path / "fido-cert.pub").write_text(f"sk-ssh-ed25519-cert-v01@openssh.com {fido}\n")
    (tmp_path / "liar.pub").write_text(f"ssh-ed25519 {mldsa}\n")  # the blob names another type
    got = {name: scan(tmp_path, name) for name in ("rsa1.pub", "pq.pub", "fido-cert.pub", "liar.pub")}
    # SSH-1 RSA authentication decrypts a server challenge, so the use is not stated as signature.
    assert rows(got["rsa1.pub"][0]) == [(KindHint.KEY, "RSA", 1024, None, Usage.UNKNOWN, "ssh1_public_key")]
    assert rows(got["pq.pub"][0]) == [
        (KindHint.KEY, "ssh-mldsa44-ed25519", None, None, Usage.SIGNATURE, "ssh_public_key")
    ]
    assert [f.raw_name for f in got["fido-cert.pub"][0]] == ["sk-ssh-ed25519@openssh.com"]
    assert got["liar.pub"][0] == [] and got["liar.pub"][1]
    result = pipeline.run([tmp_path / "pq.pub", tmp_path / "fido-cert.pub"])
    tiers = {a.canonical_name: a.tier for a in result.assets}
    assert tiers["ssh-mldsa44-ed25519"] == Tier.SAFE and tiers["Ed25519"] == Tier.CRITICAL


def test_nonconformant_certificate_request_is_read_from_its_der(tmp_path, keys):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(keys["rsa"], hashes.SHA256())
    )
    der = bytearray(csr.public_bytes(s.Encoding.DER))
    version = der.index(b"\x02\x01\x00")  # CertificationRequestInfo.version 0 -> 2, as certbot test data
    der[version + 2] = 2
    pem = base64.b64encode(bytes(der)).decode()
    (tmp_path / "v2.csr").write_text(
        f"-----BEGIN CERTIFICATE REQUEST-----\n{pem}\n-----END CERTIFICATE REQUEST-----\n"
    )
    findings, errors = scan(tmp_path, "v2.csr")
    assert errors == []
    assert [(f.raw_name, f.key_size, f.extra["signature_algorithm"]) for f in findings] == [
        ("RSA", 2048, "sha256WithRSAEncryption")
    ]


def test_key_material_under_other_names_is_claimed_by_content(tmp_path, keys):
    pem = s.Encoding.PEM
    key = keys["p256"].private_bytes(pem, s.PrivateFormat.TraditionalOpenSSL, s.NoEncryption())
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "foo.priv").write_bytes(key)
    (tmp_path / "secrets" / "ssh_user_ca_key").write_bytes(key)
    cert = _cert(keys["rsa"]).public_bytes(pem).decode()
    indented = "\n".join("      " + row for row in cert.splitlines())
    fake = "      -----BEGIN CERTIFICATE-----\n      ZmFrZQ==\n      -----END CERTIFICATE-----"
    (tmp_path / "values.yml").write_text(f"certs:\n  ca: |\n{indented}\n  placeholder: |\n{fake}\n")
    (tmp_path / "README.md").write_text("```\n" + key.decode() + "```\n")  # documentation is not sniffed
    (tmp_path / "notes.txt").write_text("nothing to see\n")
    result = pipeline.run([tmp_path])
    found = sorted((f.location.file, f.raw_name, f.extra["object"]) for f in result.findings)
    assert found == [
        ("secrets/foo.priv", "EC", "private_key"),
        ("secrets/ssh_user_ca_key", "EC", "private_key"),
        ("values.yml", "RSA", "certificate"),
    ]
    assert result.errors == []  # the fake YAML block is not a coverage error of a key file
