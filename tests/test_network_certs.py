"""certs.py: describe_certificate and the Certificate message splitter (task 2.9, M2M3-02).

The real DER comes from the committed TLS 1.2 fixture. Other key types are built in memory with
``cryptography``; no file is written and nothing touches the network.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from quantumtrace.scanners.network import certs, purepy

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "pcap" / "tls12_ecdhe_ecdsa_p256.pcap"
KEYS = {
    "key_type",
    "key_size",
    "curve",
    "public_key_algorithm_oid",
    "signature_algorithm",
    "signature_algorithm_oid",
    "not_before",
    "not_after",
    "self_signed",
}


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _der(key, algorithm, *, subject="a.lab", issuer=None, days=30) -> bytes:
    start = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer or subject))
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=days))
        .sign(key, algorithm)
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="module")
def fixture_message() -> bytes:
    result = purepy.read_flows(FIXTURE)
    assert result.errors == []
    message = result.flows[0].server_certificate_msg
    assert message is not None
    return message


# --- the real fixture -----------------------------------------------------------------------


def test_real_fixture_certificate(fixture_message):
    (der,) = certs.split_certificate_message(fixture_message)
    info = certs.describe_certificate(der)
    assert info == {
        "key_type": "EC",
        "key_size": None,
        "curve": "secp256r1",
        "public_key_algorithm_oid": "1.2.840.10045.2.1",
        "signature_algorithm": "ecdsa-with-SHA256",
        "signature_algorithm_oid": "1.2.840.10045.4.3.2",
        "not_before": "2026-10-10T18:25:08+00:00",
        "not_after": "2027-10-10T18:25:08+00:00",
        "self_signed": True,
    }
    assert certs.describe_certificate_message(fixture_message) == info


# --- key types ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "algorithm", "want"),
    [
        (
            rsa.generate_private_key(65537, 2048),
            hashes.SHA256(),
            {
                "key_type": "RSA",
                "key_size": 2048,
                "curve": None,
                "signature_algorithm": "sha256WithRSAEncryption",
            },
        ),
        (
            rsa.generate_private_key(65537, 3072),
            hashes.SHA384(),
            {
                "key_type": "RSA",
                "key_size": 3072,
                "curve": None,
                "signature_algorithm": "sha384WithRSAEncryption",
            },
        ),
        (
            ec.generate_private_key(ec.SECP384R1()),
            hashes.SHA384(),
            {
                "key_type": "EC",
                "key_size": None,
                "curve": "secp384r1",
                "signature_algorithm": "ecdsa-with-SHA384",
            },
        ),
        (
            ed25519.Ed25519PrivateKey.generate(),
            None,
            {"key_type": "Ed25519", "key_size": None, "curve": None, "signature_algorithm": "ed25519"},
        ),
        (
            ed448.Ed448PrivateKey.generate(),
            None,
            {"key_type": "Ed448", "key_size": None, "curve": None, "signature_algorithm": "ed448"},
        ),
        (
            dsa.generate_private_key(2048),
            hashes.SHA256(),
            {"key_type": "DSA", "key_size": 2048, "curve": None, "signature_algorithm": "dsa-with-sha256"},
        ),
    ],
    ids=["rsa2048", "rsa3072", "p384", "ed25519", "ed448", "dsa"],
)
def test_key_types(key, algorithm, want):
    info = certs.describe_certificate(_der(key, algorithm))
    assert info is not None and set(info) == KEYS
    assert {k: info[k] for k in want} == want
    assert info["not_before"] == "2026-01-01T00:00:00+00:00"
    assert info["not_after"] == "2026-01-31T00:00:00+00:00"
    assert info["self_signed"] is True


def test_issuer_differs_from_subject_is_not_self_signed():
    key = ec.generate_private_key(ec.SECP256R1())
    info = certs.describe_certificate(_der(key, hashes.SHA256(), subject="leaf.lab", issuer="ca.lab"))
    assert info is not None and info["self_signed"] is False


def test_unknown_key_algorithm_keeps_its_oid_and_is_not_guessed():
    der = _der(ed25519.Ed25519PrivateKey.generate(), None)
    # 1.3.101.112 -> 1.3.101.127, in both the key and the signature algorithm identifiers
    patched = der.replace(bytes.fromhex("06032b6570"), bytes.fromhex("06032b657f"))
    assert patched != der
    info = certs.describe_certificate(patched)
    assert info is not None
    assert info["key_type"] == "unknown" and info["key_size"] is None and info["curve"] is None
    assert info["public_key_algorithm_oid"] == "1.3.101.127"
    assert info["signature_algorithm"] == info["signature_algorithm_oid"] == "1.3.101.127"


def test_description_holds_no_key_material():
    key = rsa.generate_private_key(65537, 2048)
    info = certs.describe_certificate(_der(key, hashes.SHA256()))
    assert info is not None
    assert set(info) == KEYS
    assert all(not isinstance(v, bytes) for v in info.values())


# --- bytes that do not decode ----------------------------------------------------------------


@pytest.mark.parametrize("data", [b"", b"\x00", b"not a certificate", b"\x30\x03\x02\x01\x00", b"\xff" * 64])
def test_undecodable_bytes_give_none(data):
    assert certs.describe_certificate(data) is None


def test_truncated_certificate_gives_none(fixture_message):
    (der,) = certs.split_certificate_message(fixture_message)
    assert certs.describe_certificate(der[: len(der) // 2]) is None


def test_non_bytes_never_raises():
    assert certs.describe_certificate(None) is None  # type: ignore[arg-type]
    assert certs.split_certificate_message(None) == []  # type: ignore[arg-type]


# --- message splitter ------------------------------------------------------------------------


def _message(*entries: bytes) -> bytes:
    chain = b"".join(len(e).to_bytes(3, "big") + e for e in entries)
    return len(chain).to_bytes(3, "big") + chain


def test_splitter_one_and_three_entries():
    assert certs.split_certificate_message(_message(b"abc")) == [b"abc"]
    assert certs.split_certificate_message(_message(b"a", b"bb", b"ccc")) == [b"a", b"bb", b"ccc"]


def test_splitter_keeps_complete_entries_of_a_truncated_message():
    message = _message(b"aaaa", b"bbbbbbbb")
    assert certs.split_certificate_message(message[:-3]) == [b"aaaa"]


@pytest.mark.parametrize("message", [b"", b"\x00", b"\x00\x00\x00", b"\x00\x00\x06\x00\x00\x09ab"])
def test_splitter_empty_and_bad_messages(message):
    assert certs.split_certificate_message(message) == []


def test_splitter_ignores_bytes_after_the_declared_length():
    assert certs.split_certificate_message(_message(b"abc") + b"trailing") == [b"abc"]


def test_message_without_a_decodable_leaf_gives_none():
    assert certs.describe_certificate_message(_message(b"junk")) is None
    assert certs.describe_certificate_message(b"") is None
