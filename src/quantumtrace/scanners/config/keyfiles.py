"""Key, certificate and keystore files (PLAN 3.13, M3D-12, M2M3-01/02).

Detect-only: every finding states what a file holds (key type, size or curve, certificate signature and
validity) and never a tier. Private key material never leaves this module: a private key is loaded only
to read its public description, and neither its bytes, its PEM body nor a key comment reach a snippet or
`extra`. Snippets are the PEM header line or the key type.

Accepted files (M2M3-01): .pem .crt .cer .der .key .csr .p7b .p8 .pub .p12 .pfx .jks .keystore, the SSH
key names id_rsa, id_dsa, id_ecdsa, id_ed25519 (and their *_sk variants), ssh_host_*_key, authorized_keys
and known_hosts.

Finding shapes (source_type keyfile, detector config.keyfile):
- certificate: kind certificate, usage authentication, raw_name the key type (RSA, EC, Ed25519, Ed448,
  DSA, or the SubjectPublicKeyInfo OID when the library cannot decode the key, as M2 does), key_size or
  curve, extra key_algorithm, signature_algorithm(_oid), not_before, not_after, self_signed (M2M3-02:
  M2 describe_certificate, one call per DER certificate).
- key: kind key, raw_name the key type (RSA, EC, DSA, DH, Ed25519, Ed448, X25519, X448) or the SSH key
  type (ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519, ...), usage signature for signature-only types and
  SSH keys, key_exchange for X25519/X448/DH, unknown otherwise. A certificate request adds
  extra.signature_algorithm. A private key adds hygiene_flags [private_key_material] and
  extra.encrypted. A key whose type cannot be read (an encrypted PKCS#8 or PKCS#12 without a password)
  has raw_name "unresolved".
Every finding has extra.object (certificate, certificate_request, public_key, private_key,
dh_parameters, ssh_public_key, ssh_certificate, keystore) and extra.format (pem, der, openssh, ssh2,
pkcs12, jks, jceks).

A file in which nothing is recognized is a ScanError, so coverage is never reported as complete for it.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_der_parameters,
    load_der_private_key,
    load_der_public_key,
    load_pem_parameters,
    load_ssh_private_key,
    pkcs7,
    pkcs12,
)

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id, is_test_path, register
from quantumtrace.scanners.network.certs import describe_certificate

DETECTOR = "config.keyfile"
MAX_FILE_BYTES = 5 * 1024 * 1024
UNRESOLVED = "unresolved"
PRIVATE_FLAG = "private_key_material"

SUFFIXES = frozenset(
    {
        ".pem",
        ".crt",
        ".cer",
        ".der",
        ".key",
        ".csr",
        ".p7b",
        ".p8",
        ".pub",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
    }
)
NAMES = frozenset({"authorized_keys", "authorized_keys2", "known_hosts"})
_SSH_KEY_NAME = re.compile(r"(?:id_(?:rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)|ssh_host_\w+_key)(?:\.pub)?")

_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.DOTALL)
_SSH2 = re.compile(rb"---- BEGIN SSH2 PUBLIC KEY ----\r?\n(.*?)---- END SSH2 PUBLIC KEY ----", re.DOTALL)
# Any SSH key type token; the blob that follows must name the same type, so a token alone never counts.
_SSH_KEY_TYPE = re.compile(r"^(?:ssh|ecdsa|sk|rsa)-[A-Za-z0-9.@-]+$")
# SSH protocol 1 RSA public key: "bits exponent modulus [comment]".
_SSH1_RSA = re.compile(r"^(?:\S+\s+)?(\d{3,5})\s+(\d{1,10})\s+(\d{40,})(?:\s|$)")
# Blocks that hold no key or certificate of their own and are not coverage gaps.
_IGNORED_BLOCKS = frozenset({"X509 CRL", "EC PARAMETERS", "DSA PARAMETERS"})
_CURVE_BY_SSH = {"nistp256": "secp256r1", "nistp384": "secp384r1", "nistp521": "secp521r1"}
_JKS_MAGIC = b"\xfe\xed\xfe\xed"
_JCEKS_MAGIC = b"\xce\xce\xce\xce"
_DER = Encoding.DER


# ---------------------------------------------------------------- key description


def _describe_key(key: Any) -> tuple[str, int | None, str | None] | None:
    """(raw_name, key_size, curve) of a public or private key object; None for an unknown type."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA", key.key_size, None
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "EC", None, key.curve.name
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", key.key_size, None
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey, dh.DHParameters)):
        size = key.parameter_numbers().p.bit_length() if isinstance(key, dh.DHParameters) else key.key_size
        return "DH", size, None
    for name, types in (
        ("Ed25519", (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)),
        ("Ed448", (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)),
        ("X25519", (x25519.X25519PublicKey, x25519.X25519PrivateKey)),
        ("X448", (x448.X448PublicKey, x448.X448PrivateKey)),
    ):
        if isinstance(key, types):
            return name, None, None
    return None


def _usage(raw_name: str) -> Usage:
    if raw_name in {"Ed25519", "Ed448", "DSA"} or raw_name.startswith(("ssh-", "ecdsa-", "sk-")):
        return Usage.SIGNATURE
    if raw_name in {"X25519", "X448", "DH"}:
        return Usage.KEY_EXCHANGE
    return Usage.UNKNOWN


# ---------------------------------------------------------------- SSH wire format


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.i = data, 0

    def u32(self) -> int:
        if self.i + 4 > len(self.data):
            raise ValueError("truncated")
        (value,) = struct.unpack(">I", self.data[self.i : self.i + 4])
        self.i += 4
        return int(value)

    def string(self) -> bytes:
        size = self.u32()
        if self.i + size > len(self.data):
            raise ValueError("truncated")
        value = self.data[self.i : self.i + size]
        self.i += size
        return value


def _mpint_bits(value: bytes) -> int:
    return int.from_bytes(value, "big").bit_length()


def _ssh_blob(blob: bytes) -> tuple[str, int | None, str | None, bool]:
    """(base key type, key_size, curve, is_certificate) of an SSH public key blob."""
    reader = _Reader(blob)
    key_type = reader.string().decode("ascii")
    certificate = key_type.endswith(("-cert-v01@openssh.com", "-cert"))
    base = re.sub(r"-cert(?:-v01@openssh\.com)?$", "", key_type)
    if certificate and base.startswith("sk-") and not base.endswith("@openssh.com"):
        base += "@openssh.com"  # sk-ssh-ed25519-cert-v01@openssh.com certifies sk-ssh-ed25519@openssh.com
    if certificate:
        reader.string()  # nonce
    if base == "ssh-rsa":
        reader.string()  # e
        return base, _mpint_bits(reader.string()), None, certificate
    if base == "ssh-dss":
        return base, _mpint_bits(reader.string()), None, certificate
    match = re.fullmatch(r"(?:sk-)?ecdsa-sha2-(nistp\d+)(?:@openssh\.com)?", base)
    if match:
        return base, None, _CURVE_BY_SSH.get(match[1]), certificate
    if re.fullmatch(r"(?:sk-)?ssh-ed(?:25519|448)(?:@openssh\.com)?", base):
        return base, None, None, certificate
    # Other types (ssh-mldsa44-ed25519, future algorithms) are reported by name; the KB decides.
    return base, None, None, certificate


def _openssh_private_public(body: bytes) -> tuple[str, int | None, str | None, bool]:
    """Key type of an openssh-key-v1 private key from its clear public part, and whether it is encrypted."""
    magic = b"openssh-key-v1\x00"
    if not body.startswith(magic):
        raise ValueError("not an openssh-key-v1 key")
    reader = _Reader(body[len(magic) :])
    cipher = reader.string()
    reader.string()  # kdf name
    reader.string()  # kdf options
    if reader.u32() < 1:
        raise ValueError("no key")
    key_type, size, curve, _ = _ssh_blob(reader.string())
    return key_type, size, curve, cipher != b"none"


# ---------------------------------------------------------------- DER helpers


def _first_der(der: bytes) -> bytes:
    """The first DER element of `der` (an OpenSSL TRUSTED CERTIFICATE appends auxiliary data)."""
    if len(der) < 2 or der[0] != 0x30:
        return der
    length = der[1]
    if length < 0x80:
        return der[: 2 + length]
    count = length & 0x7F
    total = int.from_bytes(der[2 : 2 + count], "big")
    return der[: 2 + count + total]


class _Emitter:
    """Builds findings for one file; tracks whether anything was recognized."""

    def __init__(self, file: str) -> None:
        self.file = file
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.in_test = is_test_path(file)

    def add(
        self,
        raw_name: str,
        kind: KindHint,
        usage: Usage,
        *,
        line: int | None,
        snippet: str,
        extra: dict[str, Any],
        key_size: int | None = None,
        curve: str | None = None,
    ) -> None:
        location = Location(source_type=SourceType.KEYFILE, file=self.file, line=line, snippet=snippet)
        extra = {key: value for key, value in extra.items() if value is not None}
        # Keystore entries and bundle members share a file (and a line): their position is the target.
        position = [f"{key} {extra[key]}" for key in ("entry", "chain_index", "bundle_index") if key in extra]
        if position:
            location = location.model_copy(update={"target": ", ".join(position)})
        self.findings.append(
            Finding(
                id=finding_id(DETECTOR, raw_name, location),
                raw_name=raw_name,
                kind_hint=kind,
                usage=usage,
                key_size=key_size,
                curve=curve,
                detector=DETECTOR,
                confidence=1.0 if raw_name != UNRESOLVED else 0.5,
                in_test_code=self.in_test,
                location=location,
                extra=extra,
            )
        )

    def certificate(self, der: bytes, *, line: int | None, snippet: str, fmt: str, **extra: Any) -> bool:
        with warnings.catch_warnings():
            # cryptography warns on RFC 5280 violations (a non-positive serial) common in test certificates.
            warnings.simplefilter("ignore")
            info = describe_certificate(_first_der(der))
        if info is None:
            return False
        key_name = info["key_type"] if info["key_type"] != "unknown" else info["public_key_algorithm_oid"]
        self.add(
            key_name,
            KindHint.CERTIFICATE,
            Usage.AUTHENTICATION,
            line=line,
            snippet=snippet,
            key_size=info["key_size"],
            curve=info["curve"],
            extra={
                "object": "certificate",
                "format": fmt,
                "key_algorithm": key_name,
                "signature_algorithm": info["signature_algorithm"],
                "signature_algorithm_oid": info["signature_algorithm_oid"],
                "not_before": info["not_before"],
                "not_after": info["not_after"],
                "self_signed": info["self_signed"],
                **extra,
            },
        )
        return True

    def key(
        self,
        described: tuple[str, int | None, str | None] | None,
        *,
        line: int | None,
        snippet: str,
        obj: str,
        fmt: str,
        private: bool = False,
        encrypted: bool | None = None,
        **extra: Any,
    ) -> None:
        raw_name, size, curve = described or (UNRESOLVED, None, None)
        flags = {"hygiene_flags": [PRIVATE_FLAG], "encrypted": bool(encrypted)} if private else {}
        self.add(
            raw_name,
            KindHint.KEY,
            _usage(raw_name),
            line=line,
            snippet=snippet,
            key_size=size,
            curve=curve,
            extra={"object": obj, "format": fmt, **flags, **extra},
        )


# ---------------------------------------------------------------- formats


def _pem_block(out: _Emitter, label: str, body: bytes, line: int) -> None:
    snippet = f"-----BEGIN {label}-----"
    if label.startswith("PGP "):
        out.errors.append(f"line {line}: {label} is not decoded (OpenPGP keys are not supported)")
        return
    try:
        der = base64.b64decode(b"".join(row for row in body.splitlines() if b":" not in row), validate=False)
    except (binascii.Error, ValueError):
        out.errors.append(f"line {line}: {label} block is not valid base64")
        return
    proc_encrypted = b"Proc-Type: 4,ENCRYPTED" in body
    if label in {"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"}:
        if not out.certificate(der, line=line, snippet=snippet, fmt="pem"):
            out.errors.append(f"line {line}: certificate could not be decoded")
        return
    if label in {"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"}:
        try:
            csr = x509.load_der_x509_csr(der)
            oid = csr.signature_algorithm_oid
            name = getattr(oid, "_name", "") or oid.dotted_string
            out.key(
                _describe_key(csr.public_key()),
                line=line,
                snippet=snippet,
                obj="certificate_request",
                fmt="pem",
                signature_algorithm=name if name != "Unknown OID" else oid.dotted_string,
            )
        except Exception:
            # A non-conformant request (an unknown version) still states its key in plain DER.
            spki, signature = _csr_parts(der)
            try:
                out.key(
                    _describe_key(load_der_public_key(spki)),
                    line=line,
                    snippet=snippet,
                    obj="certificate_request",
                    fmt="pem",
                    signature_algorithm=signature,
                )
            except Exception:
                out.errors.append(f"line {line}: certificate request could not be decoded")
        return
    if label in {"PUBLIC KEY", "RSA PUBLIC KEY"}:
        try:
            public_key: Any = (
                load_der_public_key(der)
                if label == "PUBLIC KEY"
                else rsa.RSAPublicNumbers(*_pkcs1_public(der)).public_key()
            )
            out.key(_describe_key(public_key), line=line, snippet=snippet, obj="public_key", fmt="pem")
        except Exception:
            out.key(None, line=line, snippet=snippet, obj="public_key", fmt="pem")
        return
    if label == "OPENSSH PRIVATE KEY":
        try:
            key_type, size, curve, encrypted = _openssh_private_public(der)
        except Exception:
            out.key(None, line=line, snippet=snippet, obj="private_key", fmt="openssh", private=True)
            return
        if not encrypted:
            try:
                load_ssh_private_key(
                    b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + body + b"-----END OPENSSH PRIVATE KEY-----\n",
                    None,
                )
            except Exception:
                pass  # the clear public part is still a fact
        out.key(
            (key_type, size, curve),
            line=line,
            snippet=snippet,
            obj="private_key",
            fmt="openssh",
            private=True,
            encrypted=encrypted,
        )
        return
    if label in {
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    }:
        legacy = {"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "EC", "DSA PRIVATE KEY": "DSA"}.get(label)
        if label == "ENCRYPTED PRIVATE KEY" or proc_encrypted:
            described = (legacy, None, None) if legacy else None
            out.key(
                described,
                line=line,
                snippet=snippet,
                obj="private_key",
                fmt="pem",
                private=True,
                encrypted=True,
            )
            return
        try:
            key = load_der_private_key(der, None)
            out.key(
                _describe_key(key),
                line=line,
                snippet=snippet,
                obj="private_key",
                fmt="pem",
                private=True,
                encrypted=False,
            )
        except Exception:
            described = (legacy, None, None) if legacy else None
            out.key(
                described,
                line=line,
                snippet=snippet,
                obj="private_key",
                fmt="pem",
                private=True,
                encrypted=False,
            )
        return
    if label in {"DH PARAMETERS", "X9.42 DH PARAMETERS"}:
        try:
            params = load_der_parameters(der)
        except Exception:
            try:
                params = load_pem_parameters(
                    f"-----BEGIN {label}-----\n".encode() + body + f"-----END {label}-----\n".encode()
                )
            except Exception:
                out.errors.append(f"line {line}: DH parameters could not be decoded")
                return
        out.key(_describe_key(params), line=line, snippet=snippet, obj="dh_parameters", fmt="pem")
        return
    if label in {"PKCS7", "CMS"}:
        try:
            certs = pkcs7.load_der_pkcs7_certificates(der)
        except Exception:
            out.errors.append(f"line {line}: {label} bundle could not be decoded")
            return
        for index, cert in enumerate(certs):
            out.certificate(
                cert.public_bytes(_DER), line=line, snippet=snippet, fmt="pkcs7", bundle_index=index
            )
        return
    if label in _IGNORED_BLOCKS:
        return
    out.errors.append(f"line {line}: {label} block is not decoded")


def _tlv(data: bytes, i: int) -> tuple[int, int, int]:
    """(tag, start of content, end of content) of the DER element at i."""
    tag, i = data[i], i + 1
    length, i = data[i], i + 1
    if length & 0x80:
        count = length & 0x7F
        length, i = int.from_bytes(data[i : i + count], "big"), i + count
    return tag, i, i + length


def _csr_parts(der: bytes) -> tuple[bytes, str | None]:
    """(SubjectPublicKeyInfo DER, signature algorithm OID) of a CertificationRequest, read structurally:
    SEQUENCE { SEQUENCE { version, subject, subjectPKInfo, attributes }, signatureAlgorithm, signature }."""
    try:
        _, body, _ = _tlv(der, 0)
        _, info, info_end = _tlv(der, body)
        _, _, version_end = _tlv(der, info)
        _, _, subject_end = _tlv(der, version_end)
        _, _, spki_end = _tlv(der, subject_end)
        _, algo, _ = _tlv(der, info_end)
        _, oid_start, oid_end = _tlv(der, algo)
        dotted = _oid(der[oid_start:oid_end])
        name = getattr(x509.ObjectIdentifier(dotted), "_name", "")
        return der[subject_end:spki_end], name if name and name != "Unknown OID" else dotted
    except Exception:
        return b"", None


def _oid(value: bytes) -> str:
    first = value[0]
    parts, number = [first // 40, first % 40], 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(number)
            number = 0
    return ".".join(str(p) for p in parts)


def _pkcs1_public(der: bytes) -> tuple[int, int]:
    """(e, n) of a PKCS#1 RSAPublicKey SEQUENCE { n INTEGER, e INTEGER }."""

    def read(data: bytes, i: int) -> tuple[int, int, int]:
        tag, i = data[i], i + 1
        length, i = data[i], i + 1
        if length & 0x80:
            count = length & 0x7F
            length, i = int.from_bytes(data[i : i + count], "big"), i + count
        return tag, i, length

    _, i, _ = read(der, 0)
    _, i, length = read(der, i)
    n = int.from_bytes(der[i : i + length], "big")
    i += length
    _, i, length = read(der, i)
    e = int.from_bytes(der[i : i + length], "big")
    return e, n


def _pem(out: _Emitter, data: bytes) -> bool:
    found = False
    for match in _PEM.finditer(data):
        found = True
        line = data.count(b"\n", 0, match.start()) + 1
        _pem_block(out, match[1].decode("ascii"), match[2], line)
    for match in _SSH2.finditer(data):
        found = True
        line = data.count(b"\n", 0, match.start()) + 1
        body = b"".join(row for row in match[1].splitlines() if b":" not in row and not row.endswith(b"\\"))
        try:
            key_type, size, curve, cert = _ssh_blob(base64.b64decode(body))
            out.key((key_type, size, curve), line=line, snippet=key_type, obj="ssh_public_key", fmt="ssh2")
        except Exception:
            out.errors.append(f"line {line}: SSH2 public key could not be decoded")
    return found


def _ssh_lines(out: _Emitter, text: str) -> bool:
    found = False
    for number, line in enumerate(text.splitlines(), 1):
        tokens = line.strip().split()
        if not tokens or tokens[0].startswith("#"):
            continue
        ssh1 = _SSH1_RSA.match(line.strip())
        if ssh1:
            found = True
            out.key(
                ("RSA", int(ssh1[1]), None),
                line=number,
                snippet="SSH-1 RSA",
                obj="ssh1_public_key",
                fmt="openssh",
            )
            continue
        for index, token in enumerate(tokens[:-1]):
            if not _SSH_KEY_TYPE.match(token):
                continue
            try:
                blob = base64.b64decode(tokens[index + 1], validate=True)
                if _Reader(blob).string().decode("ascii") != token:
                    continue
                key_type, size, curve, cert = _ssh_blob(blob)
            except Exception:
                continue
            found = True
            marker = tokens[0] if tokens[0].startswith("@") else None
            out.key(
                (key_type, size, curve),
                line=number,
                snippet=key_type if not cert else f"{key_type}-cert-v01@openssh.com",
                obj="ssh_certificate" if cert else "ssh_public_key",
                fmt="openssh",
                marker=marker,
            )
            break
    return found


def _der(out: _Emitter, data: bytes) -> bool:
    snippet = "DER"
    if out.certificate(data, line=None, snippet=snippet, fmt="der"):
        return True
    for loader, obj in ((x509.load_der_x509_csr, "certificate_request"),):
        try:
            csr = loader(data)
            out.key(_describe_key(csr.public_key()), line=None, snippet=snippet, obj=obj, fmt="der")
            return True
        except Exception:
            pass
    try:
        out.key(
            _describe_key(load_der_public_key(data)), line=None, snippet=snippet, obj="public_key", fmt="der"
        )
        return True
    except Exception:
        pass
    try:
        key = load_der_private_key(data, None)
        out.key(
            _describe_key(key),
            line=None,
            snippet=snippet,
            obj="private_key",
            fmt="der",
            private=True,
            encrypted=False,
        )
        return True
    except TypeError:  # a password is required: an encrypted PKCS#8
        out.key(None, line=None, snippet=snippet, obj="private_key", fmt="der", private=True, encrypted=True)
        return True
    except Exception:
        pass
    try:
        for index, cert in enumerate(pkcs7.load_der_pkcs7_certificates(data)):
            out.certificate(
                cert.public_bytes(_DER), line=None, snippet=snippet, fmt="pkcs7", bundle_index=index
            )
        return bool(out.findings)
    except Exception:
        pass
    try:
        out.key(
            _describe_key(load_der_parameters(data)),
            line=None,
            snippet=snippet,
            obj="dh_parameters",
            fmt="der",
        )
        return True
    except Exception:
        return False


def _pkcs12(out: _Emitter, data: bytes) -> bool:
    if not data.startswith(b"\x30"):  # a PKCS#12 PFX is a DER SEQUENCE; anything else is not one
        return False
    try:
        key, cert, extra_certs = pkcs12.load_key_and_certificates(data, None)
    except Exception:
        # Password protected: the container is key material whose content is not readable.
        out.key(
            None, line=None, snippet="PKCS#12", obj="keystore", fmt="pkcs12", private=True, encrypted=True
        )
        return True
    if key is not None:
        out.key(
            _describe_key(key),
            line=None,
            snippet="PKCS#12",
            obj="private_key",
            fmt="pkcs12",
            private=True,
            encrypted=False,
            entry=0,
        )
    for index, item in enumerate([c for c in [cert, *extra_certs] if c is not None]):
        out.certificate(item.public_bytes(_DER), line=None, snippet="PKCS#12", fmt="pkcs12", entry=index + 1)
    return True


def _keystore(out: _Emitter, data: bytes) -> bool:
    """JKS / JCEKS: certificates are stored in clear; private and secret keys are sealed."""
    fmt = "jks" if data.startswith(_JKS_MAGIC) else "jceks"
    reader = _Reader(data)
    reader.i = 8
    count = reader.u32()
    for entry in range(count):
        tag = reader.u32()
        _skip_utf(reader)  # alias, never reported
        reader.i += 8  # timestamp
        if tag == 1:
            reader.string()  # sealed private key
            chain = []
            for _ in range(reader.u32()):
                _skip_utf(reader)  # certificate type, "X.509"
                chain.append(reader.string())
            leaf = describe_certificate(chain[0]) if chain else None
            described = (
                (leaf["key_type"], leaf["key_size"], leaf["curve"])
                if leaf and leaf["key_type"] != "unknown"
                else None
            )
            out.key(
                described,
                line=None,
                snippet=fmt.upper(),
                obj="private_key",
                fmt=fmt,
                private=True,
                encrypted=True,
                entry=entry,
            )
            for index, der in enumerate(chain):
                out.certificate(der, line=None, snippet=fmt.upper(), fmt=fmt, entry=entry, chain_index=index)
        elif tag == 2:
            _skip_utf(reader)
            out.certificate(reader.string(), line=None, snippet=fmt.upper(), fmt=fmt, entry=entry)
        else:  # JCEKS secret key: a serialized SealedObject, no length prefix to skip safely
            out.key(
                None,
                line=None,
                snippet=fmt.upper(),
                obj="keystore",
                fmt=fmt,
                private=True,
                encrypted=True,
                entry=entry,
            )
            break
    return True


def _skip_utf(reader: _Reader) -> None:
    size = struct.unpack(">H", reader.data[reader.i : reader.i + 2])[0]
    reader.i += 2 + size


# ---------------------------------------------------------------- scanner


@register
class KeyFileScanner:
    name = "config.keyfile"
    source_type = SourceType.KEYFILE

    def can_handle(self, path: Path) -> bool:
        name = path.name.lower()
        return path.suffix.lower() in SUFFIXES or name in NAMES or bool(_SSH_KEY_NAME.fullmatch(name))

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        path = Path(path)
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                yield ScanError(detector=DETECTOR, path=str(path), message="file larger than 5 MB, skipped")
                return
            data = path.read_bytes()
        except OSError as exc:
            yield ScanError(detector=DETECTOR, path=str(path), message=f"cannot read: {exc.strerror or exc}")
            return
        if not data.strip():
            return  # an empty file holds no key material: nothing to cover
        out = _Emitter(rel)
        suffix = path.suffix.lower()
        try:
            if suffix in {".p12", ".pfx"}:
                recognized = _pkcs12(out, data)
            elif data[:4] in (_JKS_MAGIC, _JCEKS_MAGIC):
                recognized = _keystore(out, data)
            elif b"-----BEGIN " in data or b"---- BEGIN SSH2" in data:
                recognized = _pem(out, data)
            elif data[:1] == b"\x30":
                recognized = _der(out, data)
            else:
                recognized = _ssh_lines(out, data.decode("utf-8", "replace"))
        except Exception as exc:  # a malformed container must not stop the scan
            out.errors.append(f"could not be decoded: {type(exc).__name__}")
            recognized = bool(out.findings)
        yield from out.findings
        for message in out.errors:
            yield ScanError(detector=DETECTOR, path=str(path), message=message)
        if not recognized and not out.errors:
            yield ScanError(
                detector=DETECTOR, path=str(path), message="no key, certificate or keystore recognized"
            )
