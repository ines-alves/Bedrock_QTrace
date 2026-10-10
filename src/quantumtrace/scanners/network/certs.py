"""X.509 certificate description for the TLS <= 1.2 Certificate message (task 2.9, M2D-07).

Detect-only: the output is raw facts about one certificate, never a tier, threat, score or verdict,
and never private key material (a certificate holds none). Nothing here raises.

``describe_certificate(der)`` returns a dict (or ``None`` for bytes that do not decode):

==========================  ==================================================================
``key_type``                ``RSA``, ``EC``, ``Ed25519``, ``Ed448``, ``DSA`` or ``unknown`` (M2M3-02)
``key_size``                bits for ``RSA`` and ``DSA``, otherwise ``None``
``curve``                   library curve name for ``EC`` (``secp256r1``), otherwise ``None``
``public_key_algorithm_oid``  dotted OID of the SubjectPublicKeyInfo algorithm, always present
``signature_algorithm``     library name when known (``ecdsa-with-SHA256``), else the dotted OID
``signature_algorithm_oid`` dotted OID, always present
``not_before``/``not_after``  ISO 8601 with timezone
``self_signed``             subject equals issuer
==========================  ==================================================================

``key_type`` is ``unknown`` only for a key the library cannot decode and whose algorithm OID is not
one of the five known types, for example a post-quantum key. Its OID is then in
``public_key_algorithm_oid`` and is what the session finding carries as the certificate key.
"""

from __future__ import annotations

from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

UNKNOWN = "unknown"

# SubjectPublicKeyInfo algorithm OIDs. Used only when the library cannot decode the key itself, so
# the type stays a fact from the certificate instead of a guess.
_KEY_TYPE_BY_OID = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10040.4.1": "DSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}


def _signature_name(cert: x509.Certificate) -> tuple[str, str]:
    oid = cert.signature_algorithm_oid
    dotted = oid.dotted_string
    name = getattr(oid, "_name", "")
    return (name if name and name != "Unknown OID" else dotted), dotted


def _key(cert: x509.Certificate) -> tuple[str, int | None, str | None, str]:
    """-> (key_type, key_size, curve, public key algorithm OID)."""
    oid = cert.public_key_algorithm_oid.dotted_string
    try:
        public = cert.public_key()
    except Exception:  # unsupported algorithm or a malformed key: fall back to the OID
        return _KEY_TYPE_BY_OID.get(oid, UNKNOWN), None, None, oid
    if isinstance(public, rsa.RSAPublicKey):
        return "RSA", public.key_size, None, oid
    if isinstance(public, ec.EllipticCurvePublicKey):
        return "EC", None, public.curve.name, oid
    if isinstance(public, ed25519.Ed25519PublicKey):
        return "Ed25519", None, None, oid
    if isinstance(public, ed448.Ed448PublicKey):
        return "Ed448", None, None, oid
    if isinstance(public, dsa.DSAPublicKey):
        return "DSA", public.key_size, None, oid
    return _KEY_TYPE_BY_OID.get(oid, UNKNOWN), None, None, oid


def describe_certificate(der: bytes) -> dict[str, Any] | None:
    """Describe one DER certificate. ``None`` when the bytes do not decode. Never raises."""
    try:
        cert = x509.load_der_x509_certificate(bytes(der))
        key_type, key_size, curve, key_oid = _key(cert)
        signature, signature_oid = _signature_name(cert)
        return {
            "key_type": key_type,
            "key_size": key_size,
            "curve": curve,
            "public_key_algorithm_oid": key_oid,
            "signature_algorithm": signature,
            "signature_algorithm_oid": signature_oid,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "self_signed": cert.subject == cert.issuer,
        }
    except Exception:
        return None


def split_certificate_message(body: bytes) -> list[bytes]:
    """DER certificates of a TLS <= 1.2 Certificate message body, in message order.

    The body is a 3-byte total length, then a 3-byte length and the DER for each certificate; the
    shape ``purepy`` keeps and ``tshark.parse_rows`` rebuilds. A truncated message returns the
    complete entries it holds. Never raises.
    """
    try:
        data = bytes(body)
    except Exception:
        return []
    if len(data) < 3:
        return []
    end = min(len(data), 3 + int.from_bytes(data[:3], "big"))
    out: list[bytes] = []
    i = 3
    while i + 3 <= end:
        size = int.from_bytes(data[i : i + 3], "big")
        i += 3
        if size == 0 or i + size > end:
            break
        out.append(data[i : i + size])
        i += size
    return out


def describe_certificate_message(body: bytes) -> dict[str, Any] | None:
    """Describe the leaf (first) certificate of a Certificate message body, ``None`` when there is
    none or it does not decode. The leaf is the one that authenticates the server."""
    entries = split_certificate_message(body)
    return describe_certificate(entries[0]) if entries else None
