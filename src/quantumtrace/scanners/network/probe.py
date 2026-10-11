"""Live TLS probe of explicit ``host:port`` endpoints through ``openssl s_client`` (agreement M1M2-05).

Detect-only, like the capture scanners: findings carry raw facts the server selected (hex codepoints,
the leaf certificate, the CertificateVerify / ServerKeyExchange signature scheme) and never a tier.

Each endpoint gets up to two handshakes ("attempts"), each its own session:

* ``default``: the local OpenSSL default offer (OpenSSL 3.5+ offers X25519MLKEM768 first).
* ``hybrid``: TLS 1.3 offering only X25519MLKEM768. Skipped when the default attempt already selected
  a hybrid group, or when the local OpenSSL lacks the group (then a ``ScanError``). A server that
  answers with an alert is recorded on the default session as ``hybrid_attempt`` evidence: a forced
  offer that was refused says nothing about the server's default preference, so it is not an error.

Evidence is the raw handshake bytes ``s_client -msg`` prints, parsed with the capture parser, so live
findings have the capture shape (``communication/M2toAll.md`` section 6). The client offers are the
probe's own OpenSSL list, not an inventory fact, so no offered findings are emitted and the session
``offered_*`` metadata stays null. Location: ``SourceType.LIVE``, ``target`` = canonical
``host:port``, ``sni`` = the DNS name sent (IP targets send none). ``finding_id`` does not hash the
target, so the target and attempt are folded into the detector argument of the helper.

Usage: ``probe_endpoints(["example.org:443"])`` or ``python -m quantumtrace.scanners.network.probe``.
The total time is bounded by two attempts of ``timeout`` seconds per endpoint. Without ``--probe``
nothing here runs and no process or socket is opened.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id
from quantumtrace.scanners.network import certs, registry
from quantumtrace.scanners.network.purepy import TlsHello, _parse_hello
from quantumtrace.scanners.network.tls_session import _PORT_SERVICES, session_id

SCANNER = "live"
DETECTOR_VERSION = "live.tls.version"
DETECTOR_SUITE = "live.tls.cipher_suite"
DETECTOR_GROUP = "live.tls.group"
DETECTOR_SIGNATURE = "live.tls.signature_scheme"
DETECTOR_CERTIFICATE = "live.tls.certificate"

HYBRID_GROUP = "X25519MLKEM768"
# IANA TLS Supported Groups: SecP256r1MLKEM768 0x11EB, X25519MLKEM768 0x11EC, SecP384r1MLKEM1024 0x11ED
# (draft-ietf-tls-ecdhe-mlkem). The skip rule only needs to know a hybrid was already selected.
_HYBRID_CODES = frozenset({0x11EB, 0x11EC, 0x11ED})
_OUTPUT_LIMIT = 4 * 1024 * 1024
_HOST = re.compile(r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?")
_RECORD = re.compile(
    r"^(?P<dir>>>>|<<<) (?P<version>\S+ \S+), (?P<type>\w+) \[length (?P<length>[0-9a-fA-F]+)\]"
    r"(?:, (?P<name>.+))?$"
)
_HEX_LINE = re.compile(r"^\s+((?:[0-9a-fA-F]{2} ?)+)\s*$")
_ALERT = re.compile(r"^<<< \S+ \S+, Alert \[length [0-9a-fA-F]+\], (?:fatal|warning) (?P<name>\w+)$")
_VERIFY = re.compile(r"^\s*Verify return code: (?P<code>\d+) \((?P<text>[^)]*)\)$", re.MULTILINE)
_FAILURES = (
    ("Connection refused", "connection refused"),
    ("No route to host", "no route to host"),
    ("Network is unreachable", "network unreachable"),
    ("Name or service not known", "DNS lookup failed"),
    ("nodename nor servname", "DNS lookup failed"),
    ("Temporary failure in name resolution", "DNS lookup failed"),
    ("no address associated", "DNS lookup failed"),
    ("BIO_lookup", "DNS lookup failed"),
    ("Connection timed out", "connection timed out"),
    ("Connection reset", "connection reset by peer"),
    ("wrong version number", "endpoint did not answer with TLS"),
    ("packet length too long", "endpoint did not answer with TLS"),
    ("unexpected eof", "connection closed during the handshake"),
)


@dataclass(frozen=True)
class Target:
    host: str  # IPv6 without brackets
    port: int
    is_ip: bool

    @property
    def text(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"

    @property
    def sni(self) -> str | None:
        return None if self.is_ip else self.host


def parse_target(text: str) -> Target:
    """``host:port`` (DNS name, IPv4, bracketed IPv6; port 1-65535). URLs and ranges are rejected."""
    value = text.strip()
    if "://" in value or "/" in value:
        raise ValueError("expected host:port, not a URL or address range")
    if value.startswith("["):
        host, sep, port = value[1:].partition("]:")
        if not sep:
            raise ValueError("bracketed IPv6 needs a port: [addr]:port")
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError("invalid IPv6 address") from None
        return Target(address.compressed, _port(port), True)
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise ValueError("expected host:port")
    if ":" in host:
        raise ValueError("IPv6 addresses must be bracketed: [addr]:port")
    try:
        return Target(str(ipaddress.IPv4Address(host)), _port(port), True)
    except ipaddress.AddressValueError:
        pass
    if not _HOST.fullmatch(host) or host.replace(".", "").isdigit():
        raise ValueError("invalid host name")
    return Target(host.rstrip(".").lower(), _port(port), False)


def _port(text: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValueError("port must be 1-65535")
    return int(text)


# --- s_client transcript ----------------------------------------------------------------------


@dataclass
class Transcript:
    """Handshake messages ``s_client -msg`` printed, as (direction, name, bytes incl. 4-byte header)."""

    messages: list[tuple[str, str, bytes]] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)  # alerts received from the server
    verify_code: int | None = None
    verify_text: str | None = None

    def first(self, direction: str, name: str) -> bytes | None:
        return next((body for d, n, body in self.messages if d == direction and n == name), None)

    def last(self, direction: str, name: str) -> bytes | None:
        """After a HelloRetryRequest the final ServerHello is the second one."""
        return next((body for d, n, body in reversed(self.messages) if d == direction and n == name), None)


def parse_transcript(text: str) -> Transcript:
    """Parse ``s_client -msg`` output. Unknown lines are ignored; a truncated dump keeps its bytes."""
    out = Transcript()
    current: tuple[str, str, bytearray] | None = None

    def close() -> None:
        nonlocal current
        if current is not None and current[2]:
            out.messages.append((current[0], current[1], bytes(current[2])))
        current = None

    for line in text.splitlines():
        record = _RECORD.match(line)
        if record:
            close()
            alert = _ALERT.match(line)
            if alert:
                out.alerts.append(alert["name"])
            elif record["type"] == "Handshake" and record["name"]:
                current = ("client" if record["dir"] == ">>>" else "server", record["name"], bytearray())
            continue
        hex_line = _HEX_LINE.match(line)
        if hex_line and current is not None:
            current[2].extend(bytes.fromhex(hex_line[1].replace(" ", "")))
            continue
        close()
    close()
    verify = _VERIFY.search(text)
    if verify:
        out.verify_code, out.verify_text = int(verify["code"]), verify["text"]
    return out


def _body(message: bytes | None) -> bytes | None:
    """Handshake body without its 4-byte header; None when missing or shorter than it claims."""
    if message is None or len(message) < 4:
        return None
    size = int.from_bytes(message[1:4], "big")
    return message[4 : 4 + size] if len(message) >= 4 + size else None


def _tls13_leaf(body: bytes) -> bytes | None:
    """Leaf DER of a TLS 1.3 Certificate body: context<0..255>, list<3> of {cert<3>, extensions<2>}."""
    try:
        i = 1 + body[0]
        end = min(len(body), i + 3 + int.from_bytes(body[i : i + 3], "big"))
        i += 3
        size = int.from_bytes(body[i : i + 3], "big")
        return body[i + 3 : i + 3 + size] if size and i + 3 + size <= end else None
    except IndexError:
        return None


def _ske_group_and_scheme(body: bytes) -> tuple[int | None, int | None]:
    """(named group, signature scheme) of a TLS 1.2 ServerKeyExchange; None where not present."""
    try:
        if body[0] == 3:  # ECParameters named_curve, then ECPoint<1..255>
            group = int.from_bytes(body[1:3], "big")
            i = 4 + body[3]
        else:  # DHE: dh_p<2>, dh_g<2>, dh_Ys<2>; no named group
            group, i = None, 0
            for _ in range(3):
                i += 2 + int.from_bytes(body[i : i + 2], "big")
        scheme = int.from_bytes(body[i : i + 2], "big") if i + 4 <= len(body) else None
        return group, scheme
    except IndexError:
        return None, None


# --- findings -----------------------------------------------------------------------------------


@dataclass
class Attempt:
    name: str  # "default" | "hybrid"
    transcript: Transcript
    server_hello: TlsHello | None


def _hex(code: int | None) -> str | None:
    return None if code is None else registry.format_code(code)


_NAMESPACE = {
    KindHint.CIPHER_SUITE: "cipher_suites",
    KindHint.GROUP: "groups",
    KindHint.SIGNATURE_SCHEME: "signature_schemes",
}


def attempt_findings(
    target: Target, attempt: Attempt, extra_session: dict[str, Any] | None = None
) -> list[Finding | ScanError]:
    """Findings for one completed handshake attempt; errors where evidence is missing."""
    out: list[Finding | ScanError] = []
    sh = attempt.server_hello
    where = f"{attempt.name} attempt"
    if sh is None:
        return [ScanError(detector=SCANNER, path=target.text, message=f"{where}: no ServerHello observed")]
    if sh.hello_retry_request:
        return [
            ScanError(
                detector=SCANNER,
                path=target.text,
                message=f"{where}: HelloRetryRequest without a final ServerHello; nothing negotiated",
            )
        ]
    transcript = attempt.transcript
    sid = session_id("live", target.text, attempt.name, None)
    version_code = sh.real_version
    protocol = registry.version_label(version_code) or registry.format_code(version_code)
    location = Location(source_type=SourceType.LIVE, target=target.text, sni=target.sni)
    tls13 = version_code == 0x0304

    group = sh.selected_group
    scheme: int | None = None
    if tls13:
        verify = _body(transcript.first("server", "CertificateVerify"))
        scheme = int.from_bytes(verify[:2], "big") if verify and len(verify) >= 2 else None
    else:
        ske = _body(transcript.first("server", "ServerKeyExchange"))
        if ske is not None:
            group, scheme = _ske_group_and_scheme(ske)

    certificate = None
    cert_message = transcript.first("server", "Certificate")
    compressed = transcript.first("server", "CompressedCertificate") is not None
    cert_body = _body(cert_message)
    certificate_state = "observed" if cert_message is not None or compressed else "absent"
    if compressed and cert_message is None:
        out.append(
            ScanError(
                detector=SCANNER,
                path=target.text,
                message=f"{where}: Certificate was compressed (RFC 8879) and is not decoded; "
                "authentication is not observed",
            )
        )
    elif cert_message is not None:
        if cert_body is None:
            certificate = None
        elif tls13:
            leaf = _tls13_leaf(cert_body)
            certificate = certs.describe_certificate(leaf) if leaf else None
        else:
            certificate = certs.describe_certificate_message(cert_body)
        if certificate is None:
            out.append(
                ScanError(
                    detector=SCANNER,
                    path=target.text,
                    message=f"{where}: Certificate message could not be decoded; authentication is not observed",
                )
            )
    key_name: str | None = None
    if certificate is not None:
        key_type = certificate["key_type"]
        key_name = certificate["public_key_algorithm_oid"] if key_type == certs.UNKNOWN else key_type

    def emit(detector: str, raw_name: str, kind: KindHint, usage: Usage, extra: dict[str, Any], **more: Any):
        out.append(
            Finding(
                id=finding_id(f"{detector}|{target.text}|{attempt.name}", raw_name, location),
                raw_name=raw_name,
                kind_hint=kind,
                usage=usage,
                protocol=protocol,
                negotiated=True,  # selected by the server in this handshake
                detector=detector,
                confidence=1.0,
                location=location,
                session_id=sid,
                extra={"probe_attempt": attempt.name, **extra},
                **more,
            )
        )

    def codepoint(kind: KindHint, code: int) -> dict[str, Any]:
        return {
            "codepoint": registry.format_code(code),
            "iana_name": registry.iana_name(_NAMESPACE[kind], code),
        }

    session = {
        "flow": None,
        "sni": target.sni,
        "version": protocol,
        "offered_groups": None,  # the probe's own offer is not an inventory fact
        "negotiated_group": _hex(group),
        "offered_cipher_suites": None,
        "negotiated_cipher_suite": _hex(sh.selected_suite),
        "offered_sig_schemes": None,
        "cert_key": key_name,
        "cert_sig_alg": certificate["signature_algorithm"] if certificate is not None else None,
        "transport": "tls",
        "service": _PORT_SERVICES.get(target.port, "other"),
        "peer_banners": None,
    }
    version_extra: dict[str, Any] = {
        "codepoint": _hex(version_code),
        "iana_name": None,
        "session": session,
        "authentication_observable": certificate is not None,
        "certificate_state": certificate_state,
        # Trust is recorded apart from the crypto inventory; a sent chain is not a verified chain.
        "verify_code": transcript.verify_code,
        "verify_result": transcript.verify_text,
    }
    version_extra.update(extra_session or {})
    emit(DETECTOR_VERSION, protocol, KindHint.PROTOCOL_VERSION, Usage.UNKNOWN, version_extra)
    if sh.selected_suite is not None:
        suite = sh.selected_suite
        emit(
            DETECTOR_SUITE,
            registry.format_code(suite),
            KindHint.CIPHER_SUITE,
            Usage.UNKNOWN,
            codepoint(KindHint.CIPHER_SUITE, suite),
        )
    if group is not None:
        emit(
            DETECTOR_GROUP,
            registry.format_code(group),
            KindHint.GROUP,
            Usage.KEY_EXCHANGE,
            codepoint(KindHint.GROUP, group),
        )
    if scheme is not None and certificate is not None:
        emit(
            DETECTOR_SIGNATURE,
            registry.format_code(scheme),
            KindHint.SIGNATURE_SCHEME,
            Usage.SIGNATURE,
            {
                **codepoint(KindHint.SIGNATURE_SCHEME, scheme),
                "message": "CertificateVerify" if tls13 else "ServerKeyExchange",
            },
        )
    if certificate is not None and key_name is not None:
        emit(
            DETECTOR_CERTIFICATE,
            key_name,
            KindHint.CERTIFICATE,
            Usage.AUTHENTICATION,
            {
                "key_algorithm": key_name,
                "signature_algorithm": certificate["signature_algorithm"],
                "signature_algorithm_oid": certificate["signature_algorithm_oid"],
                "not_before": certificate["not_before"],
                "not_after": certificate["not_after"],
                "self_signed": certificate["self_signed"],
            },
            key_size=certificate["key_size"],
            curve=certificate["curve"],
        )
    return out


def parse_attempt(name: str, text: str) -> Attempt:
    transcript = parse_transcript(text)
    hello = _body(transcript.last("server", "ServerHello"))
    return Attempt(name, transcript, _parse_hello(2, 0x0303, hello) if hello is not None else None)


# --- running OpenSSL -----------------------------------------------------------------------------


def _failure(text: str) -> str:
    for needle, label in _FAILURES:
        if needle.lower() in text.lower():
            return label
    lines = [line.strip() for line in text.splitlines() if "error" in line.lower()]
    return lines[-1][:200] if lines else "handshake did not complete"


def _s_client(
    openssl: str, target: Target, extra: list[str], timeout: float
) -> tuple[str | None, str | None]:
    """(transcript, None) or (None, failure). Argument array, no shell; stdin is closed at once."""
    args = [openssl, "s_client", "-connect", target.text, "-msg"]
    args += ["-servername", target.host] if target.sni else ["-noservername"]
    try:
        done = subprocess.run(
            args + extra,
            input=b"",
            capture_output=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout:g} s"
    except OSError as exc:
        return None, f"could not run openssl: {exc.strerror or exc}"
    text = (done.stdout[:_OUTPUT_LIMIT] + b"\n" + done.stderr[:_OUTPUT_LIMIT]).decode("utf-8", "replace")
    return text, None


def _base_flags(openssl: str, timeout: float) -> list[str]:
    """Ask for an uncompressed Certificate (RFC 8879 is OpenSSL 3.2+) so the leaf can be decoded."""
    try:
        done = subprocess.run(
            [openssl, "s_client", "-help"], capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return ["-no_rx_cert_comp"] if b"-no_rx_cert_comp" in done.stdout + done.stderr else []


def _supports_hybrid(openssl: str, timeout: float) -> bool:
    try:
        done = subprocess.run(
            [openssl, "list", "-kem-algorithms"], capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return HYBRID_GROUP.encode() in done.stdout


def probe_endpoints(endpoints: list[str], timeout: float = 10.0) -> Iterator[Finding | ScanError]:
    """Probe each distinct endpoint (canonical, sorted); a failing endpoint never stops the others."""
    targets: dict[str, Target] = {}
    for raw in endpoints:
        try:
            target = parse_target(raw)
        except ValueError as exc:
            yield ScanError(detector=SCANNER, path=raw, message=f"invalid probe target: {exc}")
            continue
        targets[target.text] = target
    if not targets:
        return
    openssl = shutil.which("openssl")
    if openssl is None:
        for name in sorted(targets):
            yield ScanError(
                detector=SCANNER, path=name, message="openssl executable not found; probe skipped"
            )
        return
    hybrid_capable: bool | None = None
    flags = _base_flags(openssl, timeout)
    for name in sorted(targets):
        target = targets[name]
        text, failure = _s_client(openssl, target, flags, timeout)
        default = parse_attempt("default", text) if text is not None else None
        if default is None or default.server_hello is None:
            reason = failure or _failure(text or "")
            if default is not None and default.transcript.alerts:
                reason = f"server alert {default.transcript.alerts[0]}"
            yield ScanError(detector=SCANNER, path=name, message=f"default attempt: {reason}")
            continue
        selected = default.server_hello.selected_group
        note: dict[str, Any]
        hybrid: Attempt | None = None
        if selected in _HYBRID_CODES:
            note = {"result": "skipped", "detail": "default attempt already selected a hybrid group"}
        else:
            if hybrid_capable is None:
                hybrid_capable = _supports_hybrid(openssl, timeout)
            if not hybrid_capable:
                note = {"result": "unavailable", "detail": f"local OpenSSL lacks {HYBRID_GROUP}"}
                yield ScanError(
                    detector=SCANNER,
                    path=name,
                    message=f"hybrid attempt: local OpenSSL lacks {HYBRID_GROUP}; hybrid support not tested",
                )
            else:
                text, failure = _s_client(
                    openssl, target, [*flags, "-tls1_3", "-groups", HYBRID_GROUP], timeout
                )
                attempt = parse_attempt("hybrid", text) if text is not None else None
                if attempt is not None and attempt.server_hello is not None:
                    hybrid = attempt
                    note = {
                        "result": "selected",
                        "detail": f"server completed a handshake with {HYBRID_GROUP}",
                    }
                elif attempt is not None and attempt.transcript.alerts:
                    note = {
                        "result": "refused",
                        "detail": f"server answered an {HYBRID_GROUP}-only offer with alert "
                        f"{attempt.transcript.alerts[0]}",
                    }
                else:
                    note = {"result": "inconclusive", "detail": failure or _failure(text or "")}
        yield from attempt_findings(target, default, {"hybrid_attempt": note})
        if hybrid is not None:
            yield from attempt_findings(target, hybrid)


def main(argv: list[str] | None = None) -> int:
    """Fallback CLI (M1M2-05): print findings and errors as JSON lines."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print(
            "usage: python -m quantumtrace.scanners.network.probe host:port [host:port ...]", file=sys.stderr
        )
        return 2
    failed = False
    for item in probe_endpoints(args):
        failed |= isinstance(item, ScanError)
        print(json.dumps({type(item).__name__: item.model_dump(mode="json")}, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
