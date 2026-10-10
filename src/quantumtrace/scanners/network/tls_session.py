"""TLS ``Flow`` records to ``Finding`` objects, independent of which parser produced them.

Detect-only: findings carry raw facts (hex codepoints, offered vs selected, evidence frames) and
never a tier, threat, score, ``pq_status`` or verdict. The engine (M1) builds every ``TLSSession``
from the findings that share a ``session_id``; this module never instantiates one.

Shape of the output: ``communication/M2toAll.md`` section 6.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id
from quantumtrace.scanners.network import registry
from quantumtrace.scanners.network.purepy import Flow, PureResult, TlsHello

SCANNER = "pcap"
DETECTOR_VERSION = "pcap.tls.version"
DETECTOR_SUITE = "pcap.tls.cipher_suite"
DETECTOR_GROUP = "pcap.tls.group"
DETECTOR_SIGNATURE = "pcap.tls.signature_scheme"

# STARTTLS / SSLRequest evidence wins over the port; the vocabulary is the one agreed in M2M4-02.
_UPGRADE_SERVICES = {"smtp-starttls": "smtp-starttls", "postgres-sslrequest": "postgres"}
_PORT_SERVICES = {
    443: "https",
    636: "ldaps",
    993: "imaps",
    25: "smtp-starttls",
    587: "smtp-starttls",
    5432: "postgres",
}
_NAMESPACE = {
    KindHint.CIPHER_SUITE: "cipher_suites",
    KindHint.GROUP: "groups",
    KindHint.SIGNATURE_SCHEME: "signature_schemes",
}
SESSION_KEYS = (
    "flow",
    "sni",
    "version",
    "offered_groups",
    "negotiated_group",
    "offered_cipher_suites",
    "negotiated_cipher_suite",
    "offered_sig_schemes",
    "cert_key",
    "cert_sig_alg",
    "transport",
    "service",
    "peer_banners",
)


def session_id(kind: str, file: str, flow: str, frame: int | None) -> str:
    """First 12 hex of SHA1 of ``<kind>|<file>|<flow>|<frame>``; kind is ``pcap`` (TLS) or ``ssh``."""
    text = f"{kind}|{file}|{flow}|{'' if frame is None else frame}"
    return hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def service_label(flow: Flow) -> str:
    """``https``, ``ldaps``, ``imaps``, ``smtp-starttls``, ``postgres``, ``ssh`` or ``other``."""
    if flow.upgrade_request in _UPGRADE_SERVICES:
        return _UPGRADE_SERVICES[flow.upgrade_request]
    return _PORT_SERVICES.get(flow.server[1], "other")


def relative_posix(path: str | Path, root: str | Path | None = None) -> str:
    """``Location.file``: path relative to the scan root, posix separators. A single capture passed
    without a root uses its parent as root, so it is reported as ``network.pcap``."""
    target = Path(path)
    base = Path(root) if root is not None else target.parent
    try:
        relative = target.resolve().relative_to(base.resolve())
    except ValueError:
        return target.name
    return relative.as_posix() if relative.parts else target.name


def _hex(code: int | None) -> str | None:
    return None if code is None else registry.format_code(code)


def _hexes(codes: list[int] | None) -> list[str] | None:
    return None if codes is None else [registry.format_code(c) for c in codes]


def _unique(codes: list[int]) -> list[int]:
    return list(dict.fromkeys(codes))  # first occurrence, client order


def _version_label(code: int | None) -> str | None:
    if code is None:
        return None
    return registry.version_label(code) or registry.format_code(code)


def _finding(
    *,
    detector: str,
    raw_name: str,
    kind: KindHint,
    usage: Usage,
    negotiated: bool,
    location: Location,
    sid: str,
    protocol: str | None,
    extra: dict[str, Any],
) -> Finding:
    return Finding(
        id=finding_id(detector, raw_name, location),
        raw_name=raw_name,
        kind_hint=kind,
        usage=usage,
        protocol=protocol,
        negotiated=negotiated,
        detector=detector,
        confidence=1.0,  # directly observed on the wire
        location=location,
        session_id=sid,
        extra=extra,
    )


def _codepoint_extra(kind: KindHint, code: int) -> dict[str, Any]:
    return {"codepoint": registry.format_code(code), "iana_name": registry.iana_name(_NAMESPACE[kind], code)}


def _flow_findings(flow: Flow, file: str) -> list[Finding | ScanError]:
    out: list[Finding | ScanError] = []
    ch: TlsHello | None = flow.client_hello
    sh: TlsHello | None = flow.server_hello
    where = f"stream {flow.stream_id} {flow.flow}"
    if ch is None and sh is None:
        return out
    # A HelloRetryRequest is a request, not a selection: nothing is negotiated from it alone.
    selected = sh if sh is not None and not sh.hello_retry_request else None

    if ch is None:
        out.append(
            ScanError(
                detector=SCANNER,
                path=file,
                message=f"{where}: ServerHello without a ClientHello; offers are not observed",
            )
        )
    if sh is None:
        out.append(
            ScanError(
                detector=SCANNER,
                path=file,
                message=f"{where}: ClientHello without a ServerHello; no session was established, "
                "only the offers are recorded",
            )
        )
    elif selected is None:
        out.append(
            ScanError(
                detector=SCANNER,
                path=file,
                message=f"{where}: HelloRetryRequest without a final ServerHello; nothing negotiated",
            )
        )

    anchor_frame = ch.frame if ch is not None else (sh.frame if sh is not None else None)
    sid = session_id("pcap", file, flow.flow, anchor_frame)
    version_code = sh.real_version if sh is not None else None
    protocol = _version_label(version_code)
    sni = ch.sni if ch is not None else None

    def at(frame: int | None) -> Location:
        return Location(source_type=SourceType.PCAP, file=file, flow=flow.flow, sni=sni, frame=frame)

    negotiated_suite = selected.selected_suite if selected is not None else None
    negotiated_group: int | None = None
    group_frame: int | None = None
    if selected is not None:
        if selected.selected_group is not None:  # TLS 1.3 key_share
            negotiated_group, group_frame = selected.selected_group, selected.frame
        elif flow.server_key_exchange_group is not None:  # TLS <= 1.2 ECDHE ServerKeyExchange
            negotiated_group = flow.server_key_exchange_group
            group_frame = flow.server_key_exchange_frame or selected.frame

    certificate_state = flow.certificate_state
    if sh is not None:
        session = {
            "flow": flow.flow,
            "sni": sni,
            "version": protocol,
            "offered_groups": _hexes(ch.supported_groups) if ch is not None else None,
            "negotiated_group": _hex(negotiated_group),
            "offered_cipher_suites": _hexes(ch.cipher_suites) if ch is not None else None,
            "negotiated_cipher_suite": _hex(negotiated_suite),
            "offered_sig_schemes": _hexes(ch.signature_algorithms) if ch is not None else None,
            "cert_key": None,  # never guessed; filled only from a parsed certificate (certs.py)
            "cert_sig_alg": None,
            "transport": "tls",
            "service": service_label(flow),
            "peer_banners": None,
        }
        out.append(
            _finding(
                detector=DETECTOR_VERSION,
                raw_name=protocol or "TLS",
                kind=KindHint.PROTOCOL_VERSION,
                usage=Usage.UNKNOWN,
                negotiated=selected is not None,  # a HelloRetryRequest alone selects nothing
                location=at(anchor_frame),
                sid=sid,
                protocol=protocol,
                extra={
                    "codepoint": _hex(version_code),
                    "iana_name": None,
                    "session": session,
                    "authentication_observable": certificate_state == "observed",
                    "certificate_state": certificate_state,
                },
            )
        )

    offered_frame = ch.frame if ch is not None else None
    selected_frame = selected.frame if selected is not None else None

    def emit(detector: str, kind: KindHint, usage: Usage, codes: list[int], frame: int | None, neg: bool):
        for code in _unique(codes):
            out.append(
                _finding(
                    detector=detector,
                    raw_name=registry.format_code(code),
                    kind=kind,
                    usage=usage,
                    negotiated=neg,
                    location=at(frame),
                    sid=sid,
                    protocol=protocol,
                    extra=_codepoint_extra(kind, code),
                )
            )

    if ch is not None:
        emit(DETECTOR_SUITE, KindHint.CIPHER_SUITE, Usage.UNKNOWN, ch.cipher_suites, offered_frame, False)
    if negotiated_suite is not None:
        emit(DETECTOR_SUITE, KindHint.CIPHER_SUITE, Usage.UNKNOWN, [negotiated_suite], selected_frame, True)
    if ch is not None:
        emit(DETECTOR_GROUP, KindHint.GROUP, Usage.KEY_EXCHANGE, ch.supported_groups, offered_frame, False)
    if negotiated_group is not None:
        emit(DETECTOR_GROUP, KindHint.GROUP, Usage.KEY_EXCHANGE, [negotiated_group], group_frame, True)
    if ch is not None:
        emit(
            DETECTOR_SIGNATURE,
            KindHint.SIGNATURE_SCHEME,
            Usage.SIGNATURE,
            ch.signature_algorithms,
            offered_frame,
            False,
        )

    for warning in flow.warnings:
        out.append(ScanError(detector=SCANNER, path=file, message=f"{where}: {warning}"))
    return out


def build_findings(result: PureResult, file: str) -> list[Finding | ScanError]:
    """Findings and errors for every TLS flow of a parse result, in stream order.

    ``file`` is the root-relative posix path (see ``relative_posix``). Parser errors become
    ``ScanError`` entries first, so an unreadable capture is never an empty success.
    """
    out: list[Finding | ScanError] = [
        ScanError(detector=SCANNER, path=file, message=e) for e in result.errors
    ]
    for flow in sorted(result.flows, key=lambda f: f.stream_id):
        if flow.kind == "tls":
            out.extend(_flow_findings(flow, file))
    return out
