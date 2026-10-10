"""SSH ``Flow`` records to ``Finding`` objects, independent of which parser produced them.

Detect-only, same shape as ``tls_session.py``: raw facts (wire names verbatim, offered vs negotiated,
evidence frames) and never a tier, threat, score, ``pq_status`` or verdict. The engine (M1) builds the
session view from the findings that share a ``session_id``; this module never instantiates one.

Negotiation follows RFC 4253 section 7.1: for each category the first algorithm in the client's list
that the server also lists. Client offers alone are never negotiated. Ciphers and MACs are decided per
direction; with an AEAD cipher in a direction no MAC is negotiated there (M1M2-06). Anchors: offered
findings and the session id use the client KEXINIT frame, negotiated findings the frame completing
the second KEXINIT (M1M2-08). ``extra["direction"]`` marks a cipher or MAC finding that applies to
one direction only (M1M2-09).

Shape of the output: ``communication/M2toAll.md`` section 6, SSH mapping in ``M2M4-02`` item 4.
"""

from __future__ import annotations

from typing import Any

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id
from quantumtrace.scanners.network.purepy import Flow, PureResult, SshSide
from quantumtrace.scanners.network.tls_session import SCANNER, session_id

DETECTOR_VERSION = "pcap.ssh.version"
DETECTOR_KEX = "pcap.ssh.kex"
DETECTOR_HOST_KEY = "pcap.ssh.host_key"
DETECTOR_CIPHER = "pcap.ssh.cipher"
DETECTOR_MAC = "pcap.ssh.mac"

VERSION_LABEL = "SSH-2.0"  # a KEXINIT (message 20) only exists in SSH-2; 1.99 banners speak 2.0

# Pseudo-algorithms in the kex list that signal a capability instead of naming a key exchange
# (RFC 8308 ext-info, OpenSSH strict kex). Never offered or selected as an algorithm.
# verify: names against RFC 8308 and OpenSSH PROTOCOL; the starter kit has none.
SIGNALLING_KEX = frozenset(
    {"ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"}
)

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


def _unique(names: list[str]) -> list[str]:
    return list(dict.fromkeys(names))  # first occurrence, client order


def first_match(client: list[str], server: list[str]) -> str | None:
    """RFC 4253 7.1: the first client algorithm that the server also lists."""
    supported = set(server)
    return next((name for name in client if name in supported), None)


def _kex(names: list[str]) -> list[str]:
    return [n for n in names if n not in SIGNALLING_KEX]


def _protocol_version(banner: str) -> str | None:
    """``2.0`` from ``SSH-2.0-OpenSSH_9.6``; None when the text is not an SSH banner."""
    if not banner.startswith("SSH-"):
        return None
    return banner[4:].split("-", 1)[0]


def _finding(
    *,
    detector: str,
    raw_name: str,
    usage: Usage,
    kind: KindHint,
    negotiated: bool,
    location: Location,
    sid: str,
    extra: dict[str, Any],
) -> Finding:
    return Finding(
        id=finding_id(detector, raw_name, location),
        raw_name=raw_name,
        kind_hint=kind,
        usage=usage,
        protocol=VERSION_LABEL,
        negotiated=negotiated,
        detector=detector,
        location=location,
        session_id=sid,
        extra=extra,
    )


_C2S, _S2C = "client_to_server", "server_to_client"

# Ciphers that authenticate by themselves: no separate MAC is negotiated or used (M1M2-06).
# verify: OpenSSH names against PROTOCOL.chacha20poly1305 / the OpenSSH sources, RFC 5647 for the
# AEAD_* names. The starter kit never selects one.
AEAD_CIPHERS = frozenset(
    {
        "chacha20-poly1305@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "AEAD_AES_128_GCM",
        "AEAD_AES_256_GCM",
    }
)


def _by_direction(c2s: list[str], s2c: list[str]) -> list[tuple[str, str | None]]:
    """Names in first-seen order, each with the one direction it applies to, or None when it applies
    to both. ``extra["direction"]`` exists only for the one-direction case (M1M2-09); a name that
    holds both ways is one finding, because ``finding_id`` has no direction to tell two apart."""
    both = set(c2s) & set(s2c)
    out: list[tuple[str, str | None]] = []
    for name in _unique(c2s + s2c):
        if name in both:
            out.append((name, None))
        else:
            out.append((name, _C2S if name in c2s else _S2C))
    return out


def _flow_findings(flow: Flow, file: str) -> list[Finding | ScanError]:
    out: list[Finding | ScanError] = []
    client: SshSide | None = flow.ssh_client
    server: SshSide | None = flow.ssh_server
    where = f"stream {flow.stream_id} {flow.flow}"

    def error(message: str) -> None:
        out.append(ScanError(detector=SCANNER, path=file, message=f"{where}: {message}"))

    client_ok = client is not None and client.has_kexinit
    server_ok = server is not None and server.has_kexinit

    for side, role in ((client, "client"), (server, "server")):
        if side is None or not side.banner:
            continue
        version = _protocol_version(side.banner)
        if version is not None and version not in ("2.0", "1.99") and not side.has_kexinit:
            error(f"{role} banner announces SSH {version}; only SSH-2 key exchange is read")

    if not client_ok and not server_ok:
        error("SSH banner without a KEXINIT; no algorithm lists were observed")
        out.extend(_warnings(flow, where, file))
        return out
    if not client_ok:
        error("server KEXINIT without a client KEXINIT; offers are not observed, nothing negotiated")
        out.extend(_warnings(flow, where, file))
        return out
    assert client is not None  # narrowed by client_ok

    if not server_ok:
        error("client KEXINIT without a server KEXINIT; nothing negotiated, only the offers are recorded")

    sid = session_id("ssh", file, flow.flow, client.frame)
    offered_frame = client.frame
    # Selection becomes decidable at the frame completing the second KEXINIT, so a server-first
    # capture anchors it on the client frame (M1M2-08).
    negotiated_frame = offered_frame
    if server is not None and server_ok:
        frames = [f for f in (client.frame, server.frame) if f is not None]
        negotiated_frame = max(frames) if frames else None

    def at(frame: int | None) -> Location:
        return Location(source_type=SourceType.SSH, file=file, flow=flow.flow, frame=frame)

    kex_offered = _unique(_kex(client.kex))
    host_offered = _unique(client.host_key)
    cipher_offered = _unique(client.enc_c2s + client.enc_s2c)

    kex_selected = host_selected = None
    cipher_c2s = cipher_s2c = mac_c2s = mac_s2c = None
    if server is not None and server_ok:
        kex_selected = first_match(_kex(client.kex), _kex(server.kex))
        host_selected = first_match(client.host_key, server.host_key)
        cipher_c2s = first_match(client.enc_c2s, server.enc_c2s)
        cipher_s2c = first_match(client.enc_s2c, server.enc_s2c)
        # An AEAD cipher carries its own authentication, so a first-match MAC would not be a
        # selection. Decided per direction (M1M2-06, M1M2-09).
        if cipher_c2s not in AEAD_CIPHERS:
            mac_c2s = first_match(client.mac_c2s, server.mac_c2s)
        if cipher_s2c not in AEAD_CIPHERS:
            mac_s2c = first_match(client.mac_s2c, server.mac_s2c)
        for label, value, needed in (
            ("key exchange", kex_selected, True),
            ("host key", host_selected, True),
            ("cipher client-to-server", cipher_c2s, True),
            ("cipher server-to-client", cipher_s2c, True),
            ("MAC client-to-server", mac_c2s, cipher_c2s not in AEAD_CIPHERS),
            ("MAC server-to-client", mac_s2c, cipher_s2c not in AEAD_CIPHERS),
        ):
            if value is None and needed:
                error(f"no common {label} algorithm between client and server lists")
        if cipher_c2s and cipher_s2c and cipher_c2s != cipher_s2c:
            error(
                f"ciphers differ by direction: client-to-server {cipher_c2s}, server-to-client "
                f"{cipher_s2c}; the session summary fields carry the client-to-server choice"
            )
        if mac_c2s and mac_s2c and mac_c2s != mac_s2c:
            error(
                f"MACs differ by direction: client-to-server {mac_c2s}, server-to-client "
                f"{mac_s2c}; the session summary fields carry the client-to-server choice"
            )

    if server is not None and server_ok:
        session = {
            "flow": flow.flow,
            "sni": None,
            "version": VERSION_LABEL,
            "offered_groups": kex_offered,
            "negotiated_group": kex_selected,
            "offered_cipher_suites": cipher_offered,
            "negotiated_cipher_suite": cipher_c2s,
            "offered_sig_schemes": host_offered,
            "cert_key": host_selected,  # algorithm name as text; the key itself is never parsed
            "cert_sig_alg": None,
            "transport": "ssh",
            "service": "ssh",
            # always two entries, client then server, verbatim; "" marks a banner not captured so
            # a lone banner is never read as the other side's (M2M4-07). Both are kept when their
            # protocol versions differ (M1M2-10).
            "peer_banners": [client.banner or "", server.banner or ""],
        }
        out.append(
            _finding(
                detector=DETECTOR_VERSION,
                raw_name=VERSION_LABEL,
                usage=Usage.UNKNOWN,
                kind=KindHint.PROTOCOL_VERSION,
                negotiated=True,
                location=at(offered_frame),
                sid=sid,
                extra={
                    "session": session,
                    # the host-key algorithm selection is established from both KEXINITs; this says
                    # nothing about the host identity or a verified signature (M1M2-07)
                    "authentication_observable": host_selected is not None,
                },
            )
        )

    algorithms: list[Finding] = []

    def emit(
        detector: str,
        usage: Usage,
        items: list[tuple[str, str | None]],
        frame: int | None,
        neg: bool,
    ) -> None:
        for name, direction in items:
            algorithms.append(
                _finding(
                    detector=detector,
                    raw_name=name,
                    usage=usage,
                    kind=KindHint.ALGORITHM,
                    negotiated=neg,
                    location=at(frame),
                    sid=sid,
                    extra={} if direction is None else {"direction": direction},
                )
            )

    def plain(names: list[str]) -> list[tuple[str, str | None]]:
        return [(n, None) for n in names]

    def chosen(c2s: str | None, s2c: str | None) -> list[tuple[str, str | None]]:
        if c2s is not None and c2s == s2c:
            return [(c2s, None)]
        return [(n, d) for n, d in ((c2s, _C2S), (s2c, _S2C)) if n is not None]

    emit(DETECTOR_KEX, Usage.KEY_EXCHANGE, plain(kex_offered), offered_frame, False)
    emit(
        DETECTOR_KEX,
        Usage.KEY_EXCHANGE,
        plain(_unique([kex_selected] if kex_selected else [])),
        negotiated_frame,
        True,
    )
    emit(DETECTOR_HOST_KEY, Usage.SIGNATURE, plain(host_offered), offered_frame, False)
    emit(
        DETECTOR_HOST_KEY,
        Usage.SIGNATURE,
        plain([host_selected] if host_selected else []),
        negotiated_frame,
        True,
    )
    emit(
        DETECTOR_CIPHER, Usage.ENCRYPTION, _by_direction(client.enc_c2s, client.enc_s2c), offered_frame, False
    )
    emit(DETECTOR_CIPHER, Usage.ENCRYPTION, chosen(cipher_c2s, cipher_s2c), negotiated_frame, True)
    emit(DETECTOR_MAC, Usage.MAC, _by_direction(client.mac_c2s, client.mac_s2c), offered_frame, False)
    emit(DETECTOR_MAC, Usage.MAC, chosen(mac_c2s, mac_s2c), negotiated_frame, True)

    # A server-first capture puts offers and selection on the same frame, so an offered finding and
    # its negotiated twin would share one id. The negotiated one says everything the offer does.
    taken = {f.id for f in algorithms if f.negotiated}
    out.extend(f for f in algorithms if f.negotiated or f.id not in taken)

    out.extend(_warnings(flow, where, file))
    return out


def _warnings(flow: Flow, where: str, file: str) -> list[ScanError]:
    return [ScanError(detector=SCANNER, path=file, message=f"{where}: {w}") for w in flow.warnings]


def build_findings(result: PureResult, file: str, parser_errors: bool = True) -> list[Finding | ScanError]:
    """Findings and errors for every SSH flow of a parse result, in stream order.

    ``file`` is the root-relative posix path (see ``tls_session.relative_posix``). Parser errors
    become ``ScanError`` entries first, so an unreadable capture is never an empty success. A caller
    that also runs ``tls_session.build_findings`` on the same result passes ``parser_errors=False``
    to one of the two, so each parser error is reported once.
    """
    out: list[Finding | ScanError] = []
    if parser_errors:
        out.extend(ScanError(detector=SCANNER, path=file, message=e) for e in result.errors)
    for flow in sorted(result.flows, key=lambda f: f.stream_id):
        if flow.kind == "ssh":
            out.extend(_flow_findings(flow, file))
    return out
