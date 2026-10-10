"""tshark runner: the primary capture parser, returning the same dataclasses as ``purepy.py``.

One ``tshark -T fields`` pass over the handshake messages (plus the STARTTLS / SSLRequest upgrade
requests and the SSH banner / KEXINIT packets) is turned into ``PureResult``/``Flow``/``TlsHello``/
``SshSide``/``HttpInfo`` objects, so ``tls_session.py``, ``ssh.py`` and ``plaintext.py`` build
findings from either parser and the two can be compared field by field.

Detect-only and never raises: every failure is recorded in ``PureResult.errors``.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from quantumtrace.scanners.network.purepy import (
    HRR_RANDOM,
    Flow,
    HttpInfo,
    PureResult,
    SshSide,
    TlsHello,
)
from quantumtrace.scanners.network.registry import SIGNALLING_SUITES, is_grease

DEFAULT_TIMEOUT = 120.0

# Display filter: the four handshake messages we read, the plaintext upgrade requests that explain
# a TLS flow on a STARTTLS or Postgres port, and the SSH banner and KEXINIT (message 20) packets.
# `smtp.req.command` is not usable because tshark cuts the verb to four characters ("STAR").
DISPLAY_FILTER = (
    "tls.handshake.type == 1 or tls.handshake.type == 2 or "
    "tls.handshake.type == 11 or tls.handshake.type == 12 or "
    'smtp.command_line contains "STARTTLS" or '
    "pgsql.request_code == 80877103 or "  # 0x04D2162F, the Postgres SSLRequest
    "ssh.protocol or ssh.message_code == 20 or "
    "http.request or http.response"
)

# Column order is the contract between the command line and `parse_rows`.
COLUMNS = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "tls.handshake.type",
    "tls.record.version",
    "tls.handshake.version",
    "tls.handshake.random",
    "tls.handshake.ciphersuite",
    "tls.handshake.extension.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_supported_group",
    "tls.handshake.extensions_key_share_group",
    "tls.handshake.extensions_key_share_selected_group",
    "tls.handshake.sig_hash_alg",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.server_named_curve",
    "tls.handshake.certificate",
    "smtp.command_line",
    "pgsql.request_code",
    "ssh.protocol",
    "ssh.message_code",
    "ssh.direction",
    "ssh.kex_algorithms",
    "ssh.server_host_key_algorithms",
    "ssh.encryption_algorithms_client_to_server",
    "ssh.encryption_algorithms_server_to_client",
    "ssh.mac_algorithms_client_to_server",
    "ssh.mac_algorithms_server_to_client",
    "ssh.compression_algorithms_client_to_server",
    "ssh.compression_algorithms_server_to_client",
    "http.request.method",
    "http.request.uri",
    "http.host",
    "http.server",
    "http.response.code",
)
_COL = {name: i for i, name in enumerate(COLUMNS)}
_AGGREGATOR = ","

_CH, _SH, _CERT, _SKE = 1, 2, 11, 12
_SSH_KEXINIT = 20
_SSH_PORT = 22


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def build_command(path: str | Path, tshark: str = "tshark") -> list[str]:
    cmd = [
        tshark,
        "-n",
        "-r",
        str(path),
        "--enable-heuristic",
        "tls_tcp",
        "-Y",
        DISPLAY_FILTER,
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=a",
        "-E",
        f"aggregator={_AGGREGATOR}",
    ]
    for name in COLUMNS:
        cmd += ["-e", name]
    return cmd


# --- value helpers -------------------------------------------------------------------------


def _num(token: str) -> int | None:
    """Parse one tshark number. Most TLS fields print ``0x1301``; key_share groups print decimal."""
    token = token.strip()
    if not token:
        return None
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token)
    except ValueError:
        return None


def _nums(cell: str) -> list[int]:
    return [n for n in (_num(t) for t in cell.split(_AGGREGATOR)) if n is not None]


def _first_num(cell: str) -> int | None:
    values = _nums(cell)
    return values[0] if values else None


def _first_text(cell: str) -> str | None:
    for token in cell.split(_AGGREGATOR):
        if token.strip():
            return token.strip()
    return None


def _hex_bytes(token: str) -> bytes | None:
    try:
        return bytes.fromhex(token.replace(":", "").replace(" ", ""))
    except ValueError:
        return None


def _ip(cell4: str, cell6: str) -> str | None:
    return _first_text(cell4) or _first_text(cell6)


def _certificate_body(cell: str) -> bytes | None:
    """tshark lists each DER certificate; rebuild the TLS <= 1.2 Certificate message body
    (3-byte total length, then 3-byte length + DER per certificate), the shape purepy keeps."""
    ders = [d for d in (_hex_bytes(t) for t in cell.split(_AGGREGATOR) if t.strip()) if d]
    if not ders:
        return None
    chain = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    return len(chain).to_bytes(3, "big") + chain


@dataclass
class _Acc:
    """Rows of one TCP stream while it is being assembled."""

    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    first_ts: float | None = None
    client_hellos: list[TlsHello] = field(default_factory=list)
    server_hellos: list[TlsHello] = field(default_factory=list)
    certificate: bytes | None = None
    certificate_frame: int | None = None
    ske_group: int | None = None
    ske_frame: int | None = None
    upgrade: str | None = None
    saw_certificate_row: bool = False
    saw_ske_row: bool = False
    ssh: dict[str, SshSide] = field(default_factory=dict)  # "client" / "server"
    ssh_warnings: list[str] = field(default_factory=list)
    http: HttpInfo | None = None
    saw_http_response: bool = False


# --- row parsing (pure) --------------------------------------------------------------------


def _hello(msg_type: int, cells: list[str], frame: int | None) -> TlsHello:
    random = _hex_bytes(_first_text(cells[_COL["tls.handshake.random"]]) or "") or b""
    hello = TlsHello(
        msg_type=msg_type,
        record_version=_first_num(cells[_COL["tls.record.version"]]) or 0,
        legacy_version=_first_num(cells[_COL["tls.handshake.version"]]) or 0,
        random=random,
        frame=frame,
    )
    hello.extensions = _nums(cells[_COL["tls.handshake.extension.type"]])
    hello.alpn = [t for t in cells[_COL["tls.handshake.extensions_alpn_str"]].split(_AGGREGATOR) if t]
    suites = _nums(cells[_COL["tls.handshake.ciphersuite"]])
    versions = [
        v for v in _nums(cells[_COL["tls.handshake.extensions.supported_version"]]) if not is_grease(v)
    ]
    if msg_type == _CH:
        hello.cipher_suites = [s for s in suites if not is_grease(s) and s not in SIGNALLING_SUITES]
        hello.sni = _first_text(cells[_COL["tls.handshake.extensions_server_name"]])
        hello.supported_groups = [
            g for g in _nums(cells[_COL["tls.handshake.extensions_supported_group"]]) if not is_grease(g)
        ]
        hello.key_share_groups = [
            g for g in _nums(cells[_COL["tls.handshake.extensions_key_share_group"]]) if not is_grease(g)
        ]
        # Read only from ClientHello rows: in a server row sig_hash_alg is the ServerKeyExchange
        # signature algorithm, which is not an offer.
        hello.signature_algorithms = [
            s for s in _nums(cells[_COL["tls.handshake.sig_hash_alg"]]) if not is_grease(s)
        ]
        hello.supported_versions = versions
    else:
        hello.cipher_suites = suites[:1]
        hello.supported_versions = versions[:1]
        # A ServerHello key_share carries the chosen group in `..._key_share_group`; tshark keeps
        # `..._key_share_selected_group` for the HelloRetryRequest form.
        hello.selected_group = _first_num(
            cells[_COL["tls.handshake.extensions_key_share_group"]]
        ) or _first_num(cells[_COL["tls.handshake.extensions_key_share_selected_group"]])
        hello.hello_retry_request = random == HRR_RANDOM
    return hello


def _ssh_role(cells: list[str], src_port: int | None, dst_port: int | None) -> str | None:
    """``client`` or ``server`` for the sender of an SSH row. ``ssh.direction`` is True on packets
    sent by the server; without it the well-known port decides."""
    direction = cells[_COL["ssh.direction"]].split(_AGGREGATOR)[0].strip().lower()
    if direction in ("true", "1"):
        return "server"
    if direction in ("false", "0"):
        return "client"
    if dst_port == _SSH_PORT:
        return "client"
    if src_port == _SSH_PORT:
        return "server"
    return None


def _ssh_row(acc: _Acc, cells: list[str], frame: int, src, dst, res: PureResult) -> None:
    role = _ssh_role(cells, src[1], dst[1])
    if role is None:
        res.errors.append(f"SSH packet in frame {frame} cannot be attributed to a client or a server")
        return
    sender, receiver = _endpoint(src), _endpoint(dst)
    if sender and receiver:
        if role == "client":
            acc.client, acc.server = acc.client or sender, acc.server or receiver
        else:
            acc.server, acc.client = acc.server or sender, acc.client or receiver
    side = acc.ssh.get(role)
    banner = cells[_COL["ssh.protocol"]].strip()
    if side is None:
        side = acc.ssh[role] = SshSide(banner=banner)
        side.frame = frame
    elif banner and not side.banner:
        side.banner = banner
        if not side.has_kexinit:
            side.frame = frame
    if _SSH_KEXINIT not in _nums(cells[_COL["ssh.message_code"]]):
        return
    if side.has_kexinit:
        acc.ssh_warnings.append(f"more than one KEXINIT from the {role}; only the first is used")
        return
    side.has_kexinit = True
    side.frame = frame
    side.kex = _names(cells[_COL["ssh.kex_algorithms"]])
    side.host_key = _names(cells[_COL["ssh.server_host_key_algorithms"]])
    side.enc_c2s = _names(cells[_COL["ssh.encryption_algorithms_client_to_server"]])
    side.enc_s2c = _names(cells[_COL["ssh.encryption_algorithms_server_to_client"]])
    side.mac_c2s = _names(cells[_COL["ssh.mac_algorithms_client_to_server"]])
    side.mac_s2c = _names(cells[_COL["ssh.mac_algorithms_server_to_client"]])
    side.comp_c2s = _names(cells[_COL["ssh.compression_algorithms_client_to_server"]])
    side.comp_s2c = _names(cells[_COL["ssh.compression_algorithms_server_to_client"]])


def _http_row(acc: _Acc, cells: list[str], frame: int, src, dst) -> None:
    """The first request of the stream and the first response to it; later ones are ignored."""
    method_cell = cells[_COL["http.request.method"]]
    method = _first_text(method_cell)
    if method:
        if acc.http is not None:
            return
        # One occurrence is the whole cell (a URI may contain the aggregator character); several
        # pipelined requests in one frame are joined, and then the first one is meant.
        pipelined = _AGGREGATOR in method_cell

        def one(name: str) -> str:
            cell = cells[_COL[name]].strip()
            return cell.split(_AGGREGATOR)[0].strip() if pipelined else cell

        acc.http = HttpInfo(
            method=method, path=one("http.request.uri"), host=one("http.host") or None, frame=frame
        )
        sender, receiver = _endpoint(src), _endpoint(dst)
        if sender and receiver:
            acc.client, acc.server = sender, receiver  # the request sender is the client
        return
    status = _first_num(cells[_COL["http.response.code"]])
    if acc.http is not None and status is not None and not acc.saw_http_response:
        acc.saw_http_response = True
        acc.http.status = status
        acc.http.server = cells[_COL["http.server"]].strip().split(_AGGREGATOR)[0].strip() or None


def _names(cell: str) -> list[str]:
    return [t.strip() for t in cell.split(_AGGREGATOR) if t.strip()]


def parse_rows(text: str) -> PureResult:
    """Turn ``tshark -T fields`` output (columns = ``COLUMNS``) into per-stream ``Flow`` records."""
    res = PureResult()
    streams: dict[int, _Acc] = {}
    width = len(COLUMNS)
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        cells = line.split("\t")
        if len(cells) < width:
            cells += [""] * (width - len(cells))
        stream = _first_num(cells[_COL["tcp.stream"]])
        frame = _first_num(cells[_COL["frame.number"]])
        if stream is None or frame is None:
            res.errors.append(f"tshark output line {line_no} is not a packet row")
            continue
        acc = streams.setdefault(stream, _Acc())
        src = (
            _ip(cells[_COL["ip.src"]], cells[_COL["ipv6.src"]]),
            _first_num(cells[_COL["tcp.srcport"]]),
        )
        dst = (
            _ip(cells[_COL["ip.dst"]], cells[_COL["ipv6.dst"]]),
            _first_num(cells[_COL["tcp.dstport"]]),
        )
        if acc.first_ts is None:
            try:
                acc.first_ts = float(cells[_COL["frame.time_epoch"]].split(_AGGREGATOR)[0])
            except ValueError:
                acc.first_ts = 0.0
        if _first_text(cells[_COL["ssh.protocol"]]) or _SSH_KEXINIT in _nums(cells[_COL["ssh.message_code"]]):
            _ssh_row(acc, cells, frame, src, dst, res)
            continue
        if _first_text(cells[_COL["http.request.method"]]) or (
            _first_num(cells[_COL["http.response.code"]]) is not None
        ):
            _http_row(acc, cells, frame, src, dst)
            continue
        types = _nums(cells[_COL["tls.handshake.type"]])
        sender = _endpoint(src)
        receiver = _endpoint(dst)

        if _first_text(cells[_COL["smtp.command_line"]]):
            acc.upgrade = "smtp-starttls"
            acc.client, acc.server = acc.client or sender, acc.server or receiver
        if _first_num(cells[_COL["pgsql.request_code"]]) == 80877103:
            acc.upgrade = "postgres-sslrequest"
            acc.client, acc.server = acc.client or sender, acc.server or receiver
        if _CH in types and sender and receiver:
            acc.client, acc.server = sender, receiver  # the ClientHello sender is the client
            acc.client_hellos.append(_hello(_CH, cells, frame))
        if _SH in types:
            if sender and receiver and acc.client is None:
                acc.server, acc.client = sender, receiver
            acc.server_hellos.append(_hello(_SH, cells, frame))
        if _CERT in types and not acc.saw_certificate_row:
            acc.saw_certificate_row = True
            acc.certificate_frame = frame
            acc.certificate = _certificate_body(cells[_COL["tls.handshake.certificate"]])
        if _SKE in types and not acc.saw_ske_row:
            acc.saw_ske_row = True
            acc.ske_group = _first_num(cells[_COL["tls.handshake.server_named_curve"]])
            acc.ske_frame = frame if acc.ske_group is not None else None

    for stream_id in sorted(streams):
        flow = _flow(stream_id, streams[stream_id])
        if flow is not None:
            res.flows.append(flow)
    return res


def _endpoint(pair: tuple[str | None, int | None]) -> tuple[str, int] | None:
    host, port = pair
    return (host, port) if host is not None and port is not None else None


def _flow(stream_id: int, acc: _Acc) -> Flow | None:
    if acc.ssh:
        if acc.client is None or acc.server is None:
            return None
        flow = Flow(stream_id, acc.client, acc.server, acc.first_ts or 0.0)
        flow.kind = "ssh"
        flow.ssh_client, flow.ssh_server = acc.ssh.get("client"), acc.ssh.get("server")
        flow.warnings.extend(acc.ssh_warnings)
        return flow
    if acc.http is not None:
        if acc.client is None or acc.server is None:
            return None
        flow = Flow(stream_id, acc.client, acc.server, acc.first_ts or 0.0)
        flow.kind, flow.http = "http", acc.http
        return flow
    if acc.client is None or acc.server is None:
        return None
    if not acc.client_hellos and not acc.server_hellos:
        if acc.upgrade is None:
            return None
        # an upgrade was requested and no TLS followed: the traffic stayed in the clear
        flow = Flow(stream_id, acc.client, acc.server, acc.first_ts or 0.0)
        flow.kind, flow.upgrade_request = "plaintext", acc.upgrade
        return flow
    flow = Flow(stream_id, acc.client, acc.server, acc.first_ts or 0.0)
    flow.kind = "tls"
    flow.upgrade_request = acc.upgrade
    chs, shs = acc.client_hellos, acc.server_hellos
    if shs and shs[0].hello_retry_request:
        flow.hello_retry_request = True
    finals = [h for h in shs if not h.hello_retry_request]
    flow.client_hello = chs[0] if chs else None
    flow.server_hello = finals[0] if finals else (shs[0] if shs else None)
    if len(chs) > (2 if flow.hello_retry_request else 1):
        flow.warnings.append("more than one ClientHello in the stream; only the first is used")
    if len(finals) > 1:
        flow.warnings.append("more than one ServerHello in the stream; only the first is used")
    flow.server_certificate_msg = acc.certificate
    flow.certificate_frame = acc.certificate_frame
    flow.server_key_exchange_group = acc.ske_group
    flow.server_key_exchange_frame = acc.ske_frame
    return flow


# --- runner --------------------------------------------------------------------------------


def read_flows_tshark(
    path: str | Path, timeout: float = DEFAULT_TIMEOUT, tshark: str | None = None
) -> PureResult:
    """Parse a capture with tshark into ``Flow`` records. Never raises."""
    binary = tshark or shutil.which("tshark")
    if binary is None:
        res = PureResult()
        res.errors.append("tshark is not installed")
        return res
    try:
        proc = subprocess.run(
            build_command(path, binary),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        res = PureResult()
        res.errors.append(f"tshark timed out after {timeout:g}s reading the capture")
        return res
    except (OSError, ValueError) as exc:
        res = PureResult()
        res.errors.append(f"tshark could not be run: {exc}")
        return res

    res = parse_rows(proc.stdout)
    detail = _first_line(proc.stderr).replace(str(path), Path(path).name)
    if proc.returncode != 0:
        # The partial output is kept, but a capture tshark rejected is an error, not an empty success.
        res.errors.append(f"tshark exited with status {proc.returncode}: {detail or 'no message'}")
    elif "cut short" in proc.stderr:
        res.errors.append("capture is truncated; evidence may be partial")
    return res


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""
