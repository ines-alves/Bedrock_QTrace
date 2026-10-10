"""Pure-Python pcap reader: Ethernet/IPv4/IPv6/TCP reassembly + TLS hello / SSH / HTTP parsing.

Detect-only and dependency-free. Used when tshark is missing, and as the oracle for the
tshark runner's cross-check. Returns plain dataclasses; conversion to quantumtrace.models
(TLSSession / Finding) happens in tls_session.py and ssh.py.

Never raises on malformed input: problems are collected in ``PureResult.errors``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from quantumtrace.scanners.network.registry import SIGNALLING_SUITES, is_grease

log = logging.getLogger(__name__)

MAX_STREAM_BYTES = 1 << 20  # per direction; hellos and KEXINIT are tiny
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

EXT_SNI, EXT_GROUPS, EXT_SIGALGS, EXT_ALPN = 0, 10, 13, 16
EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE = 43, 51

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_HTTP_REQ = re.compile(rb"^([A-Z]{3,7}) (\S+) HTTP/1\.[01]\r\n")
_STARTTLS_CMD = re.compile(rb"(?im)^(?:\S+ )?STARTTLS\r?$")
_PG_SSLREQUEST = bytes.fromhex("0000000804d2162f")
_STARTTLS_BY_PORT = {25: "smtp", 465: "smtp", 587: "smtp", 143: "imap", 110: "pop3"}
_FRAGMENT = object()  # sentinel: IP fragment, not reassembled


def _endpoint(ep: tuple[str, int]) -> str:
    host, port = ep
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


# --- result types -------------------------------------------------------------------


@dataclass
class TlsHello:
    msg_type: int  # 1 ClientHello, 2 ServerHello
    record_version: int
    legacy_version: int
    random: bytes
    cipher_suites: list[int] = field(default_factory=list)  # client: offered; server: [selected]
    extensions: list[int] = field(default_factory=list)  # extension type ids, wire order
    sni: str | None = None
    supported_groups: list[int] = field(default_factory=list)
    key_share_groups: list[int] = field(default_factory=list)  # client: offered shares
    signature_algorithms: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)  # client list / server [selected]
    alpn: list[str] = field(default_factory=list)
    selected_group: int | None = None  # server key_share group (TLS 1.3)
    hello_retry_request: bool = False
    frame: int | None = None  # 1-based packet number where the hello record ends

    @property
    def selected_suite(self) -> int | None:
        return self.cipher_suites[0] if self.msg_type == 2 and self.cipher_suites else None

    @property
    def real_version(self) -> int:
        """TLS 1.3 hides in supported_versions; legacy_version stays 0x0303."""
        if self.msg_type == 2 and self.supported_versions:
            return self.supported_versions[0]
        return self.legacy_version


@dataclass
class SshSide:
    banner: str
    kex: list[str] = field(default_factory=list)
    host_key: list[str] = field(default_factory=list)
    enc_c2s: list[str] = field(default_factory=list)
    enc_s2c: list[str] = field(default_factory=list)
    mac_c2s: list[str] = field(default_factory=list)
    mac_s2c: list[str] = field(default_factory=list)
    comp_c2s: list[str] = field(default_factory=list)
    comp_s2c: list[str] = field(default_factory=list)
    has_kexinit: bool = False
    frame: int | None = None  # packet where KEXINIT ends (banner packet if no KEXINIT)


@dataclass
class HttpInfo:
    method: str
    path: str
    host: str | None = None
    server: str | None = None
    status: int | None = None
    frame: int | None = None  # packet where the request head ends


@dataclass
class Flow:
    stream_id: int  # ordinal of first packet; matches tshark's tcp.stream numbering
    client: tuple[str, int]
    server: tuple[str, int]
    first_ts: float
    kind: str | None = None  # "tls" | "ssh" | "http" | "plaintext" (unanswered upgrade) | None
    client_hello: TlsHello | None = None
    server_hello: TlsHello | None = None
    server_certificate_msg: bytes | None = None  # raw Certificate handshake body (TLS <= 1.2)
    server_key_exchange_group: int | None = None  # ECDHE named curve (TLS <= 1.2)
    server_key_exchange_frame: int | None = None  # packet where the ServerKeyExchange message ends
    ssh_client: SshSide | None = None
    ssh_server: SshSide | None = None
    http: HttpInfo | None = None
    certificate_frame: int | None = None  # packet where the Certificate message ends
    hello_retry_request: bool = False  # TLS 1.3 HRR seen; hellos below are the original offer and final pick
    upgrade_request: str | None = None  # "smtp-starttls", "imap-starttls", "postgres-sslrequest", ...
    warnings: list[str] = field(default_factory=list)  # evidence is partial or ambiguous; scanner reports

    @property
    def certificate_state(self) -> str | None:
        """`observed`, `encrypted` (TLS 1.3) or `absent` (plaintext handshake, no Certificate captured)."""
        if self.kind != "tls" or self.server_hello is None:
            return None
        if self.server_certificate_msg is not None:
            return "observed"
        return "encrypted" if self.server_hello.real_version == 0x0304 else "absent"

    @property
    def flow(self) -> str:
        """Canonical `Location.flow` text, client first; IPv6 addresses are bracketed."""
        return f"{_endpoint(self.client)}->{_endpoint(self.server)}"


@dataclass
class PureResult:
    flows: list[Flow] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    packets: int = 0
    skipped_non_tcp: int = 0
    skipped_fragments: int = 0


# --- pcap / L2-L4 ----------------------------------------------------------------------


@dataclass
class _Seg:
    seq: int
    data: bytes
    frame: int


@dataclass
class _Dir:
    isn: int | None = None
    segs: list[_Seg] = field(default_factory=list)
    size: int = 0


@dataclass
class _Conn:
    stream_id: int
    first_ts: float
    client: tuple[str, int]
    server: tuple[str, int]
    c2s: _Dir = field(default_factory=_Dir)
    s2c: _Dir = field(default_factory=_Dir)


def _ip(b: bytes) -> str:
    return str(ipaddress.ip_address(b))


def _iter_packets(data: bytes, res: PureResult):
    magic = data[:4]
    if magic not in _PCAP_MAGICS:
        res.errors.append("not a classic pcap (pcapng is only supported through tshark)")
        return
    endian, tick = _PCAP_MAGICS[magic]
    if len(data) < 24:
        res.errors.append("truncated pcap global header")
        return
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != 1:
        res.errors.append(f"unsupported linktype {linktype} (only Ethernet=1)")
        return
    off = 24
    while off + 16 <= len(data):
        sec, frac, caplen, _ = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if off + caplen > len(data):
            res.errors.append("truncated packet at end of file")
            return
        yield sec + frac / tick, data[off : off + caplen]
        off += caplen


_V6_EXT_HEADERS = frozenset(
    {0, 43, 60, 135, 139, 140}
)  # hop-by-hop, routing, dest opts, mobility, HIP, shim6


def _parse_l3(frame: bytes, off: int, ethertype: int):
    """-> (src, dst, tcp_offset, l3_end) for an unfragmented IPv4/IPv6 TCP packet, _FRAGMENT, or None."""
    if ethertype == 0x0800:
        if len(frame) < off + 20:
            return None
        ihl = (frame[off] & 0x0F) * 4
        total = struct.unpack_from(">H", frame, off + 2)[0]
        frag = struct.unpack_from(">H", frame, off + 6)[0]
        if frame[off + 9] != 6 or ihl < 20:
            return None
        if frag & 0x3FFF:  # offset != 0 or More Fragments set
            return _FRAGMENT
        return (
            _ip(frame[off + 12 : off + 16]),
            _ip(frame[off + 16 : off + 20]),
            off + ihl,
            min(len(frame), off + total),
        )  # trim Ethernet padding
    if ethertype == 0x86DD:
        if len(frame) < off + 40 or frame[off] >> 4 != 6:
            return None
        plen = struct.unpack_from(">H", frame, off + 4)[0]
        nxt, end, i = frame[off + 6], min(len(frame), off + 40 + plen), off + 40
        while nxt in _V6_EXT_HEADERS:
            if i + 8 > end:
                return None
            nxt, i = frame[i], i + (frame[i + 1] + 1) * 8
        if nxt == 44:
            return _FRAGMENT
        if nxt != 6:  # ESP/AH and non-TCP are not decoded
            return None
        return _ip(frame[off + 8 : off + 24]), _ip(frame[off + 24 : off + 40]), i, end
    return None


def _parse_tcp(frame: bytes):
    """-> (src_ip, dst_ip, sport, dport, seq, flags, payload), None, or _FRAGMENT."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    off = 14
    while ethertype in (0x8100, 0x88A8):  # 802.1Q / QinQ
        if len(frame) < off + 4:
            return None
        ethertype = struct.unpack_from(">H", frame, off + 2)[0]
        off += 4
    l3 = _parse_l3(frame, off, ethertype)
    if l3 is None or l3 is _FRAGMENT:
        return l3
    src, dst, tcp, end = l3
    if end < tcp + 20:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", frame, tcp)
    doff = (frame[tcp + 12] >> 4) * 4
    flags = frame[tcp + 13]
    return src, dst, sport, dport, seq, flags, frame[tcp + doff : end]


def _reassemble(d: _Dir) -> tuple[bytes, list[tuple[int, int]], bool]:
    """-> (contiguous bytes, [(stream offset, frame)] per contributing packet, complete?)."""
    if not d.segs:
        return b"", [], True
    base = d.isn if d.isn is not None else min(s.seq for s in d.segs)
    out = bytearray()
    marks: list[tuple[int, int]] = []
    complete = d.size < MAX_STREAM_BYTES
    for seg in sorted(d.segs, key=lambda s: (((s.seq - base) & 0xFFFFFFFF), s.frame)):
        rel = (seg.seq - base) & 0xFFFFFFFF
        if rel > len(out):
            complete = False  # gap: keep the contiguous prefix only
            break
        if rel + len(seg.data) > len(out):
            marks.append((len(out), seg.frame))
            out += seg.data[len(out) - rel :]
    return bytes(out), marks, complete


def _frame_at(marks: list[tuple[int, int]], offset: int) -> int | None:
    """Packet number carrying the byte at `offset` of a reassembled stream."""
    frame = None
    for start, number in marks:
        if start > offset:
            break
        frame = number
    return frame


# --- TLS ---------------------------------------------------------------------------------


def _u16s(b: bytes) -> list[int]:
    return [struct.unpack_from(">H", b, i)[0] for i in range(0, len(b) - 1, 2)]


def _parse_extensions(h: TlsHello, blob: bytes) -> None:
    i = 0
    while i + 4 <= len(blob):
        etype, elen = struct.unpack_from(">HH", blob, i)
        body = blob[i + 4 : i + 4 + elen]
        i += 4 + elen
        h.extensions.append(etype)
        client = h.msg_type == 1
        if etype == EXT_SNI and len(body) >= 5:
            nlen = struct.unpack_from(">H", body, 3)[0]
            h.sni = body[5 : 5 + nlen].decode("ascii", "replace")
        elif etype == EXT_GROUPS and len(body) >= 2:
            h.supported_groups = [g for g in _u16s(body[2:]) if not is_grease(g)]
        elif etype == EXT_SIGALGS and len(body) >= 2:
            h.signature_algorithms = [s for s in _u16s(body[2:]) if not is_grease(s)]
        elif etype == EXT_SUPPORTED_VERSIONS and body:
            vs = _u16s(body[1:]) if client else _u16s(body[:2])
            h.supported_versions = [v for v in vs if not is_grease(v)]
        elif etype == EXT_KEY_SHARE and len(body) >= 2:
            if client:
                j, end = 2, 2 + struct.unpack_from(">H", body, 0)[0]
                while j + 4 <= min(end, len(body)):
                    group, klen = struct.unpack_from(">HH", body, j)
                    if not is_grease(group):
                        h.key_share_groups.append(group)
                    j += 4 + klen
            else:
                h.selected_group = struct.unpack_from(">H", body, 0)[0]
        elif etype == EXT_ALPN and len(body) >= 2:
            j = 2
            while j < len(body):
                n = body[j]
                h.alpn.append(body[j + 1 : j + 1 + n].decode("ascii", "replace"))
                j += 1 + n


def _parse_hello(msg_type: int, record_version: int, body: bytes) -> TlsHello | None:
    try:
        legacy = struct.unpack_from(">H", body, 0)[0]
        h = TlsHello(msg_type, record_version, legacy, body[2:34])
        i = 34
        i += 1 + body[i]  # session id
        if msg_type == 1:
            n = struct.unpack_from(">H", body, i)[0]
            suites = _u16s(body[i + 2 : i + 2 + n])
            h.cipher_suites = [s for s in suites if not is_grease(s) and s not in SIGNALLING_SUITES]
            i += 2 + n
            i += 1 + body[i]  # compression methods
        else:
            h.cipher_suites = [struct.unpack_from(">H", body, i)[0]]
            h.hello_retry_request = h.random == HRR_RANDOM
            i += 3  # suite + compression method
        if i + 2 <= len(body):
            elen = struct.unpack_from(">H", body, i)[0]
            _parse_extensions(h, body[i + 2 : i + 2 + elen])
        return h
    except (struct.error, IndexError):
        return None


def _tls_start(buf: bytes, want: int) -> int:
    """Offset of the first plausible TLS handshake record whose first message is `want`.

    Skips the plaintext prefix of STARTTLS (SMTP) and Postgres SSLRequest flows.
    """
    for m in re.finditer(rb"\x16\x03[\x00-\x04]", buf):
        i = m.start()
        if i + 9 <= len(buf) and buf[i + 5] == want:
            rlen = struct.unpack_from(">H", buf, i + 3)[0]
            hlen = int.from_bytes(buf[i + 6 : i + 9], "big")
            if hlen + 4 <= rlen:
                return i
    return -1


def _tls_handshake_msgs(buf: bytes, start: int, skip_ccs: bool = False):
    """Yield (record_version, msg_type, body, last_byte_offset) from plaintext handshake records.

    `skip_ccs` steps over one-byte ChangeCipherSpec records, which TLS 1.3 sends in compatibility
    mode around a HelloRetryRequest; it is only safe when the handshake is known to be plaintext.
    """
    pending = b""
    i = start
    rec_ver = 0
    while i + 5 <= len(buf) and buf[i] in ((0x16, 0x14) if skip_ccs else (0x16,)):
        if buf[i] == 0x14:
            i += 5 + struct.unpack_from(">H", buf, i + 3)[0]
            continue
        rec_ver, rlen = struct.unpack_from(">HH", buf, i + 1)
        pending += buf[i + 5 : i + 5 + rlen]
        i += 5 + rlen
        while len(pending) >= 4:
            mlen = int.from_bytes(pending[1:4], "big")
            if len(pending) < 4 + mlen:
                break
            yield rec_ver, pending[0], pending[4 : 4 + mlen], i - 1
            pending = pending[4 + mlen :]


@dataclass
class _TlsSide:
    hellos: list[TlsHello] = field(default_factory=list)
    certificate: bytes | None = None
    certificate_frame: int | None = None
    ske_group: int | None = None
    ske_frame: int | None = None


def _parse_tls_side(buf: bytes, want: int, marks: list[tuple[int, int]], skip_ccs: bool = False) -> _TlsSide:
    side = _TlsSide()
    start = _tls_start(buf, want)
    if start < 0:
        return side
    for rec_ver, mtype, body, last in _tls_handshake_msgs(buf, start, skip_ccs):
        if mtype == want:
            hello = _parse_hello(mtype, rec_ver, body)
            if hello:
                hello.frame = _frame_at(marks, last)
                side.hellos.append(hello)
        elif mtype == 11 and side.certificate is None:
            side.certificate, side.certificate_frame = body, _frame_at(marks, last)
        elif mtype == 12 and side.ske_group is None and len(body) >= 3 and body[0] == 3:
            side.ske_group = struct.unpack_from(">H", body, 1)[0]  # ECDHE named_curve
            side.ske_frame = _frame_at(marks, last)
    return side


# --- SSH / HTTP ------------------------------------------------------------------------


def _name_list(buf: bytes, i: int) -> tuple[list[str], int]:
    n = struct.unpack_from(">I", buf, i)[0]
    raw = buf[i + 4 : i + 4 + n].decode("ascii", "replace")
    return (raw.split(",") if raw else []), i + 4 + n


def _parse_ssh_side(buf: bytes, marks: list[tuple[int, int]]) -> SshSide | None:
    if not buf.startswith(b"SSH-"):
        return None
    nl = buf.find(b"\n")
    if nl < 0:
        return None
    side = SshSide(banner=buf[:nl].rstrip(b"\r").decode("ascii", "replace"))
    side.frame = _frame_at(marks, nl)
    i = nl + 1
    try:
        plen = struct.unpack_from(">I", buf, i)[0]
        padlen, msg = buf[i + 4], buf[i + 5]
        if msg != 20 or plen > 35000 or i + 4 + plen > len(buf) or padlen >= plen:
            return side
        j = i + 6 + 16  # skip cookie
        lists = []
        for _ in range(10):
            names, j = _name_list(buf, j)
            lists.append(names)
        (
            side.kex,
            side.host_key,
            side.enc_c2s,
            side.enc_s2c,
            side.mac_c2s,
            side.mac_s2c,
            side.comp_c2s,
            side.comp_s2c,
        ) = lists[:8]
        side.has_kexinit = True
        side.frame = _frame_at(marks, i + 3 + plen)
    except (struct.error, IndexError):
        pass
    return side


def _parse_http(c2s: bytes, s2c: bytes, c_marks: list[tuple[int, int]]) -> HttpInfo | None:
    m = _HTTP_REQ.match(c2s)
    if not m:
        return None
    info = HttpInfo(m.group(1).decode(), m.group(2).decode("ascii", "replace"))
    head_end = c2s.find(b"\r\n\r\n")
    # the request head ends at the blank line; an unterminated head keeps the first packet
    info.frame = _frame_at(c_marks, head_end + 3 if head_end >= 0 else 0)
    head = c2s.split(b"\r\n\r\n", 1)[0]
    h = re.search(rb"(?im)^host:[ \t]*(\S+)", head)
    info.host = h.group(1).decode("ascii", "replace") if h else None
    if s2c.startswith(b"HTTP/"):
        st = re.match(rb"HTTP/1\.[01] (\d{3})", s2c)
        info.status = int(st.group(1)) if st else None
        sv = re.search(rb"(?im)^server:[ \t]*([^\r\n]+)", s2c.split(b"\r\n\r\n", 1)[0])
        info.server = sv.group(1).decode("ascii", "replace") if sv else None
    return info


def _upgrade_request(cb: bytes, server_port: int) -> str | None:
    if cb.startswith(_PG_SSLREQUEST):
        return "postgres-sslrequest"
    if _STARTTLS_CMD.search(cb[:4096]):
        return f"{_STARTTLS_BY_PORT.get(server_port, 'unknown')}-starttls"
    return None


def _classify(c: _Conn) -> Flow:
    (cb, cm, c_complete), (sb, sm, s_complete) = _reassemble(c.c2s), _reassemble(c.s2c)
    flow = Flow(c.stream_id, c.client, c.server, c.first_ts)
    if not c_complete:
        flow.warnings.append("client-to-server stream has a gap or exceeds the size limit; evidence partial")
    if not s_complete:
        flow.warnings.append("server-to-client stream has a gap or exceeds the size limit; evidence partial")
    ssh_c, ssh_s = _parse_ssh_side(cb, cm), _parse_ssh_side(sb, sm)
    if ssh_c or ssh_s:
        flow.kind, flow.ssh_client, flow.ssh_server = "ssh", ssh_c, ssh_s
        return flow
    http = _parse_http(cb, sb, cm)
    if http:
        flow.kind, flow.http = "http", http
        return flow

    flow.upgrade_request = _upgrade_request(cb, c.server[1])
    cside, sside = _parse_tls_side(cb, 1, cm), _parse_tls_side(sb, 2, sm)
    if sside.hellos and sside.hellos[0].hello_retry_request:
        # HelloRetryRequest: the final ServerHello follows a compatibility CCS record.
        flow.hello_retry_request = True
        cside, sside = _parse_tls_side(cb, 1, cm, True), _parse_tls_side(sb, 2, sm, True)
    if not (cside.hellos or sside.hellos):
        if flow.upgrade_request:
            flow.kind = "plaintext"  # upgrade requested, no TLS followed
        return flow

    flow.kind = "tls"
    flow.client_hello = cside.hellos[0] if cside.hellos else None
    finals = [h for h in sside.hellos if not h.hello_retry_request]
    flow.server_hello = finals[0] if finals else (sside.hellos[0] if sside.hellos else None)
    if len(cside.hellos) > (2 if flow.hello_retry_request else 1):
        flow.warnings.append("more than one ClientHello in the stream; only the first is used")
    if len(finals) > 1:
        flow.warnings.append("more than one ServerHello in the stream; only the first is used")
    flow.server_certificate_msg = sside.certificate
    flow.certificate_frame = sside.certificate_frame
    flow.server_key_exchange_group = sside.ske_group
    flow.server_key_exchange_frame = sside.ske_frame
    return flow


# --- entry point ---------------------------------------------------------------------------


def read_flows(path: str | Path) -> PureResult:
    """Parse a classic pcap into per-TCP-stream Flow records. Never raises."""
    res = PureResult()
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        res.errors.append(f"cannot read {path}: {e}")
        return res
    conns: dict[frozenset, _Conn] = {}
    for ts, frame in _iter_packets(data, res):
        res.packets += 1
        seg = _parse_tcp(frame)
        if seg is _FRAGMENT:
            res.skipped_fragments += 1
            continue
        if seg is None:
            res.skipped_non_tcp += 1
            continue
        src, dst, sport, dport, seq, flags, payload = seg
        a, b = (src, sport), (dst, dport)
        key = frozenset((a, b))
        syn, ack = bool(flags & 0x02), bool(flags & 0x10)
        conn = conns.get(key)
        if conn is None:  # first packet seen decides the initiator unless a SYN-ACK arrives first
            client, server = (b, a) if syn and ack else (a, b)
            conn = conns[key] = _Conn(len(conns), ts, client, server)
        d = conn.c2s if a == conn.client else conn.s2c
        if syn:
            d.isn = (seq + 1) & 0xFFFFFFFF
        if payload and d.size < MAX_STREAM_BYTES:
            d.segs.append(_Seg(seq, payload, res.packets))
            d.size += len(payload)
    res.flows = [_classify(c) for c in conns.values()]
    if res.skipped_fragments:
        res.errors.append(
            f"{res.skipped_fragments} IP fragment(s) were not reassembled; "
            "TCP sessions carried in them may be missing"
        )
    for f in res.flows:
        if f.kind is None:
            log.debug("stream %d %s -> %s: no recognised protocol", f.stream_id, f.client, f.server)
    return res
