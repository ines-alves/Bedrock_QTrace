"""purepy.py: starter-kit golden counts, tshark cross-check, and synthetic edge cases."""

from __future__ import annotations

import shutil
import struct
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from quantumtrace.scanners.network import purepy

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "network-capture" / "network.pcap"


@pytest.fixture(scope="module")
def kit():
    res = purepy.read_flows(KIT)
    assert res.errors == []
    return res


# --- golden counts (PLAN Appendix D.2 / D.3, confirmed with tshark in docs/DECISIONS.md) ---


def test_kit_packet_and_flow_totals(kit):
    assert kit.packets == 2000
    assert len(kit.flows) == 135
    assert Counter(f.kind for f in kit.flows) == {"tls": 97, "ssh": 24, "http": 14}


def test_kit_tls_profiles(kit):
    c = Counter()
    for f in kit.flows:
        if f.kind != "tls":
            continue
        assert f.client_hello and f.server_hello  # every session has both hellos
        sh = f.server_hello
        c[(f.server[1], hex(sh.real_version), hex(sh.selected_suite), sh.selected_group)] += 1
    assert c == {
        (443, "0x303", "0x2f", None): 33,
        (587, "0x303", "0x2f", None): 11,
        (636, "0x303", "0x2f", None): 10,
        (443, "0x304", "0x1301", 0x001D): 18,
        (993, "0x304", "0x1301", 0x001D): 10,
        (5432, "0x304", "0x1301", 0x001D): 8,
        (443, "0x304", "0x1302", 0x11EC): 7,
    }


def test_kit_tls13_legacy_version_is_0303(kit):
    for f in kit.flows:
        if f.kind == "tls":
            assert f.client_hello.legacy_version == 0x0303


def test_kit_hybrid_offer_and_sni(kit):
    hybrid = [f for f in kit.flows if f.kind == "tls" and f.server_hello.selected_group == 0x11EC]
    assert len(hybrid) == 7
    for f in hybrid:
        assert 0x11EC in f.client_hello.supported_groups
        assert 0x11EC in f.client_hello.key_share_groups
        assert f.client_hello.sni.startswith("vault")


def test_kit_no_certificates(kit):
    assert all(f.server_certificate_msg is None for f in kit.flows)


def test_kit_ssh(kit):
    ssh = [f for f in kit.flows if f.kind == "ssh"]
    assert len(ssh) == 24
    legacy = [f for f in ssh if "diffie-hellman-group1-sha1" in f.ssh_server.kex]
    modern = [f for f in ssh if "curve25519-sha256" in f.ssh_server.kex]
    assert (len(legacy), len(modern)) == (14, 10)
    assert {f.ssh_server.banner for f in legacy} == {"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"}
    assert {f.ssh_client.banner for f in legacy} == {"SSH-2.0-PuTTY_Release_0.76"}
    assert {f.ssh_server.banner for f in modern} == {"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1"}
    assert all(f.ssh_client.has_kexinit and f.ssh_server.has_kexinit for f in ssh)


def test_kit_http(kit):
    http = [f for f in kit.flows if f.kind == "http"]
    assert len(http) == 14
    assert {f.server[1] for f in http} == {80}
    assert all(f.http.method == "GET" and f.http.host.startswith("intranet") for f in http)


def test_kit_flow_and_frame_evidence(kit):
    f = next(x for x in kit.flows if x.kind == "tls" and x.client_hello.sni == "web32.lab")
    assert f.flow == "192.0.2.10:49155->192.0.2.14:443"
    assert (f.client_hello.frame, f.server_hello.frame) == (53, 55)  # tshark: Client/Server Hello
    for x in kit.flows:
        if x.kind == "tls":
            assert x.client_hello.frame < x.server_hello.frame
        if x.kind == "ssh":
            assert x.ssh_client.frame and x.ssh_server.frame
        if x.kind == "http":
            assert x.http.frame


# --- tshark as oracle ------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_crosscheck_with_tshark(kit):
    out = subprocess.run(
        [
            "tshark",
            "-r",
            str(KIT),
            "-Y",
            "tls.handshake.type==2",
            "-T",
            "fields",
            "-e",
            "tcp.stream",
            "-e",
            "tls.handshake.ciphersuite",
            "-e",
            "tls.handshake.extensions.supported_version",
            "-e",
            "tls.handshake.extensions_key_share_group",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    expected = {}
    for line in out.splitlines():
        stream, suite, ver, group = line.split("\t")
        expected[int(stream)] = (
            int(suite, 16),
            int(ver, 16) if ver else 0x0303,
            int(group) if group else None,
        )
    got = {
        f.stream_id: (
            f.server_hello.selected_suite,
            f.server_hello.real_version,
            f.server_hello.selected_group,
        )
        for f in kit.flows
        if f.kind == "tls"
    }
    assert got == expected


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_crosscheck_frame_numbers_with_tshark(kit):
    out = subprocess.run(
        [
            "tshark",
            "-r",
            str(KIT),
            "-Y",
            "tls.handshake.type==1 or tls.handshake.type==2",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "tls.handshake.type",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    expected = {(int(s), int(t)): int(n) for n, s, t in (ln.split("\t") for ln in out.splitlines())}
    got = {}
    for f in kit.flows:
        if f.kind == "tls":
            got[(f.stream_id, 1)] = f.client_hello.frame
            got[(f.stream_id, 2)] = f.server_hello.frame
    assert got == expected


# --- synthetic edge cases ----------------------------------------------------------------


@pytest.mark.parametrize(
    "v, grease",
    [
        (0x0A0A, True),
        (0x1A1A, True),
        (0xFAFA, True),
        (0x0A1A, False),
        (0x11EC, False),
        (0x1301, False),
        (0x0000, False),
        (0x001D, False),
    ],
)
def test_is_grease(v, grease):
    assert purepy.is_grease(v) is grease


def _client_hello(suites, groups, versions, sni="a.lab", key_shares=()):
    def ext(t, b):
        return struct.pack(">HH", t, len(b)) + b

    name = sni.encode()
    sni_ext = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    shares = b"".join(struct.pack(">HH", g, 1) + b"\x00" for g in key_shares)
    exts = (
        ext(0, sni_ext)
        + ext(10, struct.pack(">H", 2 * len(groups)) + b"".join(struct.pack(">H", g) for g in groups))
        + ext(43, bytes([2 * len(versions)]) + b"".join(struct.pack(">H", v) for v in versions))
        + ext(51, struct.pack(">H", len(shares)) + shares)
    )
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + struct.pack(">H", 2 * len(suites))
        + b"".join(struct.pack(">H", s) for s in suites)
        + b"\x01\x00"
        + struct.pack(">H", len(exts))
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _frame(payload, seq, flags=0x18, vlan=False, sport=50000, dport=443, rev=False, v6=False, ext=False):
    if rev:  # server -> client: swap ports here, addresses below
        sport, dport = dport, sport
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload
    if v6:
        src, dst = bytes.fromhex("20010db8" + "0" * 23 + "1"), bytes.fromhex("20010db8" + "0" * 23 + "2")
        if rev:
            src, dst = dst, src
        # optional hop-by-hop header (8 bytes) before TCP
        l4 = (bytes([6, 0]) + bytes(6) if ext else b"") + tcp
        ip = struct.pack(">IHBB", 6 << 28, len(l4), 0 if ext else 6, 64) + src + dst + l4
        et = b"\x86\xdd"
    else:
        src, dst = (b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
        if rev:
            src, dst = dst, src
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0) + src + dst + tcp
        et = b"\x08\x00"
    eth = b"\x00" * 12 + (b"\x81\x00\x00\x07" if vlan else b"") + et
    return eth + ip


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, fr in enumerate(frames):
        out += struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)) + fr
    return out


def test_grease_and_signalling_dropped(tmp_path):
    ch = _client_hello(
        [0x0A0A, 0x1301, 0x00FF, 0x5600, 0xFAFA, 0x1302],
        [0x2A2A, 0x11EC, 0x001D],
        [0x3A3A, 0x0304],
        key_shares=[0x4A4A, 0x11EC],
    )
    p = tmp_path / "g.pcap"
    p.write_bytes(_pcap([_frame(ch, 1)]))
    h = purepy.read_flows(p).flows[0].client_hello
    assert h.cipher_suites == [0x1301, 0x1302]
    assert h.supported_groups == [0x11EC, 0x001D]
    assert h.supported_versions == [0x0304]
    assert h.key_share_groups == [0x11EC]
    assert h.sni == "a.lab"


@pytest.mark.parametrize("vlan", [False, True])
def test_vlan_and_out_of_order_segments(tmp_path, vlan):
    ch = _client_hello([0x1301], [0x001D], [0x0304])
    a, b = ch[:40], ch[40:]
    frames = [
        _frame(b, 1 + len(a), vlan=vlan),
        _frame(a, 1, vlan=vlan),
        _frame(a, 1, vlan=vlan),
    ]  # reordered + retransmit
    p = tmp_path / "o.pcap"
    p.write_bytes(_pcap(frames))
    res = purepy.read_flows(p)
    assert res.flows[0].client_hello.cipher_suites == [0x1301]


@pytest.mark.parametrize("ext", [False, True], ids=["plain", "hop-by-hop"])
@pytest.mark.parametrize("vlan", [False, True], ids=["untagged", "vlan"])
def test_ipv6(tmp_path, vlan, ext):
    ch = _client_hello([0x1301, 0x1302], [0x11EC], [0x0304], sni="v6.lab")
    p = tmp_path / "v6.pcap"
    p.write_bytes(_pcap([_frame(ch, 1, v6=True, vlan=vlan, ext=ext)]))
    res = purepy.read_flows(p)
    f = res.flows[0]
    assert res.skipped_non_tcp == 0
    assert f.client == ("2001:db8::1", 50000) and f.server == ("2001:db8::2", 443)
    assert f.flow == "[2001:db8::1]:50000->[2001:db8::2]:443"
    assert f.client_hello.frame == 1
    assert f.client_hello.sni == "v6.lab" and f.client_hello.cipher_suites == [0x1301, 0x1302]


def test_ipv6_and_ipv4_are_separate_streams(tmp_path):
    ch = _client_hello([0x1301], [0x001D], [0x0304])
    p = tmp_path / "mix.pcap"
    p.write_bytes(_pcap([_frame(ch, 1), _frame(ch, 1, v6=True)]))
    assert len(purepy.read_flows(p).flows) == 2


def test_ipv6_fragment_is_reported_not_silent(tmp_path):
    fr = bytearray(_frame(b"x" * 20, 1, v6=True))
    fr[14 + 6] = 44  # next header = fragment
    p = tmp_path / "frag.pcap"
    p.write_bytes(_pcap([bytes(fr)]))
    res = purepy.read_flows(p)
    assert res.flows == [] and res.skipped_fragments == 1
    assert len(res.errors) == 1 and "fragment" in res.errors[0]


def test_ipv4_fragment_is_reported_not_silent(tmp_path):
    fr = bytearray(_frame(b"x" * 20, 1))
    fr[14 + 6 : 14 + 8] = struct.pack(">H", 0x2000)  # More Fragments, offset 0
    p = tmp_path / "frag4.pcap"
    p.write_bytes(_pcap([bytes(fr)]))
    res = purepy.read_flows(p)
    assert res.flows == [] and res.skipped_fragments == 1 and len(res.errors) == 1


def test_tls_after_plaintext_prefix(tmp_path):
    """STARTTLS-style: plaintext lines precede the ClientHello in the same direction."""
    prefix = b"EHLO client.lab\r\nSTARTTLS\r\n"
    ch = _client_hello([0x002F], [0x0017], [])
    p = tmp_path / "s.pcap"
    p.write_bytes(_pcap([_frame(prefix + ch, 1, dport=587)]))
    f = purepy.read_flows(p).flows[0]
    assert f.kind == "tls" and f.client_hello.cipher_suites == [0x002F]
    assert f.upgrade_request == "smtp-starttls"


@pytest.mark.parametrize("content", [b"", b"not a pcap at all", b"\xd4\xc3\xb2\xa1" + b"\x00" * 10])
def test_never_raises_on_garbage(tmp_path, content):
    p = tmp_path / "bad.pcap"
    p.write_bytes(content)
    res = purepy.read_flows(p)
    assert res.errors and res.flows == []


def test_missing_file_is_an_error_not_an_exception(tmp_path):
    res = purepy.read_flows(tmp_path / "nope.pcap")
    assert res.errors


def test_truncated_pcap_keeps_complete_packets(tmp_path):
    ch = _client_hello([0x1301], [0x001D], [0x0304])
    data = _pcap([_frame(ch, 1), _frame(ch, 1, sport=50001)])
    p = tmp_path / "t.pcap"
    p.write_bytes(data[:-10])
    res = purepy.read_flows(p)
    assert len(res.flows) == 1 and res.errors


# --- certificate state, HelloRetryRequest, unanswered upgrades, partial streams ---------------


def _ext(t, b):
    return struct.pack(">HH", t, len(b)) + b


def _hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def _rec(ct, payload, ver=0x0303):
    return bytes([ct]) + struct.pack(">HH", ver, len(payload)) + payload


def _server_hello(suite, tls13=False, group=None, hrr=False):
    exts = b""
    if tls13:
        exts += _ext(43, struct.pack(">H", 0x0304))
    if group is not None:
        exts += _ext(51, struct.pack(">H", group) + (b"" if hrr else b"\x00\x01\x00"))
    rnd = purepy.HRR_RANDOM if hrr else bytes(32)
    body = (
        b"\x03\x03" + rnd + b"\x00" + struct.pack(">H", suite) + b"\x00" + struct.pack(">H", len(exts)) + exts
    )
    return _hs(2, body)


def _flow_pcap(tmp_path, c2s=(), s2c=(), dport=443):
    """c2s / s2c: lists of payloads, one packet each, in capture order c2s first then s2c."""
    frames, cseq, sseq = [], 1, 1000
    for payload in c2s:
        frames.append(_frame(payload, cseq, dport=dport))
        cseq += len(payload)
    for payload in s2c:
        frames.append(_frame(payload, sseq, dport=dport, rev=True))
        sseq += len(payload)
    p = tmp_path / "f.pcap"
    p.write_bytes(_pcap(frames))
    return p


def test_kit_certificate_state_and_upgrades(kit):
    tls = [f for f in kit.flows if f.kind == "tls"]
    assert Counter(f.certificate_state for f in tls) == {"absent": 54, "encrypted": 43}
    assert all(f.warnings == [] and not f.hello_retry_request for f in kit.flows)
    assert Counter(f.upgrade_request for f in tls) == {
        None: 78,
        "smtp-starttls": 11,
        "postgres-sslrequest": 8,
    }


@pytest.mark.parametrize(
    "tls13, with_cert, state",
    [(True, False, "encrypted"), (False, False, "absent"), (False, True, "observed")],
)
def test_certificate_state(tmp_path, tls13, with_cert, state):
    ch = _client_hello([0x1301, 0x002F], [0x001D], [0x0304] if tls13 else [])
    s2c = [_rec(0x16, _server_hello(0x1301 if tls13 else 0x002F, tls13=tls13))]
    if with_cert:
        s2c.append(_rec(0x16, _hs(11, b"\x00\x00\x03abc")))
    f = purepy.read_flows(_flow_pcap(tmp_path, [ch], s2c)).flows[0]
    assert f.certificate_state == state
    if with_cert:
        assert (f.server_hello.frame, f.certificate_frame) == (2, 3)
        assert f.server_certificate_msg == b"\x00\x00\x03abc"
    else:
        assert f.certificate_frame is None


def test_hello_retry_request_uses_original_offer_and_final_pick(tmp_path):
    ch1 = _client_hello([0x1301], [0x11EC, 0x001D], [0x0304], key_shares=[0x001D])
    ch2 = _client_hello([0x1301], [0x11EC, 0x001D], [0x0304], key_shares=[0x11EC])
    hrr = _rec(0x16, _server_hello(0x1301, tls13=True, group=0x11EC, hrr=True))
    ccs = _rec(0x14, b"\x01")
    sh = _rec(0x16, _server_hello(0x1301, tls13=True, group=0x11EC))
    f = purepy.read_flows(_flow_pcap(tmp_path, [ch1, ccs + ch2], [hrr + ccs, sh])).flows[0]
    assert f.hello_retry_request and f.warnings == []
    assert f.client_hello.key_share_groups == [0x001D]  # the original offer
    assert not f.server_hello.hello_retry_request and f.server_hello.selected_group == 0x11EC
    assert f.server_hello.frame == 4


def test_second_client_hello_without_hrr_is_a_warning(tmp_path):
    ch = _client_hello([0x002F], [0x0017], [])
    sh = _rec(0x16, _server_hello(0x002F))
    f = purepy.read_flows(_flow_pcap(tmp_path, [ch + ch], [sh])).flows[0]
    assert f.kind == "tls" and any("ClientHello" in w for w in f.warnings)


@pytest.mark.parametrize(
    "payload, port, upgrade",
    [
        (b"EHLO a.lab\r\nSTARTTLS\r\n", 587, "smtp-starttls"),
        (b"a001 STARTTLS\r\n", 143, "imap-starttls"),
        (bytes.fromhex("0000000804d2162f"), 5432, "postgres-sslrequest"),
    ],
)
def test_upgrade_never_followed_by_tls_is_plaintext(tmp_path, payload, port, upgrade):
    f = purepy.read_flows(_flow_pcap(tmp_path, [payload], [b"N"], dport=port)).flows[0]
    assert f.kind == "plaintext" and f.upgrade_request == upgrade


def test_plain_smtp_without_starttls_is_not_an_upgrade_flow(tmp_path):
    f = purepy.read_flows(_flow_pcap(tmp_path, [b"EHLO a.lab\r\n"], [b"250 ok\r\n"], dport=25)).flows[0]
    assert f.kind is None and f.upgrade_request is None


def test_gap_in_stream_is_a_warning(tmp_path):
    ch = _client_hello([0x1301], [0x001D], [0x0304])
    frames = [_frame(ch[:40], 1), _frame(ch[40:], 1 + 40 + 10)]  # 10 bytes missing
    p = tmp_path / "gap.pcap"
    p.write_bytes(_pcap(frames))
    f = purepy.read_flows(p).flows[0]
    assert any("client-to-server" in w for w in f.warnings)


def _handshake_record(msg_type, body):
    hs = bytes([msg_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def test_server_key_exchange_group_and_frame(tmp_path):
    ch = _client_hello([0xC02F], [0x0017], [0x0303])
    sh = _handshake_record(2, b"\x03\x03" + bytes(32) + b"\x00" + struct.pack(">H", 0xC02F) + b"\x00")
    cert = _handshake_record(11, b"\x00\x00\x00")
    ske = _handshake_record(12, b"\x03" + struct.pack(">H", 0x0017) + b"\x01\x04")
    frames = [_frame(ch, 1)]
    seq = 1
    for payload in (sh, cert, ske):  # one TCP segment (frame) per server handshake message
        frames.append(_frame(payload, seq, rev=True))
        seq += len(payload)
    p = tmp_path / "ske.pcap"
    p.write_bytes(_pcap(frames))
    flow = purepy.read_flows(p).flows[0]
    assert flow.server_hello.frame == 2
    assert flow.certificate_frame == 3
    assert flow.server_key_exchange_group == 0x0017
    assert flow.server_key_exchange_frame == 4
    assert flow.certificate_state == "observed"
