"""Regressions from public captures (Wireshark test captures, an OpenSSH 10 capture): link types other
than Ethernet, TLS 1.3 draft ServerHellos, decrypted HTTP inside TLS and non-TCP HTTP rows."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from quantumtrace.scanners.network import purepy, tshark

FIXTURE = Path(__file__).parent / "fixtures" / "pcap" / "tls12_ecdhe_ecdsa_p256.pcap"


def _rewrite(linktype: int, header: bytes = b"", strip: int = 14) -> bytes:
    """The Ethernet fixture with every frame's link layer replaced (IPv4 payloads)."""
    data = FIXTURE.read_bytes()
    out = bytearray(data[:20] + struct.pack("<I", linktype))
    off = 24
    while off + 16 <= len(data):
        sec, frac, caplen, length = struct.unpack_from("<IIII", data, off)
        frame = data[off + 16 : off + 16 + caplen]
        body = header + frame[strip:]
        out += struct.pack("<IIII", sec, frac, len(body), len(body) - caplen + length) + body
        off += 16 + caplen
    return bytes(out)


def _summary(path: Path):
    result = purepy.read_flows(path)
    return result.errors, [
        (f.kind, f.server_hello.selected_suite if f.server_hello else None) for f in result.flows
    ]


@pytest.mark.parametrize(
    "linktype,header",
    [
        (101, b""),  # LINKTYPE_RAW
        (228, b""),  # LINKTYPE_IPV4
        (0, struct.pack("<I", 2)),  # BSD loopback, AF_INET
        (113, b"\x00\x00\x00\x01\x00\x06" + b"\x00" * 8 + b"\x08\x00"),  # Linux cooked v1
        (276, b"\x08\x00\x00\x00" + b"\x00" * 16),  # Linux cooked v2: protocol first
    ],
)
def test_non_ethernet_link_types_give_the_ethernet_sessions(tmp_path, linktype, header):
    assert FIXTURE.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"  # little-endian classic pcap
    expected = _summary(FIXTURE)
    path = tmp_path / f"lt{linktype}.pcap"
    path.write_bytes(_rewrite(linktype, header))
    assert _summary(path) == expected and expected[1]


def test_tls13_draft_server_hello_reads_suite_and_draft_key_share():
    # draft-20 ServerHello: version 0x7F14, random, cipher_suite, extensions (key_share was type 40).
    key_share = struct.pack(">HH", 0x001D, 32) + b"\x11" * 32
    extensions = struct.pack(">HH", 40, len(key_share)) + key_share
    body = struct.pack(">H", 0x7F14) + b"\x22" * 32 + struct.pack(">H", 0x1303)
    body += struct.pack(">H", len(extensions)) + extensions
    hello = purepy._parse_hello(2, 0x0303, body)
    assert hello is not None
    assert hello.cipher_suites == [0x1303] and hello.selected_group == 0x001D


def _row(**cells: str) -> str:
    row = [""] * len(tshark.COLUMNS)
    for name, value in cells.items():
        row[tshark._COL[name.replace("__", ".")]] = value
    return "\t".join(row)


def test_decrypted_http_inside_tls_stays_tls_and_udp_http_is_skipped():
    base = {"ip__src": "10.0.0.2", "ip__dst": "93.184.216.34", "tcp__stream": "0"}
    rows = [
        _row(
            frame__number="1",
            tcp__srcport="46800",
            tcp__dstport="443",
            tls__handshake__type="1",
            tls__handshake__ciphersuite="0xc02f",
            **base,
        ),
        _row(
            frame__number="2",
            tcp__srcport="443",
            tcp__dstport="46800",
            tls__handshake__type="2",
            tls__handshake__ciphersuite="0xc02f",
            **{**base, "ip__src": "93.184.216.34", "ip__dst": "10.0.0.2"},
        ),
        _row(
            frame__number="5",
            tcp__srcport="46800",
            tcp__dstport="443",
            http__request__method="GET",
            http__request__uri="/",
            **base,
        ),
        _row(
            frame__number="9",
            ip__src="172.16.16.128",
            ip__dst="239.255.255.250",
            http__request__method="M-SEARCH",
        ),
    ]
    result = tshark.parse_rows("\n".join(rows) + "\n")
    assert result.errors == []
    assert [(flow.kind, flow.server_hello.selected_suite) for flow in result.flows] == [("tls", 0xC02F)]


def _to_pcapng(classic: bytes, tsresol: int | None = None) -> bytes:
    """The classic Ethernet fixture as pcapng: SHB, IDB (Ethernet), one EPB per packet."""

    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", btype, length) + body + struct.pack("<I", length)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = b"" if tsresol is None else struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0)
    out += block(1, struct.pack("<HHI", 1, 0, 65535) + options)
    off = 24
    while off + 16 <= len(classic):
        sec, usec, caplen, length = struct.unpack_from("<IIII", classic, off)
        frame = classic[off + 16 : off + 16 + caplen]
        stamp = sec * 1_000_000 + usec
        out += block(6, struct.pack("<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, caplen, length) + frame)
        off += 16 + caplen
    return out


def test_pcapng_is_read_without_tshark(tmp_path):
    expected = _summary(FIXTURE)
    path = tmp_path / "fixture.pcapng"
    path.write_bytes(_to_pcapng(FIXTURE.read_bytes()))
    assert _summary(path) == expected and expected[1]
    flows = purepy.read_flows(path).flows
    assert abs(flows[0].first_ts - purepy.read_flows(FIXTURE).flows[0].first_ts) < 1e-6
