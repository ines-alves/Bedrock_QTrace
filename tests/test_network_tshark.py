"""tshark.py: canned-output parsing (no tshark needed) and field-level parity with purepy.py."""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
from pathlib import Path

import pytest

from quantumtrace.scanners.network import purepy, tshark

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "network-capture" / "network.pcap"
needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

HRR_HEX = purepy.HRR_RANDOM.hex()
RANDOM_A = "aa" * 32
RANDOM_B = "bb" * 32


def row(**cols: str) -> str:
    """One tshark output line; dots in column names are written as double underscores."""
    values = {name.replace("__", "."): v for name, v in cols.items()}
    unknown = set(values) - set(tshark.COLUMNS)
    assert not unknown, unknown
    return "\t".join(values.get(name, "") for name in tshark.COLUMNS)


def client_row(frame=10, stream=0, **over):
    base = dict(
        frame__number=str(frame),
        frame__time_epoch="1700000000.5",
        tcp__stream=str(stream),
        ip__src="10.0.0.1",
        tcp__srcport="50000",
        ip__dst="10.0.0.2",
        tcp__dstport="443",
        tls__handshake__type="1",
        tls__record__version="0x0301",
        tls__handshake__version="0x0303",
        tls__handshake__random=RANDOM_A,
        tls__handshake__ciphersuite="0x0a0a,0x1301,0x00ff,0x1302,0x5600",
        tls__handshake__extension__type="2570,0,10,13,43,51",
        tls__handshake__extensions_server_name="a.lab",
        tls__handshake__extensions_supported_group="0x2a2a,0x11ec,0x001d",
        tls__handshake__extensions_key_share_group="19018,4588,29",  # decimal, GREASE first
        tls__handshake__sig_hash_alg="0x0403,0x0804",
        tls__handshake__extensions__supported_version="0x3a3a,0x0304,0x0303",
    )
    base.update(over)
    return row(**base)


def server_row(frame=12, stream=0, **over):
    base = dict(
        frame__number=str(frame),
        frame__time_epoch="1700000000.6",
        tcp__stream=str(stream),
        ip__src="10.0.0.2",
        tcp__srcport="443",
        ip__dst="10.0.0.1",
        tcp__dstport="50000",
        tls__handshake__type="2",
        tls__record__version="0x0303",
        tls__handshake__version="0x0303",
        tls__handshake__random=RANDOM_B,
        tls__handshake__ciphersuite="0x1302",
        tls__handshake__extensions__supported_version="0x0304",
        tls__handshake__extensions_key_share_group="4588",
    )
    base.update(over)
    return row(**base)


def flows(*lines: str):
    return tshark.parse_rows("\n".join(lines) + "\n")


# --- number parsing ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "token, expected",
    [("0x1301", 0x1301), ("0X11EC", 0x11EC), ("4588", 4588), (" 29 ", 29), ("", None), ("zz", None)],
)
def test_num_accepts_hex_and_decimal(token, expected):
    assert tshark._num(token) == expected


def test_nums_skips_blanks():
    assert tshark._nums("0x1301,,0x1302") == [0x1301, 0x1302]
    assert tshark._nums("") == []


# --- canned rows ------------------------------------------------------------------------


def test_client_hello_removes_grease_and_signalling_and_keeps_order():
    res = flows(client_row(), server_row())
    assert res.errors == []
    flow = res.flows[0]
    ch = flow.client_hello
    assert ch.cipher_suites == [0x1301, 0x1302]
    assert ch.supported_groups == [0x11EC, 0x001D]
    assert ch.key_share_groups == [0x11EC, 0x001D]  # decimal 4588 and 29, GREASE 19018 dropped
    assert ch.signature_algorithms == [0x0403, 0x0804]
    assert ch.supported_versions == [0x0304, 0x0303]
    assert ch.sni == "a.lab" and ch.legacy_version == 0x0303 and ch.frame == 10
    assert ch.extensions == [2570, 0, 10, 13, 43, 51]  # wire order, GREASE type kept as on the wire
    assert flow.client == ("10.0.0.1", 50000) and flow.server == ("10.0.0.2", 443)
    assert flow.flow == "10.0.0.1:50000->10.0.0.2:443"


def test_tls13_server_hello_version_comes_from_supported_versions():
    flow = flows(client_row(), server_row()).flows[0]
    sh = flow.server_hello
    assert sh.legacy_version == 0x0303 and sh.real_version == 0x0304
    assert sh.selected_suite == 0x1302 and sh.selected_group == 0x11EC and sh.frame == 12
    assert flow.certificate_state == "encrypted"


def test_signature_algorithms_are_read_only_from_client_hello_rows():
    # In a server row sig_hash_alg is the ServerKeyExchange signature, not an offer.
    server = server_row(tls__handshake__type="2,12", tls__handshake__sig_hash_alg="0x0403")
    flow = flows(client_row(), server).flows[0]
    assert flow.server_hello.signature_algorithms == []
    assert flow.client_hello.signature_algorithms == [0x0403, 0x0804]


def test_tls12_flight_with_certificate_and_ecdhe_curve():
    server = server_row(
        tls__handshake__type="2,11,12",
        tls__handshake__ciphersuite="0xc02f",
        tls__handshake__extensions__supported_version="",
        tls__handshake__extensions_key_share_group="",
        tls__handshake__server_named_curve="0x0017",
        tls__handshake__certificate="3082aa,3082bb",
    )
    flow = flows(client_row(), server).flows[0]
    assert flow.server_hello.real_version == 0x0303 and flow.server_hello.selected_group is None
    assert flow.server_key_exchange_group == 0x0017 and flow.server_key_exchange_frame == 12
    assert flow.certificate_frame == 12 and flow.certificate_state == "observed"
    # Rebuilt TLS 1.2 Certificate message body: total length, then length + DER per certificate.
    der1, der2 = bytes.fromhex("3082aa"), bytes.fromhex("3082bb")
    chain = len(der1).to_bytes(3, "big") + der1 + len(der2).to_bytes(3, "big") + der2
    assert flow.server_certificate_msg == len(chain).to_bytes(3, "big") + chain


def test_certificate_row_without_bytes_is_not_observed():
    server = server_row(tls__handshake__type="2,11", tls__handshake__certificate="")
    flow = flows(client_row(), server).flows[0]
    assert flow.certificate_frame == 12 and flow.server_certificate_msg is None
    assert flow.certificate_state == "encrypted"  # TLS 1.3 here, nothing parsed


def test_hello_retry_request_keeps_first_client_hello_and_final_server_hello():
    hrr = server_row(
        frame=11, tls__handshake__random=HRR_HEX, tls__handshake__extensions_key_share_group="29"
    )
    final = server_row(frame=14)
    retry = client_row(frame=13, tls__handshake__random=RANDOM_B)
    res = flows(client_row(), hrr, retry, final)
    flow = res.flows[0]
    assert flow.hello_retry_request is True
    assert flow.client_hello.frame == 10
    assert flow.server_hello.frame == 14 and flow.server_hello.selected_group == 0x11EC
    assert flow.warnings == []


def test_second_hello_pair_keeps_first_and_warns():
    res = flows(client_row(10), server_row(12), client_row(20), server_row(22))
    flow = res.flows[0]
    assert flow.client_hello.frame == 10 and flow.server_hello.frame == 12
    assert len(flow.warnings) == 2
    assert all("only the first is used" in w for w in flow.warnings)


def test_ipv6_endpoints_are_bracketed_in_flow_text():
    c = client_row(ip__src="", ipv6__src="2001:db8::1", ip__dst="", ipv6__dst="2001:db8::2")
    s = server_row(ip__src="", ipv6__src="2001:db8::2", ip__dst="", ipv6__dst="2001:db8::1")
    flow = flows(c, s).flows[0]
    assert flow.flow == "[2001:db8::1]:50000->[2001:db8::2]:443"


def test_server_hello_without_client_hello_still_orients_the_flow():
    flow = flows(server_row()).flows[0]
    assert flow.client_hello is None and flow.server_hello is not None
    assert flow.client == ("10.0.0.1", 50000) and flow.server == ("10.0.0.2", 443)


def test_upgrade_requests_are_recorded_on_tls_flows():
    smtp = row(
        frame__number="5", tcp__stream="0", ip__src="10.0.0.1", tcp__srcport="50000",
        ip__dst="10.0.0.2", tcp__dstport="587", smtp__command_line="STARTTLS\\r\\n",
    )  # fmt: skip
    pg = row(
        frame__number="5", tcp__stream="1", ip__src="10.0.0.1", tcp__srcport="50001",
        ip__dst="10.0.0.2", tcp__dstport="5432", pgsql__request_code="80877103",
    )  # fmt: skip
    res = flows(
        smtp,
        client_row(frame=10, stream=0),
        server_row(frame=12, stream=0),
        pg,
        client_row(frame=20, stream=1),
        server_row(frame=22, stream=1),
    )
    assert [f.upgrade_request for f in res.flows] == ["smtp-starttls", "postgres-sslrequest"]


def test_upgrade_request_never_followed_by_tls_is_a_plaintext_flow():
    smtp = row(
        frame__number="5", tcp__stream="0", ip__src="10.0.0.1", tcp__srcport="50000",
        ip__dst="10.0.0.2", tcp__dstport="587", smtp__command_line="STARTTLS\\r\\n",
    )  # fmt: skip
    flow = flows(smtp).flows[0]
    assert flow.kind == "plaintext" and flow.upgrade_request == "smtp-starttls"
    assert flow.client == ("10.0.0.1", 50000) and flow.server == ("10.0.0.2", 587)
    assert flow.client_hello is None and flow.server_hello is None


def test_streams_are_ordered_and_stream_id_is_the_tcp_stream():
    res = flows(
        client_row(30, stream=7), server_row(32, stream=7), client_row(10, stream=2), server_row(12, stream=2)
    )
    assert [f.stream_id for f in res.flows] == [2, 7]


@pytest.mark.parametrize("garbage", ["not a packet row", "\t\t\t", "x\ty\tz", ""])
def test_garbage_lines_never_raise(garbage):
    res = tshark.parse_rows(garbage + "\n")
    assert res.flows == []


def test_garbage_line_is_reported():
    res = tshark.parse_rows("this is not tshark output\n")
    assert len(res.errors) == 1 and "line 1" in res.errors[0]


# --- SSH canned rows ----------------------------------------------------------------------


def ssh_row(frame, *, stream=0, role="client", banner="", kexinit=False, lists=None, **over):
    """One SSH packet row; ``lists`` = kex, host key, enc c2s, enc s2c, mac c2s, mac s2c."""
    client = ("10.0.0.1", "50000")
    server = ("10.0.0.2", "22")
    (sip, sport), (dip, dport) = (client, server) if role == "client" else (server, client)
    cols = dict(
        frame__number=str(frame),
        frame__time_epoch="1700000000.5",
        tcp__stream=str(stream),
        ip__src=sip,
        tcp__srcport=sport,
        ip__dst=dip,
        tcp__dstport=dport,
        ssh__direction="False" if role == "client" else "True",
    )
    if banner:
        cols["ssh__protocol"] = banner
    if kexinit:
        kex, host, enc_c, enc_s, mac_c, mac_s = lists
        cols.update(
            ssh__message_code="20",
            ssh__kex_algorithms=kex,
            ssh__server_host_key_algorithms=host,
            ssh__encryption_algorithms_client_to_server=enc_c,
            ssh__encryption_algorithms_server_to_client=enc_s,
            ssh__mac_algorithms_client_to_server=mac_c,
            ssh__mac_algorithms_server_to_client=mac_s,
            ssh__compression_algorithms_client_to_server="none",
            ssh__compression_algorithms_server_to_client="none",
        )
    cols.update(over)
    return row(**cols)


LISTS = (
    "curve25519-sha256,group14",
    "ssh-ed25519",
    "aes128-ctr,chacha20",
    "aes128-ctr",
    "hmac-sha2-256",
    "hmac-sha1",
)


def test_ssh_flow_is_built_from_banner_and_kexinit_rows():
    res = flows(
        ssh_row(6, role="server", banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1"),
        ssh_row(8, banner="SSH-2.0-OpenSSH_9.6"),
        ssh_row(10, kexinit=True, lists=LISTS),
        ssh_row(12, role="server", kexinit=True, lists=LISTS),
    )
    assert res.errors == [] and len(res.flows) == 1
    flow = res.flows[0]
    assert flow.kind == "ssh" and flow.flow == "10.0.0.1:50000->10.0.0.2:22"
    assert flow.ssh_client.banner == "SSH-2.0-OpenSSH_9.6"  # server banner came first on the wire
    assert flow.ssh_server.banner == "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1"
    c = flow.ssh_client
    assert c.has_kexinit and c.frame == 10
    assert c.kex == ["curve25519-sha256", "group14"]
    assert c.host_key == ["ssh-ed25519"]
    assert (c.enc_c2s, c.enc_s2c) == (["aes128-ctr", "chacha20"], ["aes128-ctr"])
    assert (c.mac_c2s, c.mac_s2c) == (["hmac-sha2-256"], ["hmac-sha1"])
    assert c.comp_c2s == c.comp_s2c == ["none"]
    assert flow.ssh_server.frame == 12


def test_ssh_banner_only_keeps_the_banner_frame_and_no_kexinit():
    res = flows(ssh_row(6, role="server", banner="SSH-2.0-x"), ssh_row(8, banner="SSH-2.0-y"))
    flow = res.flows[0]
    assert not flow.ssh_client.has_kexinit and flow.ssh_client.frame == 8
    assert flow.ssh_client.kex == []


def test_ssh_banner_and_kexinit_in_one_frame():
    res = flows(ssh_row(9, banner="SSH-2.0-y", kexinit=True, lists=LISTS))
    side = res.flows[0].ssh_client
    assert side.banner == "SSH-2.0-y" and side.has_kexinit and side.frame == 9


def test_second_ssh_kexinit_keeps_the_first_and_warns():
    other = ("x", "y", "z", "z", "m", "m")
    res = flows(
        ssh_row(8, banner="SSH-2.0-y"),
        ssh_row(10, kexinit=True, lists=LISTS),
        ssh_row(30, kexinit=True, lists=other),
    )
    flow = res.flows[0]
    assert flow.ssh_client.kex == ["curve25519-sha256", "group14"] and flow.ssh_client.frame == 10
    assert any("more than one KEXINIT" in w for w in flow.warnings)


def test_ssh_direction_falls_back_to_the_well_known_port():
    res = flows(
        ssh_row(8, banner="SSH-2.0-y", ssh__direction=""),
        ssh_row(6, role="server", banner="SSH-2.0-x", ssh__direction=""),
    )
    flow = res.flows[0]
    assert flow.client == ("10.0.0.1", 50000) and flow.server == ("10.0.0.2", 22)
    assert flow.ssh_client.banner == "SSH-2.0-y"


def test_ssh_row_that_cannot_be_oriented_is_reported():
    res = flows(ssh_row(8, banner="SSH-2.0-y", ssh__direction="", tcp__dstport="2222", tcp__srcport="50000"))
    assert res.flows == [] and "frame 8" in res.errors[0]


def test_ssh_ipv6_endpoints_are_bracketed():
    res = flows(
        ssh_row(
            8,
            banner="SSH-2.0-y",
            ip__src="",
            ipv6__src="2001:db8::1",
            ip__dst="",
            ipv6__dst="2001:db8::2",
            tcp__dstport="22",
        )
    )
    assert res.flows[0].flow == "[2001:db8::1]:50000->[2001:db8::2]:22"


def test_ssh_and_tls_streams_coexist():
    res = flows(
        ssh_row(8, stream=0, banner="SSH-2.0-y"),
        client_row(frame=20, stream=1),
        server_row(frame=22, stream=1),
    )
    assert [f.kind for f in res.flows] == ["ssh", "tls"]


# --- HTTP canned rows ---------------------------------------------------------------------


def http_request_row(frame=447, stream=0, **over):
    base = dict(
        frame__number=str(frame),
        frame__time_epoch="1700000000.5",
        tcp__stream=str(stream),
        ip__src="10.0.0.1",
        tcp__srcport="50000",
        ip__dst="10.0.0.2",
        tcp__dstport="80",
        http__request__method="GET",
        http__request__uri="/status",
        http__host="intranet03.lab",
    )
    base.update(over)
    return row(**base)


def http_response_row(frame=449, stream=0, **over):
    base = dict(
        frame__number=str(frame),
        frame__time_epoch="1700000000.6",
        tcp__stream=str(stream),
        ip__src="10.0.0.2",
        tcp__srcport="80",
        ip__dst="10.0.0.1",
        tcp__dstport="50000",
        http__server="Apache/2.4.58",
        http__response__code="200",
    )
    base.update(over)
    return row(**base)


def test_http_flow_is_built_from_request_and_response_rows():
    res = flows(http_request_row(), http_response_row())
    assert res.errors == [] and len(res.flows) == 1
    flow = res.flows[0]
    assert flow.kind == "http" and flow.flow == "10.0.0.1:50000->10.0.0.2:80"
    info = flow.http
    assert (info.method, info.path, info.host) == ("GET", "/status", "intranet03.lab")
    assert (info.server, info.status, info.frame) == ("Apache/2.4.58", 200, 447)


def test_http_request_without_response_has_no_server_or_status():
    info = flows(http_request_row()).flows[0].http
    assert info.server is None and info.status is None


def test_http_response_without_request_is_not_a_flow():
    assert flows(http_response_row()).flows == []


def test_http_keeps_the_first_request_and_first_response_only():
    res = flows(
        http_request_row(frame=10),
        http_response_row(frame=12),
        http_request_row(frame=20, http__request__uri="/other"),
        http_response_row(frame=22, http__response__code="404", http__server="x"),
    )
    info = res.flows[0].http
    assert (info.path, info.frame, info.status, info.server) == ("/status", 10, 200, "Apache/2.4.58")


def test_http_uri_with_a_comma_is_not_split():
    info = flows(http_request_row(http__request__uri="/a,b")).flows[0].http
    assert info.path == "/a,b"


def test_http_request_without_host_header():
    assert flows(http_request_row(http__host="")).flows[0].http.host is None


def test_http_ipv6_endpoints_are_bracketed():
    req = http_request_row(ip__src="", ipv6__src="2001:db8::1", ip__dst="", ipv6__dst="2001:db8::2")
    assert flows(req).flows[0].flow == "[2001:db8::1]:50000->[2001:db8::2]:80"


def test_http_http_and_tls_streams_coexist_in_stream_order():
    res = flows(
        client_row(frame=20, stream=1),
        server_row(frame=22, stream=1),
        http_request_row(stream=0),
    )
    assert [f.kind for f in res.flows] == ["http", "tls"]


# --- command line and runner ------------------------------------------------------------


def test_command_requests_every_column_and_numeric_fields_mode():
    cmd = tshark.build_command("x.pcap")
    assert cmd[:4] == ["tshark", "-n", "-r", "x.pcap"]
    assert cmd.count("-e") == len(tshark.COLUMNS)
    assert "fields" in cmd and "occurrence=a" in cmd
    assert "tls_tcp" in cmd
    assert "smtp.req.command" not in " ".join(cmd)  # tshark cuts the verb to "STAR"
    assert "ssh.message_code == 20" in cmd[cmd.index("-Y") + 1]
    assert " in {" not in cmd[cmd.index("-Y") + 1]  # Wireshark 4.6 rejects `x in {1 2}`


def test_missing_tshark_is_an_error_not_an_exception(monkeypatch):
    monkeypatch.setattr(tshark.shutil, "which", lambda name: None)
    res = tshark.read_flows_tshark("x.pcap")
    assert res.flows == [] and res.errors == ["tshark is not installed"]
    assert tshark.tshark_available() is False


def test_non_zero_exit_is_an_error_naming_the_file_only(monkeypatch, tmp_path):
    target = tmp_path / "secret-dir" / "x.pcap"

    def fake_run(*args, **kwargs):
        msg = f'tshark: The file "{target}" appears to be damaged or corrupt.\n'
        return subprocess.CompletedProcess(args[0], 2, stdout="", stderr=msg)

    monkeypatch.setattr(tshark.subprocess, "run", fake_run)
    res = tshark.read_flows_tshark(target, tshark="tshark")
    assert len(res.errors) == 1
    assert "status 2" in res.errors[0] and "x.pcap" in res.errors[0]
    assert "secret-dir" not in res.errors[0]


def test_timeout_and_oserror_become_errors(monkeypatch):
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("tshark", 1)

    monkeypatch.setattr(tshark.subprocess, "run", timeout)
    assert "timed out" in tshark.read_flows_tshark("x.pcap", tshark="tshark").errors[0]

    def broken(*a, **k):
        raise OSError("exec format error")

    monkeypatch.setattr(tshark.subprocess, "run", broken)
    assert "could not be run" in tshark.read_flows_tshark("x.pcap", tshark="tshark").errors[0]


def test_truncated_capture_message_is_an_error(monkeypatch):
    def fake_run(*args, **kwargs):
        err = 'tshark: The file "x.pcap" appears to have been cut short in the middle of a packet.\n'
        return subprocess.CompletedProcess(args[0], 0, stdout=client_row() + "\n", stderr=err)

    monkeypatch.setattr(tshark.subprocess, "run", fake_run)
    res = tshark.read_flows_tshark("x.pcap", tshark="tshark")
    assert res.errors == ["capture is truncated; evidence may be partial"]
    assert len(res.flows) == 1  # partial evidence is kept


# --- real tshark ------------------------------------------------------------------------


@needs_tshark
def test_unreadable_files_are_errors(tmp_path):
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture at all" * 10)
    res = tshark.read_flows_tshark(junk)
    assert res.flows == [] and res.errors

    cut = tmp_path / "cut.pcap"
    cut.write_bytes(KIT.read_bytes()[:300])
    res = tshark.read_flows_tshark(cut)
    assert res.errors

    assert tshark.read_flows_tshark(tmp_path / "missing.pcap").errors


@needs_tshark
def test_kit_has_97_tls_24_ssh_and_14_http_flows_and_no_errors():
    res = tshark.read_flows_tshark(KIT)
    assert res.errors == []
    tls = [f for f in res.flows if f.kind == "tls"]
    assert len(tls) == 97 and len(res.flows) == 97 + 24 + 14
    assert all(f.client_hello and f.server_hello for f in tls)
    assert sum(f.kind == "ssh" for f in res.flows) == 24
    assert sum(f.kind == "http" for f in res.flows) == 14
    assert not any(f.kind == "plaintext" for f in res.flows)  # all 11 STARTTLS flows upgrade


@needs_tshark
def test_kit_matches_purepy_on_every_field():
    """Same counts is not enough: the two parsers must agree on each recorded value."""
    ts = {f.stream_id: f for f in tshark.read_flows_tshark(KIT).flows if f.kind == "tls"}
    pp = {f.stream_id: f for f in purepy.read_flows(KIT).flows if f.kind == "tls"}
    assert set(ts) == set(pp) and len(ts) == 97
    skipped = {"first_ts", "kind", "http", "ssh_client", "ssh_server"}
    for stream_id, expected in pp.items():
        actual = ts[stream_id]
        for fld in dataclasses.fields(expected):
            if fld.name in skipped:
                continue
            assert getattr(actual, fld.name) == getattr(expected, fld.name), (stream_id, fld.name)
        assert actual.kind == "tls"
    # the upgrade evidence the service label relies on
    assert sum(f.upgrade_request == "smtp-starttls" for f in ts.values()) == 11
    assert sum(f.upgrade_request == "postgres-sslrequest" for f in ts.values()) == 8


@needs_tshark
def test_kit_ssh_flows_match_purepy_on_every_field():
    ts = {f.stream_id: f for f in tshark.read_flows_tshark(KIT).flows if f.kind == "ssh"}
    pp = {f.stream_id: f for f in purepy.read_flows(KIT).flows if f.kind == "ssh"}
    assert set(ts) == set(pp) and len(ts) == 24
    for stream_id, expected in pp.items():
        actual = ts[stream_id]
        for name in ("client", "server", "warnings"):
            assert getattr(actual, name) == getattr(expected, name), (stream_id, name)
        for side in ("ssh_client", "ssh_server"):
            assert dataclasses.asdict(getattr(actual, side)) == dataclasses.asdict(getattr(expected, side)), (
                stream_id,
                side,
            )


@needs_tshark
def test_kit_http_flows_match_purepy_on_every_field():
    ts = {f.stream_id: f for f in tshark.read_flows_tshark(KIT).flows if f.kind == "http"}
    pp = {f.stream_id: f for f in purepy.read_flows(KIT).flows if f.kind == "http"}
    assert set(ts) == set(pp) and len(ts) == 14
    for stream_id, expected in pp.items():
        actual = ts[stream_id]
        assert (actual.client, actual.server, actual.warnings) == (
            expected.client,
            expected.server,
            expected.warnings,
        )
        assert dataclasses.asdict(actual.http) == dataclasses.asdict(expected.http), stream_id
