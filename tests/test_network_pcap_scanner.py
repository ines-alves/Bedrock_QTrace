"""pcap_scanner.py: the registered `pcap` adapter, on the starter kit through both parsers and on
small hand-made files for the failure paths."""

from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest

from quantumtrace.models import Finding, KindHint, ScanError, SourceType
from quantumtrace.scanners import base
from quantumtrace.scanners.network import pcap_scanner, plaintext, purepy, ssh, tls_session, tshark
from quantumtrace.scanners.network.pcap_scanner import PcapScanner
from quantumtrace.scanners.network.purepy import PureResult

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "network-capture" / "network.pcap"
FORBIDDEN_KEYS = {"tier", "verdict", "verdict_tier", "pq_status", "threat", "score", "risk_points"}
HAS_TSHARK = shutil.which("tshark") is not None


def scan(path: Path, root: Path | None = None) -> list[Finding | ScanError]:
    return list(PcapScanner().scan(path, root if root is not None else path.parent))


def findings(out):
    return [x for x in out if isinstance(x, Finding)]


def errors(out):
    return [x for x in out if isinstance(x, ScanError)]


def parser_names():
    return ["purepy", "tshark"] if HAS_TSHARK else ["purepy"]


@pytest.fixture(params=parser_names())
def parser(request, monkeypatch):
    if request.param == "purepy":
        monkeypatch.setattr(tshark, "tshark_available", lambda: False)
    return request.param


@pytest.fixture
def no_tshark(monkeypatch):
    monkeypatch.setattr(tshark, "tshark_available", lambda: False)


@pytest.fixture
def with_tshark(monkeypatch):
    monkeypatch.setattr(tshark, "tshark_available", lambda: True)


# --- registration and can_handle ----------------------------------------------------------------


def test_registered_once_as_pcap():
    assert [s.name for s in base.REGISTRY].count("pcap") == 1
    scanner = base.select_scanners(["pcap"])[0]
    assert scanner.name == "pcap" and scanner.source_type == SourceType.PCAP
    assert isinstance(scanner, PcapScanner)


@pytest.mark.parametrize("name", ["a.pcap", "a.PCAP", "a.pcapng", "a.Cap", "dir/x.cap", "missing.pcap"])
def test_can_handle_by_extension(name):
    assert PcapScanner().can_handle(Path(name))


@pytest.mark.parametrize("name", ["a.txt", "a.json", "pcap", "a.pcap.gz", "a.pcapx", "a"])
def test_can_handle_rejects_other_files(name):
    assert not PcapScanner().can_handle(Path(name))


# --- kit ----------------------------------------------------------------------------------------


def test_kit_counts_and_contract(parser):
    out = scan(KIT)
    assert errors(out) == []
    found = findings(out)
    sessions = [f for f in found if f.session_id and f.location.source_type == SourceType.PCAP]
    assert (
        len({f.session_id for f in found if f.location.source_type == SourceType.PCAP and f.session_id}) == 97
    )
    assert len({f.session_id for f in found if f.location.source_type == SourceType.SSH}) == 24
    assert sum(1 for f in found if f.kind_hint == KindHint.PLAINTEXT) == 14
    assert [f for f in found if f.kind_hint == KindHint.CERTIFICATE] == []  # the kit has no Certificate
    assert sessions
    assert len({f.id for f in found}) == len(found)
    for f in found:
        assert f.location.file == "network.pcap"
        assert not (FORBIDDEN_KEYS & set(f.extra))
        assert not (FORBIDDEN_KEYS & set(f.extra.get("session") or {}))


def test_location_file_is_relative_to_root(parser, tmp_path):
    nested = tmp_path / "captures" / "site"
    nested.mkdir(parents=True)
    copy = nested / "net.pcap"
    shutil.copy(KIT, copy)
    files = {f.location.file for f in findings(scan(copy, tmp_path))}
    assert files == {"captures/site/net.pcap"}
    files = {f.location.file for f in findings(scan(copy, nested))}
    assert files == {"net.pcap"}


def test_scan_with_parent_root_reports_bare_name(parser):
    assert {f.location.file for f in findings(scan(KIT, KIT.parent))} == {"network.pcap"}


def test_order_is_tls_then_ssh_then_plaintext(parser):
    kinds = []
    for f in findings(scan(KIT)):
        group = (
            "plaintext"
            if f.kind_hint == KindHint.PLAINTEXT
            else "ssh"
            if f.location.source_type == SourceType.SSH
            else "tls"
        )
        if not kinds or kinds[-1] != group:
            kinds.append(group)
    assert kinds == ["tls", "ssh", "plaintext"]


def test_rescan_is_deterministic_and_registry_unchanged(parser):
    first = [x.model_dump() for x in scan(KIT)]
    second = [x.model_dump() for x in scan(KIT)]
    assert first == second
    assert [s.name for s in base.REGISTRY].count("pcap") == 1


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not installed")
def test_both_parsers_give_the_same_output(monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(tshark, "tshark_available", lambda: False)
        a = [x.model_dump() for x in scan(KIT)]
    b = [x.model_dump() for x in scan(KIT)]
    assert a == b and a


# --- unreadable captures: ScanError, never an empty success -------------------------------------


def test_pcapng_without_tshark_is_an_error(no_tshark, tmp_path):
    p = tmp_path / "x.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    out = scan(p)
    assert findings(out) == []
    assert len(errors(out)) == 1 and "pcapng" in errors(out)[0].message
    assert errors(out)[0].path == "x.pcapng" and errors(out)[0].detector == "pcap"


def test_missing_file(parser, tmp_path):
    out = scan(tmp_path / "gone.pcap")
    assert findings(out) == [] and len(errors(out)) == 1
    assert str(tmp_path) not in errors(out)[0].message


def test_empty_file(parser, tmp_path):
    p = tmp_path / "e.pcap"
    p.write_bytes(b"")
    out = scan(p)
    assert findings(out) == [] and [e.message for e in errors(out)] == ["capture is empty"]


def test_garbage_file(parser, tmp_path):
    p = tmp_path / "g.pcap"
    p.write_bytes(b"this is not a capture file at all" * 4)
    out = scan(p)
    assert findings(out) == [] and errors(out)
    assert all(str(tmp_path) not in e.message for e in errors(out))


def test_truncated_capture_keeps_findings_and_reports_error(parser, tmp_path):
    data = KIT.read_bytes()
    p = tmp_path / "t.pcap"
    p.write_bytes(data[: len(data) // 2])
    out = scan(p)
    assert errors(out) and findings(out)
    assert 0 < len(findings(out))


# --- errors once, cross-check, fallback ---------------------------------------------------------


def test_parser_errors_reported_once(no_tshark, monkeypatch):
    real = purepy.read_flows

    def fake(path):
        res = real(path)
        res.errors = ["something odd", "something odd", "second problem"]
        return res

    monkeypatch.setattr(purepy, "read_flows", fake)
    messages = [e.message for e in errors(scan(KIT))]
    assert messages == ["something odd", "second problem"]


def test_error_messages_carry_no_absolute_path(no_tshark, tmp_path, monkeypatch):
    p = tmp_path / "c.pcap"
    p.write_bytes(KIT.read_bytes()[:100])

    def fake(path):
        res = PureResult()
        res.errors = [f"cannot read {path}: boom"]
        return res

    monkeypatch.setattr(purepy, "read_flows", fake)
    for e in errors(scan(p)):
        assert str(tmp_path) not in e.message


def test_cross_check_mismatch_is_reported_and_primary_used(with_tshark, monkeypatch):
    real = purepy.read_flows
    monkeypatch.setattr(tshark, "read_flows_tshark", lambda path, timeout=0: real(path))
    calls = []

    def second(path):
        res = real(path)
        calls.append(path)
        if len(calls) == 1:  # the cross-check parse; the tshark stand-in uses the saved parser
            res.flows = [f for f in res.flows if f.kind != "tls"]
        return res

    monkeypatch.setattr(purepy, "read_flows", second)
    out = scan(KIT)
    msgs = [e.message for e in errors(out)]
    assert msgs == ["parsers disagree on tls flows: tshark 97, built-in parser 0; tshark result used"]
    assert len(findings(out)) > 0


def test_cross_check_skipped_for_large_files(with_tshark, monkeypatch):
    real = purepy.read_flows
    monkeypatch.setattr(tshark, "read_flows_tshark", lambda path, timeout=0: real(path))
    calls = []
    monkeypatch.setattr(purepy, "read_flows", lambda p: calls.append(p) or real(p))
    monkeypatch.setattr(pcap_scanner, "CROSS_CHECK_MAX_BYTES", 10)
    assert errors(scan(KIT)) == []
    assert calls == []  # the tshark stand-in called the saved parser; no second opinion was run


def test_tshark_timeout_falls_back_to_builtin_parser(with_tshark, monkeypatch):
    def timed_out(path, timeout=0):
        res = PureResult()
        res.errors.append("tshark timed out after 120s reading the capture")
        return res

    monkeypatch.setattr(tshark, "read_flows_tshark", timed_out)
    out = scan(KIT)
    assert len(findings(out)) > 0
    assert [e.message for e in errors(out)] == [
        "tshark timed out after 120s reading the capture",
        "tshark failed; flows come from the built-in parser",
    ]


def test_tshark_timeout_on_pcapng_is_error_only(with_tshark, monkeypatch, tmp_path):
    def timed_out(path, timeout=0):
        res = PureResult()
        res.errors.append("tshark timed out after 120s reading the capture")
        return res

    monkeypatch.setattr(tshark, "read_flows_tshark", timed_out)
    p = tmp_path / "n.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    out = scan(p)
    assert findings(out) == []
    assert [e.message for e in errors(out)] == ["tshark timed out after 120s reading the capture"]


def test_oversized_capture_without_tshark_is_error(no_tshark, monkeypatch):
    monkeypatch.setattr(pcap_scanner, "PUREPY_MAX_BYTES", 10)
    out = scan(KIT)
    assert findings(out) == [] and len(errors(out)) == 1 and "too large" in errors(out)[0].message


# --- never raises -------------------------------------------------------------------------------


def _boom(*args, **kwargs):
    raise RuntimeError("boom " + str(KIT))


def test_parser_raising_yields_scan_error(no_tshark, monkeypatch):
    monkeypatch.setattr(purepy, "read_flows", _boom)
    out = scan(KIT)
    assert findings(out) == []
    assert [e.message for e in errors(out)] == ["pcap scan failed: RuntimeError"]


def test_tshark_raising_yields_scan_error(with_tshark, monkeypatch):
    monkeypatch.setattr(tshark, "read_flows_tshark", _boom)
    out = scan(KIT)
    assert findings(out) == [] and errors(out)


@pytest.mark.parametrize(("module", "label"), [(tls_session, "tls"), (ssh, "ssh"), (plaintext, "plaintext")])
def test_one_failing_builder_keeps_the_others(parser, monkeypatch, module, label):
    monkeypatch.setattr(module, "build_findings", _boom)
    out = scan(KIT)
    assert [e.message for e in errors(out)] == [f"{label} findings failed: RuntimeError"]
    assert findings(out)
    assert all(str(KIT) not in e.message for e in errors(out))


def test_relative_path_failure_does_not_raise(parser, monkeypatch):
    monkeypatch.setattr(tls_session, "relative_posix", _boom)
    out = scan(KIT)
    assert errors(out) == [] and {f.location.file for f in findings(out)} == {"network.pcap"}


# --- no network ---------------------------------------------------------------------------------


def test_scan_opens_no_sockets(parser, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network access during scan")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    assert errors(scan(KIT)) == []


# --- damaged and unusual captures: never an empty success ------------------------------------------


@pytest.mark.parametrize("size", [1, 4, 23])
def test_file_shorter_than_a_capture_header_is_an_error(parser, tmp_path, size):
    p = tmp_path / "s.pcap"
    p.write_bytes(b"\x07" * size)
    out = scan(p)
    assert findings(out) == []
    assert [e.message for e in errors(out)] == ["file is too short to be a capture"]


def test_unsupported_linktype_is_an_error_even_when_tshark_reads_it_cleanly(parser, tmp_path):
    data = KIT.read_bytes()
    p = tmp_path / "l.pcap"
    p.write_bytes(data[:20] + bytes([19]) + data[21:])
    out = scan(p)
    assert findings(out) == []
    assert [e.message for e in errors(out)] == [
        "unsupported linktype 19 (Ethernet, Linux SLL/SLL2, raw IP and loopback only)"
    ]


def test_valid_capture_without_packets_is_not_an_error(parser, tmp_path):
    p = tmp_path / "h.pcap"
    p.write_bytes(KIT.read_bytes()[:24])
    out = scan(p)
    assert out == []


@pytest.mark.parametrize("extra", [1, 10, 15])
def test_partial_packet_header_at_the_end_is_reported(parser, tmp_path, extra):
    p = tmp_path / "t.pcap"
    p.write_bytes(KIT.read_bytes()[:24] + b"\x00" * extra)
    out = scan(p)
    assert findings(out) == []
    assert "truncated packet header at end of file" in [e.message for e in errors(out)]


def test_tshark_clean_run_without_flows_is_checked_against_the_builtin_parser(with_tshark, monkeypatch):
    monkeypatch.setattr(tshark, "read_flows_tshark", lambda path, timeout=0: PureResult())
    out = scan(KIT)
    assert [e.message for e in errors(out)] == [
        "parsers disagree on tls flows: tshark 0, built-in parser 97; tshark result used",
        "parsers disagree on ssh flows: tshark 0, built-in parser 24; tshark result used",
        "parsers disagree on plaintext flows: tshark 0, built-in parser 14; tshark result used",
    ]
    assert findings(out) == []


def test_reused_four_tuples_agree_between_parsers(with_tshark, tmp_path):
    if not HAS_TSHARK:
        pytest.skip("tshark not installed")
    data = KIT.read_bytes()
    p = tmp_path / "twice.pcap"
    p.write_bytes(data + data[24:])
    out = scan(p)
    assert errors(out) == []
    assert len({f.session_id for f in findings(out) if f.session_id}) == 2 * (97 + 24)
