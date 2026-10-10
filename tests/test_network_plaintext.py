"""plaintext.py: Flow to PLAINTEXT Finding conversion, on the starter kit through both parsers and
on hand-built flows for the cases the kit does not contain."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from quantumtrace.models import Finding, KindHint, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id
from quantumtrace.scanners.network import plaintext, purepy, ssh, tls_session, tshark
from quantumtrace.scanners.network.purepy import Flow, HttpInfo, PureResult

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "network-capture" / "network.pcap"
FILE = "network.pcap"
FORBIDDEN_KEYS = {"tier", "verdict", "verdict_tier", "pq_status", "threat", "score", "risk_points"}


def parsers():
    out = ["purepy"]
    if shutil.which("tshark"):
        out.append("tshark")
    return out


@pytest.fixture(scope="module", params=parsers())
def kit(request):
    result = purepy.read_flows(KIT) if request.param == "purepy" else tshark.read_flows_tshark(KIT)
    assert result.errors == []
    out = plaintext.build_findings(result, FILE)
    return {
        "parser": request.param,
        "findings": [x for x in out if isinstance(x, Finding)],
        "errors": [x for x in out if isinstance(x, ScanError)],
    }


# --- kit -------------------------------------------------------------------------------------


def test_kit_has_14_plaintext_flows_and_no_errors(kit):
    assert len(kit["findings"]) == 14
    assert kit["errors"] == []
    assert len({f.id for f in kit["findings"]}) == 14


def test_kit_findings_follow_the_agreed_contract(kit):
    for f in kit["findings"]:
        assert f.kind_hint == KindHint.PLAINTEXT and f.raw_name == "HTTP" and f.protocol == "http"
        assert f.usage == Usage.UNKNOWN and f.negotiated is None and f.session_id is None
        assert f.detector == "pcap.plaintext.http" and f.confidence == 1.0
        assert f.location.source_type == SourceType.PCAP
        assert f.location.file == FILE and f.location.sni is None
        assert f.location.flow.endswith(":80") and "->" in f.location.flow
        assert f.location.frame is not None
        assert f.id == finding_id(f.detector, f.raw_name, f.location)
        assert set(f.extra) == {"hygiene_only", "http"} and f.extra["hygiene_only"] is True
        assert "hygiene_flags" not in f.extra
        assert not FORBIDDEN_KEYS & set(f.extra) and not FORBIDDEN_KEYS & set(f.extra["http"])


def test_kit_http_evidence(kit):
    for f in kit["findings"]:
        http = f.extra["http"]
        assert tuple(http) == plaintext.HTTP_KEYS
        assert http["method"] == "GET" and http["path"] == "/status"
        assert http["host"].startswith("intranet") and http["host"].endswith(".lab")
        assert http["server"] == "Apache/2.4.58" and http["status"] == 200


def test_kit_findings_serialise_to_json(kit):
    json.dumps([f.model_dump(mode="json") for f in kit["findings"]])


def test_both_parsers_give_identical_findings():
    if shutil.which("tshark") is None:
        pytest.skip("tshark not installed")
    a = plaintext.build_findings(purepy.read_flows(KIT), FILE)
    b = plaintext.build_findings(tshark.read_flows_tshark(KIT), FILE)
    assert len(a) == len(b) == 14
    assert [f.model_dump() for f in a] == [f.model_dump() for f in b]


def test_output_is_deterministic():
    first = plaintext.build_findings(purepy.read_flows(KIT), FILE)
    second = plaintext.build_findings(purepy.read_flows(KIT), FILE)
    assert first == second


def test_builders_split_the_flows_of_one_result():
    result = purepy.read_flows(KIT)
    tls_out = tls_session.build_findings(result, FILE)
    ssh_out = ssh.build_findings(result, FILE, parser_errors=False)
    plain_out = plaintext.build_findings(result, FILE, parser_errors=False)
    ids = [f.id for out in (tls_out, ssh_out, plain_out) for f in out if isinstance(f, Finding)]
    assert len(ids) == len(set(ids))
    assert sum(isinstance(f, Finding) for f in plain_out) == 14
    assert not any(f.session_id for f in plain_out if isinstance(f, Finding))


# --- synthetic flows ---------------------------------------------------------------------------


def http_flow(*, info=None, client=("10.0.0.1", 50000), server=("10.0.0.2", 80), stream=4):
    flow = Flow(stream, client, server, 0.0)
    flow.kind = "http"
    flow.http = info or HttpInfo("GET", "/x", host="a.lab", server="srv", status=301, frame=7)
    return flow


def run(*flows):
    res = PureResult()
    res.flows = list(flows)
    out = plaintext.build_findings(res, FILE)
    return (
        [x for x in out if isinstance(x, Finding)],
        [x for x in out if isinstance(x, ScanError)],
    )


def test_request_without_response_has_no_server_or_status():
    findings, errors = run(http_flow(info=HttpInfo("POST", "/login", host="a.lab", frame=9)))
    assert errors == []
    assert findings[0].extra["http"] == {
        "method": "POST",
        "path": "/login",
        "host": "a.lab",
        "server": None,
        "status": None,
    }
    assert findings[0].location.frame == 9


def test_redirect_status_is_a_plain_fact_with_no_flag():
    findings, _ = run(http_flow())
    assert findings[0].extra["http"]["status"] == 301
    assert set(findings[0].extra) == {"hygiene_only", "http"}


def test_non_standard_port_is_still_a_plaintext_http_flow():
    findings, _ = run(http_flow(server=("10.0.0.2", 8080)))
    assert findings[0].location.flow == "10.0.0.1:50000->10.0.0.2:8080"


def test_ipv6_flow_text_is_bracketed():
    findings, _ = run(http_flow(client=("2001:db8::1", 50000), server=("2001:db8::2", 80)))
    assert findings[0].location.flow == "[2001:db8::1]:50000->[2001:db8::2]:80"


@pytest.mark.parametrize(
    "upgrade", ["smtp-starttls", "imap-starttls", "postgres-sslrequest", "unknown-starttls"]
)
def test_unanswered_upgrade_is_an_error_and_never_a_finding(upgrade):
    flow = Flow(2, ("10.0.0.1", 50000), ("10.0.0.2", 587), 0.0)
    flow.kind, flow.upgrade_request = "plaintext", upgrade
    findings, errors = run(flow)
    assert findings == []
    assert len(errors) == 1
    assert errors[0].message.startswith("stream 2 10.0.0.1:50000->10.0.0.2:587:")
    assert upgrade in errors[0].message and "no plaintext finding" in errors[0].message
    assert errors[0].path == FILE


def test_flow_warnings_become_errors_naming_the_stream():
    flow = http_flow()
    flow.warnings.append("client-to-server stream has a gap; evidence partial")
    findings, errors = run(flow)
    assert len(findings) == 1
    assert errors[0].message == (
        "stream 4 10.0.0.1:50000->10.0.0.2:80: client-to-server stream has a gap; evidence partial"
    )


def test_other_flow_kinds_are_ignored_here():
    tls = Flow(0, ("10.0.0.1", 1), ("10.0.0.2", 443), 0.0)
    tls.kind = "tls"
    other = Flow(1, ("10.0.0.1", 2), ("10.0.0.2", 22), 0.0)
    other.kind = "ssh"
    assert run(tls, other) == ([], [])


def test_parser_errors_are_reported_once_when_asked_to():
    res = PureResult()
    res.errors.append("capture is truncated; evidence may be partial")
    assert [type(x) for x in plaintext.build_findings(res, FILE)] == [ScanError]
    assert plaintext.build_findings(res, FILE, parser_errors=False) == []


def test_findings_are_in_stream_order():
    findings, _ = run(http_flow(stream=9), http_flow(stream=2, client=("10.0.0.1", 50001)))
    assert [f.location.flow for f in findings] == [
        "10.0.0.1:50001->10.0.0.2:80",
        "10.0.0.1:50000->10.0.0.2:80",
    ]
