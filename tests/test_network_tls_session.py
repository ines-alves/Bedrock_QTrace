"""tls_session.py: Flow to Finding conversion, on the starter kit through both parsers and on
hand-built flows for the cases the kit does not contain."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from quantumtrace.models import Finding, KindHint, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id
from quantumtrace.scanners.network import purepy, registry, tls_session, tshark
from quantumtrace.scanners.network.purepy import Flow, PureResult, TlsHello

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "network-capture" / "network.pcap"
FILE = "network.pcap"

SESSION_KEYS = {
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
}
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
    out = tls_session.build_findings(result, FILE)
    findings = [x for x in out if isinstance(x, Finding)]
    return {
        "parser": request.param,
        "all": out,
        "findings": findings,
        "errors": [x for x in out if isinstance(x, ScanError)],
        "sessions": [x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION],
    }


def by_session(findings):
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.session_id, []).append(f)
    return groups


# --- kit: counts and profiles (PLAN D.2) ----------------------------------------------------


def test_kit_has_97_sessions_and_no_errors(kit):
    assert len(kit["sessions"]) == 97
    assert len({s.session_id for s in kit["sessions"]}) == 97
    assert kit["errors"] == []


def test_kit_ids_are_unique(kit):
    ids = [f.id for f in kit["findings"]]
    assert len(ids) == len(set(ids))


def test_kit_profiles(kit):
    profiles = Counter()
    for s in kit["sessions"]:
        sess = s.extra["session"]
        profiles[
            (
                sess["version"],
                sess["negotiated_cipher_suite"],
                sess["negotiated_group"],
                tuple(sess["offered_cipher_suites"]),
            )
        ] += 1
    assert profiles == {
        ("TLS 1.2", "0x002F", None, ("0x0035", "0x002F")): 54,
        ("TLS 1.3", "0x1301", "0x001D", ("0x1301", "0x1302", "0x1303")): 36,
        ("TLS 1.3", "0x1302", "0x11EC", ("0x1301", "0x1302", "0x1303")): 7,
    }


def test_kit_service_labels(kit):
    assert Counter(s.extra["session"]["service"] for s in kit["sessions"]) == {
        "https": 58,
        "smtp-starttls": 11,
        "ldaps": 10,
        "imaps": 10,
        "postgres": 8,
    }


def test_kit_authentication_is_not_observable_and_certificate_state_is_set(kit):
    assert all(s.extra["authentication_observable"] is False for s in kit["sessions"])
    states = Counter((s.extra["session"]["version"], s.extra["certificate_state"]) for s in kit["sessions"])
    assert states == {("TLS 1.2", "absent"): 54, ("TLS 1.3", "encrypted"): 43}
    assert all(s.extra["session"]["cert_key"] is None for s in kit["sessions"])  # never guessed


def test_kit_hybrid_session_findings(kit):
    hybrid = next(s for s in kit["sessions"] if s.extra["session"]["negotiated_group"] == "0x11EC")
    members = by_session(kit["findings"])[hybrid.session_id]
    groups = [f for f in members if f.kind_hint == KindHint.GROUP]
    assert [(g.raw_name, g.negotiated) for g in groups] == [
        ("0x11EC", False),
        ("0x001D", False),
        ("0x11EC", True),
    ]
    offered, selected = groups[0], groups[-1]
    assert offered.location.frame < selected.location.frame  # ClientHello before ServerHello
    assert selected.extra == {"codepoint": "0x11EC", "iana_name": "X25519MLKEM768"}
    assert all(g.usage == Usage.KEY_EXCHANGE for g in groups)
    assert hybrid.extra["session"]["sni"] == "vault01.lab"
    assert all(f.location.sni == "vault01.lab" for f in members)


def test_kit_static_rsa_has_no_negotiated_group(kit):
    legacy = next(s for s in kit["sessions"] if s.extra["session"]["version"] == "TLS 1.2")
    members = by_session(kit["findings"])[legacy.session_id]
    assert not [f for f in members if f.kind_hint == KindHint.GROUP and f.negotiated]
    suites = [f for f in members if f.kind_hint == KindHint.CIPHER_SUITE]
    assert [(f.raw_name, f.negotiated) for f in suites] == [
        ("0x0035", False),
        ("0x002F", False),
        ("0x002F", True),
    ]
    assert suites[-1].extra["iana_name"] == "TLS_RSA_WITH_AES_128_CBC_SHA"


def test_negotiated_is_true_only_for_selections(kit):
    for members in by_session(kit["findings"]).values():
        negotiated = [f for f in members if f.negotiated]
        kinds = Counter(f.kind_hint for f in negotiated)
        assert kinds[KindHint.PROTOCOL_VERSION] == 1
        assert kinds[KindHint.CIPHER_SUITE] == 1
        assert kinds[KindHint.GROUP] <= 1
        assert kinds[KindHint.SIGNATURE_SCHEME] == 0  # TLS 1.3 selection is encrypted; never guessed
    assert all(f.negotiated is not None for f in kit["findings"])


def test_offered_lists_keep_client_order(kit):
    for sid, members in by_session(kit["findings"]).items():
        session = next(f for f in members if f.kind_hint == KindHint.PROTOCOL_VERSION).extra["session"]
        offered_suites = [
            f.raw_name for f in members if f.kind_hint == KindHint.CIPHER_SUITE and not f.negotiated
        ]
        offered_groups = [f.raw_name for f in members if f.kind_hint == KindHint.GROUP and not f.negotiated]
        offered_sigs = [f.raw_name for f in members if f.kind_hint == KindHint.SIGNATURE_SCHEME]
        assert offered_suites == session["offered_cipher_suites"]
        assert offered_groups == session["offered_groups"]
        assert offered_sigs == session["offered_sig_schemes"]


# --- kit: contract --------------------------------------------------------------------------


def test_every_finding_follows_the_evidence_contract(kit):
    for f in kit["findings"]:
        assert f.location.source_type == SourceType.PCAP
        assert f.location.file == "network.pcap"
        assert f.location.flow and f.location.frame
        assert f.location.sni
        assert f.session_id and f.protocol in {"TLS 1.2", "TLS 1.3"}
        assert set(f.extra) >= {"codepoint", "iana_name"}
        assert not FORBIDDEN_KEYS & set(f.extra)
        if f.kind_hint != KindHint.PROTOCOL_VERSION:
            assert f.raw_name.startswith("0x") and f.raw_name == f.raw_name.upper().replace("0X", "0x")
            assert f.raw_name == f.extra["codepoint"]
        assert Finding.model_validate(f.model_dump()) == f
        assert f.id == finding_id(f.detector, f.raw_name, f.location)


def test_session_evidence_has_exactly_the_agreed_keys(kit):
    for s in kit["sessions"]:
        sess = s.extra["session"]
        assert set(sess) == SESSION_KEYS
        assert sess["transport"] == "tls" and sess["peer_banners"] is None
        assert s.usage == Usage.UNKNOWN and s.negotiated is True and s.raw_name == sess["version"]
        assert set(s.extra) == {
            "codepoint",
            "iana_name",
            "session",
            "authentication_observable",
            "certificate_state",
        }
    assert sum("session" in f.extra for f in kit["findings"]) == 97  # only the session finding


def test_no_grease_or_signalling_codepoint_is_reported(kit):
    for f in kit["findings"]:
        if f.kind_hint in (KindHint.CIPHER_SUITE, KindHint.GROUP, KindHint.SIGNATURE_SCHEME):
            code = int(f.raw_name, 16)
            assert not registry.is_grease(code)
            assert code not in registry.SIGNALLING_SUITES


def test_output_is_deterministic(kit):
    again = tls_session.build_findings(
        purepy.read_flows(KIT) if kit["parser"] == "purepy" else tshark.read_flows_tshark(KIT), FILE
    )
    dump = lambda items: json.dumps([x.model_dump(mode="json") for x in items], sort_keys=True)  # noqa: E731
    assert dump(again) == dump(kit["all"])


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_both_parsers_give_identical_findings():
    a = tls_session.build_findings(purepy.read_flows(KIT), FILE)
    b = tls_session.build_findings(tshark.read_flows_tshark(KIT), FILE)
    assert [x.model_dump() for x in a] == [x.model_dump() for x in b]


def test_known_session_id_is_stable():
    flow = "192.0.2.10:49178->192.0.2.37:443"
    assert tls_session.session_id("pcap", FILE, flow, 404) == "bca11cfc1da2"
    assert tls_session.session_id("ssh", FILE, flow, 404) != "bca11cfc1da2"


# --- hand-built flows -----------------------------------------------------------------------


def hello(
    msg_type, *, suites=(), groups=(), sigs=(), sni=None, versions=(), selected_group=None, frame=1, hrr=False
):
    h = TlsHello(msg_type, 0x0303, 0x0303, bytes(32))
    h.cipher_suites = list(suites)
    h.supported_groups = list(groups)
    h.signature_algorithms = list(sigs)
    h.supported_versions = list(versions)
    h.sni = sni
    h.selected_group = selected_group
    h.frame = frame
    h.hello_retry_request = hrr
    return h


def make_flow(*, ch=None, sh=None, stream=0, server=("10.0.0.2", 443), client=("10.0.0.1", 50000), **kw):
    flow = Flow(stream, client, server, 0.0, kind="tls", client_hello=ch, server_hello=sh)
    for key, value in kw.items():
        setattr(flow, key, value)
    return flow


def convert(*flows, errors=()):
    res = PureResult(flows=list(flows), errors=list(errors))
    out = tls_session.build_findings(res, "cap/x.pcap")
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, ScanError)]


def test_suite_and_group_with_the_same_code_do_not_collide():
    ch = hello(1, suites=[0x0017], groups=[0x0017], sigs=[0x0201], sni="c.lab", frame=5)
    sh = hello(2, suites=[0xC02F], frame=7)
    findings, errors = convert(make_flow(ch=ch, sh=sh))
    assert errors == []
    same = [f for f in findings if f.raw_name == "0x0017"]
    assert {f.kind_hint for f in same} == {KindHint.CIPHER_SUITE, KindHint.GROUP}
    assert len({f.id for f in findings}) == len(findings)
    # 0x0201 resolves in the signature scheme namespace only
    sig = next(f for f in findings if f.kind_hint == KindHint.SIGNATURE_SCHEME)
    assert sig.extra["iana_name"] == "rsa_pkcs1_sha1"


def test_ecdhe_group_uses_the_server_key_exchange_frame():
    ch = hello(1, suites=[0xC02F], groups=[0x0017], sni="e.lab", frame=3)
    sh = hello(2, suites=[0xC02F], frame=5)
    flow = make_flow(ch=ch, sh=sh, server_key_exchange_group=0x0017, server_key_exchange_frame=6)
    findings, _ = convert(flow)
    chosen = next(f for f in findings if f.kind_hint == KindHint.GROUP and f.negotiated)
    assert (chosen.raw_name, chosen.location.frame) == ("0x0017", 6)
    suite = next(f for f in findings if f.kind_hint == KindHint.CIPHER_SUITE and f.negotiated)
    assert suite.location.frame == 5
    session = next(f for f in findings if f.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["session"]["negotiated_group"] == "0x0017"
    assert session.location.frame == 3 and session.protocol == "TLS 1.2"


def test_parsed_certificate_makes_authentication_observable_but_never_guesses_a_key():
    ch = hello(1, suites=[0xC02B], frame=3)
    sh = hello(2, suites=[0xC02B], frame=5)
    flow = make_flow(ch=ch, sh=sh, server_certificate_msg=b"\x00\x00\x00", certificate_frame=5)
    findings, _ = convert(flow)
    session = findings[0]
    assert session.extra["authentication_observable"] is True
    assert session.extra["certificate_state"] == "observed"
    assert session.extra["session"]["cert_key"] is None and session.extra["session"]["cert_sig_alg"] is None


def test_unknown_codepoints_keep_hex_and_a_null_name():
    ch = hello(1, suites=[0xBEEF], groups=[0xBEE0], frame=1)
    sh = hello(2, suites=[0xBEEF], frame=2)
    findings, _ = convert(make_flow(ch=ch, sh=sh))
    unknown = [f for f in findings if f.kind_hint != KindHint.PROTOCOL_VERSION]
    assert {f.raw_name for f in unknown} == {"0xBEEF", "0xBEE0"}
    assert all(f.extra["iana_name"] is None for f in unknown)


def test_duplicate_codes_are_emitted_once_but_kept_in_the_session_list():
    ch = hello(1, suites=[0x1301, 0x1301, 0x1302], frame=1)
    sh = hello(2, suites=[0x1301], frame=2)
    findings, _ = convert(make_flow(ch=ch, sh=sh))
    assert [f.raw_name for f in findings if f.kind_hint == KindHint.CIPHER_SUITE and not f.negotiated] == [
        "0x1301",
        "0x1302",
    ]
    assert findings[0].extra["session"]["offered_cipher_suites"] == ["0x1301", "0x1301", "0x1302"]


def test_unknown_version_keeps_its_hex_spelling():
    ch = hello(1, suites=[0x1301], frame=1)
    sh = hello(2, suites=[0x1301], frame=2)
    sh.legacy_version = 0x7F1C
    findings, _ = convert(make_flow(ch=ch, sh=sh))
    assert findings[0].raw_name == "0x7F1C" and findings[0].extra["codepoint"] == "0x7F1C"


def test_client_hello_without_server_hello_records_offers_but_no_session():
    ch = hello(1, suites=[0x1301], groups=[0x11EC], frame=4)
    findings, errors = convert(make_flow(ch=ch))
    assert [f.negotiated for f in findings] == [False, False]
    assert not [f for f in findings if f.kind_hint == KindHint.PROTOCOL_VERSION]
    assert len(errors) == 1 and "ClientHello without a ServerHello" in errors[0].message


def test_server_hello_without_client_hello_is_partial_and_anchored_on_the_server_hello():
    sh = hello(2, suites=[0x1301], versions=[0x0304], selected_group=0x001D, frame=9)
    findings, errors = convert(make_flow(sh=sh))
    session = findings[0]
    assert session.session_id == tls_session.session_id(
        "pcap", "cap/x.pcap", "10.0.0.1:50000->10.0.0.2:443", 9
    )
    assert session.extra["session"]["offered_cipher_suites"] is None
    assert session.extra["session"]["sni"] is None
    assert len(errors) == 1 and "without a ClientHello" in errors[0].message


def test_hello_retry_request_alone_negotiates_nothing():
    ch = hello(1, suites=[0x1301], groups=[0x11EC, 0x001D], versions=[0x0304], frame=1)
    hrr = hello(2, suites=[0x1301], versions=[0x0304], selected_group=0x11EC, frame=2, hrr=True)
    findings, errors = convert(make_flow(ch=ch, sh=hrr, hello_retry_request=True))
    assert not [f for f in findings if f.negotiated]  # including the session finding
    assert len(errors) == 1 and "HelloRetryRequest" in errors[0].message


def test_flow_warnings_and_parser_errors_become_scan_errors_naming_the_stream():
    ch = hello(1, suites=[0x1301], frame=1)
    sh = hello(2, suites=[0x1301], frame=2)
    flow = make_flow(ch=ch, sh=sh, stream=17, warnings=["more than one ClientHello in the stream"])
    res = PureResult(flows=[flow], errors=["unsupported linktype 113"])
    out = tls_session.build_findings(res, "cap/x.pcap")
    assert isinstance(out[0], ScanError) and out[0].message == "unsupported linktype 113"
    assert out[0].path == "cap/x.pcap" and out[0].detector == "pcap"
    warn = [x for x in out if isinstance(x, ScanError)][-1]
    assert "stream 17" in warn.message and "10.0.0.1:50000->10.0.0.2:443" in warn.message


def test_ipv6_flow_text_is_bracketed():
    ch = hello(1, suites=[0x1301], frame=1)
    sh = hello(2, suites=[0x1301], frame=2)
    flow = make_flow(ch=ch, sh=sh, client=("2001:db8::1", 50000), server=("2001:db8::2", 443))
    findings, _ = convert(flow)
    assert findings[0].location.flow == "[2001:db8::1]:50000->[2001:db8::2]:443"


def test_non_tls_flows_are_ignored_here():
    other = Flow(3, ("10.0.0.1", 1), ("10.0.0.2", 22), 0.0, kind="ssh")
    assert convert(other) == ([], [])


# --- service label and file helper ----------------------------------------------------------


@pytest.mark.parametrize(
    "port, upgrade, label",
    [
        (443, None, "https"),
        (636, None, "ldaps"),
        (993, None, "imaps"),
        (587, "smtp-starttls", "smtp-starttls"),
        (25, None, "smtp-starttls"),
        (5432, "postgres-sslrequest", "postgres"),
        (2525, "smtp-starttls", "smtp-starttls"),  # evidence wins over the port
        (8443, None, "other"),
        (143, "imap-starttls", "other"),
    ],
)
def test_service_label(port, upgrade, label):
    flow = make_flow(server=("10.0.0.2", port), upgrade_request=upgrade)
    assert tls_session.service_label(flow) == label


def test_relative_posix_paths(tmp_path):
    nested = tmp_path / "caps" / "lab" / "a.pcap"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"")
    assert tls_session.relative_posix(nested, tmp_path) == "caps/lab/a.pcap"
    assert tls_session.relative_posix(nested) == "a.pcap"  # single capture: parent is the root
    assert tls_session.relative_posix(nested, nested) == "a.pcap"
    assert tls_session.relative_posix(nested, tmp_path / "elsewhere") == "a.pcap"
    assert "\\" not in tls_session.relative_posix(nested, tmp_path)
