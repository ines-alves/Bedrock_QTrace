"""ssh.py: Flow to Finding conversion, on the starter kit through both parsers and on hand-built
flows for the cases the kit does not contain."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from quantumtrace.models import Finding, KindHint, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id
from quantumtrace.scanners.network import purepy, ssh, tls_session, tshark
from quantumtrace.scanners.network.purepy import Flow, PureResult, SshSide

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "network-capture" / "network.pcap"
FILE = "network.pcap"

FORBIDDEN_KEYS = {"tier", "verdict", "verdict_tier", "pq_status", "threat", "score", "risk_points"}
LEGACY_PEERS = ["SSH-2.0-PuTTY_Release_0.76", "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"]
MODERN_PEERS = ["SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1"]


def parsers():
    out = ["purepy"]
    if shutil.which("tshark"):
        out.append("tshark")
    return out


@pytest.fixture(scope="module", params=parsers())
def kit(request):
    result = purepy.read_flows(KIT) if request.param == "purepy" else tshark.read_flows_tshark(KIT)
    assert result.errors == []
    out = ssh.build_findings(result, FILE)
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


def names(findings, detector, negotiated):
    return [f.raw_name for f in findings if f.detector == detector and f.negotiated is negotiated]


def peers(finding):
    return finding.extra["session"]["peer_banners"]


# --- kit: counts and profiles (PLAN D.3) -------------------------------------------------------


def test_kit_has_24_ssh_sessions_and_no_errors(kit):
    assert len(kit["sessions"]) == 24
    assert kit["errors"] == []
    assert len(by_session(kit["findings"])) == 24


def test_kit_ids_are_unique(kit):
    ids = [f.id for f in kit["findings"]]
    assert len(ids) == len(set(ids))
    for f in kit["findings"]:
        assert f.id == finding_id(f.detector, f.raw_name, f.location)


def test_kit_has_14_legacy_and_10_modern_sessions(kit):
    profiles = Counter(tuple(peers(s)) for s in kit["sessions"])
    assert profiles == {tuple(LEGACY_PEERS): 14, tuple(MODERN_PEERS): 10}


def test_kit_legacy_profile(kit):
    groups = by_session(kit["findings"])
    legacy = [s for s in kit["sessions"] if peers(s) == LEGACY_PEERS]
    assert len(legacy) == 14
    for s in legacy:
        group = groups[s.session_id]
        assert names(group, ssh.DETECTOR_KEX, False) == [
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group1-sha1",
        ]
        assert names(group, ssh.DETECTOR_KEX, True) == ["diffie-hellman-group14-sha1"]
        assert names(group, ssh.DETECTOR_HOST_KEY, False) == ["ssh-rsa"]
        assert names(group, ssh.DETECTOR_HOST_KEY, True) == ["ssh-rsa"]
        assert names(group, ssh.DETECTOR_CIPHER, False) == ["aes128-cbc", "3des-cbc"]
        assert names(group, ssh.DETECTOR_CIPHER, True) == ["aes128-cbc"]
        assert names(group, ssh.DETECTOR_MAC, False) == ["hmac-sha1"]
        assert names(group, ssh.DETECTOR_MAC, True) == ["hmac-sha1"]
        session = s.extra["session"]
        assert session["negotiated_group"] == "diffie-hellman-group14-sha1"
        assert session["cert_key"] == "ssh-rsa"
        assert session["negotiated_cipher_suite"] == "aes128-cbc"


def test_kit_modern_profile(kit):
    groups = by_session(kit["findings"])
    modern = [s for s in kit["sessions"] if peers(s) == MODERN_PEERS]
    assert len(modern) == 10
    for s in modern:
        group = groups[s.session_id]
        assert names(group, ssh.DETECTOR_KEX, False) == [
            "curve25519-sha256",
            "diffie-hellman-group16-sha512",
        ]
        assert names(group, ssh.DETECTOR_KEX, True) == ["curve25519-sha256"]
        assert names(group, ssh.DETECTOR_HOST_KEY, False) == ["rsa-sha2-512", "ssh-ed25519"]
        assert names(group, ssh.DETECTOR_HOST_KEY, True) == ["rsa-sha2-512"]
        assert names(group, ssh.DETECTOR_CIPHER, True) == ["chacha20-poly1305@openssh.com"]
        assert names(group, ssh.DETECTOR_CIPHER, False) == [
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
        ]
        # ChaCha20-Poly1305 carries its own authentication: the MAC stays an offer (M1M2-06)
        assert names(group, ssh.DETECTOR_MAC, True) == []
        assert names(group, ssh.DETECTOR_MAC, False) == ["hmac-sha2-256-etm@openssh.com"]


def test_kit_offers_no_post_quantum_kex(kit):
    pq = {"mlkem768x25519-sha256", "sntrup761x25519-sha512"}
    assert not pq & {f.raw_name for f in kit["findings"]}


def test_kit_findings_follow_the_evidence_contract(kit):
    for f in kit["findings"]:
        assert f.location.source_type == SourceType.SSH
        assert f.location.file == FILE and "\\" not in f.location.file
        assert f.location.flow and "->" in f.location.flow and f.location.flow.endswith(":22")
        assert f.location.frame is not None and f.location.sni is None
        assert f.protocol == "SSH-2.0"
        assert f.detector.startswith("pcap.ssh.")
        assert "codepoint" not in f.extra and "iana_name" not in f.extra
        if f.kind_hint != KindHint.PROTOCOL_VERSION:
            # the kit agrees in both directions, so no finding is direction-specific
            assert f.kind_hint == KindHint.ALGORITHM and f.extra == {}


def test_kit_usages(kit):
    expected = {
        ssh.DETECTOR_KEX: Usage.KEY_EXCHANGE,
        ssh.DETECTOR_HOST_KEY: Usage.SIGNATURE,
        ssh.DETECTOR_CIPHER: Usage.ENCRYPTION,
        ssh.DETECTOR_MAC: Usage.MAC,
    }
    for f in kit["findings"]:
        if f.detector in expected:
            assert f.usage == expected[f.detector]
        else:
            assert f.usage == Usage.UNKNOWN


def test_kit_frames_are_the_kexinit_ends(kit):
    groups = by_session(kit["findings"])
    for s in kit["sessions"]:
        frames = {(f.negotiated, f.location.frame) for f in groups[s.session_id] if f is not s}
        client_frame, server_frame = s.location.frame, None
        server_frames = {frame for neg, frame in frames if neg}
        offered_frames = {frame for neg, frame in frames if not neg}
        assert offered_frames == {client_frame}
        assert len(server_frames) == 1
        server_frame = server_frames.pop()
        assert server_frame > client_frame


def test_kit_session_evidence_has_exactly_the_agreed_keys(kit):
    for s in kit["sessions"]:
        assert s.negotiated is True and s.usage == Usage.UNKNOWN and s.raw_name == "SSH-2.0"
        assert tuple(s.extra["session"]) == ssh.SESSION_KEYS
        assert len(s.extra["session"]) == 13
        assert s.extra["session"]["transport"] == "ssh"
        assert s.extra["session"]["service"] == "ssh"
        assert s.extra["session"]["sni"] is None and s.extra["session"]["cert_sig_alg"] is None
        assert s.extra["authentication_observable"] is True  # selection from both KEXINITs (M1M2-07)
        assert "certificate_state" not in s.extra
        assert set(s.extra) == {"session", "authentication_observable"}
        assert not FORBIDDEN_KEYS & set(s.extra) and not FORBIDDEN_KEYS & set(s.extra["session"])


def test_kit_findings_serialise_to_json(kit):
    json.dumps([f.model_dump(mode="json") for f in kit["findings"]])


def test_kit_output_is_deterministic():
    first = ssh.build_findings(purepy.read_flows(KIT), FILE)
    second = ssh.build_findings(purepy.read_flows(KIT), FILE)
    assert first == second
    streams = [f.location.flow for f in first if isinstance(f, Finding)]
    assert streams == sorted(streams, key=streams.index)  # grouped per flow, stream order


def test_both_parsers_give_identical_findings():
    if shutil.which("tshark") is None:
        pytest.skip("tshark not installed")
    a = ssh.build_findings(purepy.read_flows(KIT), FILE)
    b = ssh.build_findings(tshark.read_flows_tshark(KIT), FILE)
    assert len(a) == len(b) > 0
    assert [f.model_dump() for f in a] == [f.model_dump() for f in b]


def test_known_session_id_is_stable():
    result = purepy.read_flows(KIT)
    sessions = [
        f
        for f in ssh.build_findings(result, FILE)
        if isinstance(f, Finding) and f.kind_hint == KindHint.PROTOCOL_VERSION
    ]
    first = sessions[0]
    expected = tls_session.session_id("ssh", FILE, first.location.flow, first.location.frame)
    assert first.session_id == expected and len(expected) == 12
    assert first.location.frame == 10  # client KEXINIT of stream 0


def test_tls_and_ssh_builders_split_the_flows_of_one_result():
    result = purepy.read_flows(KIT)
    tls_out = tls_session.build_findings(result, FILE)
    ssh_out = ssh.build_findings(result, FILE)
    tls_sessions = {f.session_id for f in tls_out if isinstance(f, Finding)}
    ssh_sessions = {f.session_id for f in ssh_out if isinstance(f, Finding)}
    assert len(tls_sessions) == 97 and len(ssh_sessions) == 24
    assert not tls_sessions & ssh_sessions


def test_parser_errors_are_reported_once_when_asked_to():
    res = PureResult()
    res.errors.append("capture is truncated; evidence may be partial")
    assert [type(x) for x in ssh.build_findings(res, FILE)] == [ScanError]
    assert ssh.build_findings(res, FILE, parser_errors=False) == []


# --- synthetic flows ------------------------------------------------------------------------


def side(banner="SSH-2.0-test", *, frame=10, kex=None, host=None, enc=None, mac=None, **over):
    s = SshSide(banner=banner, frame=frame)
    if kex is not None:
        s.has_kexinit = True
        s.kex = kex
        s.host_key = host or []
        s.enc_c2s = s.enc_s2c = enc or []
        s.mac_c2s = s.mac_s2c = mac or []
    for key, value in over.items():
        setattr(s, key, value)
    return s


def flow_of(client, server, *, client_addr=("10.0.0.1", 50000), server_addr=("10.0.0.2", 22)):
    f = Flow(3, client_addr, server_addr, 0.0)
    f.kind, f.ssh_client, f.ssh_server = "ssh", client, server
    return f


def run(flow):
    res = PureResult()
    res.flows = [flow]
    out = ssh.build_findings(res, FILE)
    return (
        [x for x in out if isinstance(x, Finding)],
        [x for x in out if isinstance(x, ScanError)],
    )


def negotiated(findings, detector):
    return names(findings, detector, True)


@pytest.mark.parametrize(
    "client, server, expected",
    [
        (["a", "b", "c"], ["c", "b"], "b"),  # client order wins, not server order
        (["a", "b"], ["b", "a"], "a"),
        (
            ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"],
            ["diffie-hellman-group1-sha1"],
            "diffie-hellman-group1-sha1",
        ),
        (["a"], ["b"], None),
        ([], ["a"], None),
        (["a", "a", "b"], ["b", "a"], "a"),
    ],
)
def test_first_match_rule(client, server, expected):
    assert ssh.first_match(client, server) == expected


def test_server_order_does_not_change_the_selection():
    client = side(
        frame=10,
        kex=["k1", "k2", "k3"],
        host=["h1", "h2"],
        enc=["c1", "c2"],
        mac=["m1", "m2"],
    )
    server = side(
        frame=12,
        kex=["k3", "k2"],
        host=["h2", "h1"],
        enc=["c2", "c1"],
        mac=["m2", "m1"],
    )
    findings, errors = run(flow_of(client, server))
    assert errors == []
    assert negotiated(findings, ssh.DETECTOR_KEX) == ["k2"]
    assert negotiated(findings, ssh.DETECTOR_HOST_KEY) == ["h1"]
    assert negotiated(findings, ssh.DETECTOR_CIPHER) == ["c1"]
    assert negotiated(findings, ssh.DETECTOR_MAC) == ["m1"]


def test_client_offers_alone_are_never_negotiated():
    client = side(frame=10, kex=["k1"], host=["h1"], enc=["c1"], mac=["m1"])
    findings, errors = run(flow_of(client, side("SSH-2.0-srv", frame=8)))
    assert findings and all(f.negotiated is False for f in findings)
    assert not any(f.kind_hint == KindHint.PROTOCOL_VERSION for f in findings)
    assert len(errors) == 1 and "stream 3" in errors[0].message and "server KEXINIT" in errors[0].message


def test_no_common_algorithm_emits_no_negotiated_finding_and_an_error():
    client = side(frame=10, kex=["k1"], host=["h1"], enc=["c1"], mac=["m1"])
    server = side(frame=12, kex=["k9"], host=["h1"], enc=["c1"], mac=["m1"])
    findings, errors = run(flow_of(client, server))
    assert negotiated(findings, ssh.DETECTOR_KEX) == []
    assert negotiated(findings, ssh.DETECTOR_HOST_KEY) == ["h1"]
    session = next(f for f in findings if f.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["session"]["negotiated_group"] is None
    assert [e.message for e in errors] == [
        "stream 3 10.0.0.1:50000->10.0.0.2:22: no common key exchange algorithm between client and server lists"
    ]


def test_server_only_algorithms_are_not_emitted_as_offers():
    client = side(frame=10, kex=["k1"], host=["h1"], enc=["c1"], mac=["m1"])
    server = side(frame=12, kex=["k1", "kx"], host=["h1", "hx"], enc=["c1", "cx"], mac=["m1", "mx"])
    findings, _ = run(flow_of(client, server))
    assert {"kx", "hx", "cx", "mx"}.isdisjoint({f.raw_name for f in findings})


def test_duplicate_names_are_emitted_once_but_the_session_list_is_deduplicated_in_order():
    client = side(frame=10, kex=["k1", "k1", "k2"], host=["h1"], enc=["c1"], mac=["m1"])
    server = side(frame=12, kex=["k2"], host=["h1"], enc=["c1"], mac=["m1"])
    findings, _ = run(flow_of(client, server))
    assert names(findings, ssh.DETECTOR_KEX, False) == ["k1", "k2"]
    assert negotiated(findings, ssh.DETECTOR_KEX) == ["k2"]


def test_signalling_pseudo_algorithms_are_not_algorithms():
    kex = ["curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"]
    client = side(frame=10, kex=kex, host=["h1"], enc=["c1"], mac=["m1"])
    server = side(
        frame=12,
        kex=["ext-info-c", "kex-strict-c-v00@openssh.com", "curve25519-sha256"],
        host=["h1"],
        enc=["c1"],
        mac=["m1"],
    )
    findings, errors = run(flow_of(client, server))
    assert errors == []
    assert names(findings, ssh.DETECTOR_KEX, False) == ["curve25519-sha256"]
    assert negotiated(findings, ssh.DETECTOR_KEX) == ["curve25519-sha256"]


def test_directional_cipher_difference_emits_both_and_a_named_error():
    client = side(frame=10, kex=["k"], host=["h"], enc=["c1"], mac=["m"])
    server = side(frame=12, kex=["k"], host=["h"], enc=["c1"], mac=["m"])
    client.enc_c2s, client.enc_s2c = ["c1", "c2"], ["c2", "c1"]
    server.enc_c2s, server.enc_s2c = ["c1"], ["c2"]
    findings, errors = run(flow_of(client, server))
    assert negotiated(findings, ssh.DETECTOR_CIPHER) == ["c1", "c2"]
    assert names(findings, ssh.DETECTOR_CIPHER, False) == ["c1", "c2"]
    session = next(f for f in findings if f.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["session"]["negotiated_cipher_suite"] == "c1"  # client-to-server
    assert len(errors) == 1 and "client-to-server c1, server-to-client c2" in errors[0].message


def test_banner_only_is_a_scan_error_naming_the_stream():
    findings, errors = run(flow_of(side("SSH-2.0-y", frame=8), side("SSH-2.0-x", frame=6)))
    assert findings == []
    assert len(errors) == 1
    assert errors[0].message.startswith("stream 3 10.0.0.1:50000->10.0.0.2:22:")
    assert "banner" in errors[0].message and errors[0].path == FILE


def test_server_kexinit_without_client_kexinit_is_an_error_without_findings():
    server = side(frame=12, kex=["k"], host=["h"], enc=["c"], mac=["m"])
    findings, errors = run(flow_of(side("SSH-2.0-y", frame=8), server))
    assert findings == [] and len(errors) == 1 and "without a client KEXINIT" in errors[0].message


def test_a_side_missing_entirely_is_an_error_not_a_crash():
    client = side(frame=10, kex=["k"], host=["h"], enc=["c"], mac=["m"])
    findings, errors = run(flow_of(client, None))
    assert findings and all(not f.negotiated for f in findings) and len(errors) == 1


def test_ssh1_banner_without_kexinit_is_reported():
    findings, errors = run(flow_of(side("SSH-1.5-old", frame=8), side("SSH-1.5-old", frame=6)))
    assert findings == []
    assert any("SSH 1.5" in e.message for e in errors)


def test_second_kexinit_warning_becomes_a_scan_error_and_keeps_the_first_pair():
    client = side(frame=10, kex=["k1"], host=["h"], enc=["c"], mac=["m"])
    server = side(frame=12, kex=["k1"], host=["h"], enc=["c"], mac=["m"])
    flow = flow_of(client, server)
    flow.warnings.append("more than one KEXINIT from the client; only the first is used")
    findings, errors = run(flow)
    assert negotiated(findings, ssh.DETECTOR_KEX) == ["k1"]
    assert len(errors) == 1
    assert errors[0].message == (
        "stream 3 10.0.0.1:50000->10.0.0.2:22: more than one KEXINIT from the client; only the first is used"
    )


def test_ipv6_flow_text_is_bracketed():
    client = side(frame=10, kex=["k"], host=["h"], enc=["c"], mac=["m"])
    server = side(frame=12, kex=["k"], host=["h"], enc=["c"], mac=["m"])
    flow = flow_of(client, server, client_addr=("2001:db8::1", 50000), server_addr=("2001:db8::2", 22))
    findings, _ = run(flow)
    assert {f.location.flow for f in findings} == {"[2001:db8::1]:50000->[2001:db8::2]:22"}


def test_non_ssh_flows_are_ignored_here():
    res = PureResult()
    other = Flow(0, ("10.0.0.1", 1), ("10.0.0.2", 80), 0.0)
    other.kind = "http"
    res.flows = [other]
    assert ssh.build_findings(res, FILE) == []


def test_session_id_uses_the_client_kexinit_frame():
    client = side(frame=10, kex=["k"], host=["h"], enc=["c"], mac=["m"])
    server = side(frame=12, kex=["k"], host=["h"], enc=["c"], mac=["m"])
    findings, _ = run(flow_of(client, server))
    expected = tls_session.session_id("ssh", FILE, "10.0.0.1:50000->10.0.0.2:22", 10)
    assert {f.session_id for f in findings} == {expected}
    frames = {f.negotiated: f.location.frame for f in findings if f.kind_hint == KindHint.ALGORITHM}
    assert frames == {False: 10, True: 12}


# --- M1M2-06..10 ----------------------------------------------------------------------------


def pair(client_kw, server_kw, *, client_frame=10, server_frame=12):
    return flow_of(
        side(frame=client_frame, **client_kw), side("SSH-2.0-srv", frame=server_frame, **server_kw)
    )


@pytest.mark.parametrize(
    "cipher",
    [
        "chacha20-poly1305@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "AEAD_AES_128_GCM",
    ],
)
def test_aead_cipher_leaves_the_mac_as_an_offer_with_no_selection(cipher):
    lists = dict(kex=["k"], host=["h"], enc=[cipher, "aes128-ctr"], mac=["hmac-sha1"])
    findings, errors = run(pair(lists, lists))
    assert negotiated(findings, ssh.DETECTOR_CIPHER) == [cipher]
    assert names(findings, ssh.DETECTOR_MAC, False) == ["hmac-sha1"]
    assert negotiated(findings, ssh.DETECTOR_MAC) == []
    assert errors == []  # a missing MAC selection is not a failure here


def test_non_aead_cipher_still_negotiates_the_mac():
    lists = dict(kex=["k"], host=["h"], enc=["aes128-ctr"], mac=["hmac-sha1"])
    findings, _ = run(pair(lists, lists))
    assert negotiated(findings, ssh.DETECTOR_MAC) == ["hmac-sha1"]


def test_aead_rule_is_applied_per_direction():
    client = dict(kex=["k"], host=["h"], enc=["x"], mac=["hmac-sha1"])
    server = dict(kex=["k"], host=["h"], enc=["x"], mac=["hmac-sha1"])
    f = pair(client, server)
    f.ssh_client.enc_c2s, f.ssh_server.enc_c2s = ["aes256-gcm@openssh.com"], ["aes256-gcm@openssh.com"]
    f.ssh_client.enc_s2c, f.ssh_server.enc_s2c = ["aes128-ctr"], ["aes128-ctr"]
    findings, errors = run(f)
    macs = [x for x in findings if x.detector == ssh.DETECTOR_MAC and x.negotiated]
    assert [(m.raw_name, m.extra) for m in macs] == [("hmac-sha1", {"direction": "server_to_client"})]
    ciphers = [x for x in findings if x.detector == ssh.DETECTOR_CIPHER and x.negotiated]
    assert {(c.raw_name, c.extra["direction"]) for c in ciphers} == {
        ("aes256-gcm@openssh.com", "client_to_server"),
        ("aes128-ctr", "server_to_client"),
    }
    session = next(x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["session"]["negotiated_cipher_suite"] == "aes256-gcm@openssh.com"
    assert any("ciphers differ by direction" in e.message for e in errors)


def test_direction_is_only_set_on_one_direction_findings():
    f = pair(
        dict(kex=["k"], host=["h"], enc=["c1"], mac=["m1"]),
        dict(kex=["k"], host=["h"], enc=["c1"], mac=["m1"]),
    )
    f.ssh_client.enc_s2c = ["c1", "c2"]
    findings, _ = run(f)
    offered = {
        x.raw_name: x.extra for x in findings if x.detector == ssh.DETECTOR_CIPHER and not x.negotiated
    }
    assert offered == {"c1": {}, "c2": {"direction": "server_to_client"}}


def test_host_key_selection_makes_authentication_observable_only_when_established():
    ok = dict(kex=["k"], host=["h"], enc=["c"], mac=["m"])
    findings, _ = run(pair(ok, ok))
    session = next(x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["authentication_observable"] is True
    assert session.extra["session"]["cert_key"] == "h"
    assert "certificate_state" not in session.extra

    findings, _ = run(pair(ok, dict(ok, host=["other"])))
    session = next(x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["authentication_observable"] is False
    assert session.extra["session"]["cert_key"] is None


def test_negotiated_frame_is_the_second_kexinit_for_server_first_captures():
    lists = dict(kex=["k"], host=["h"], enc=["c"], mac=["m"])
    findings, errors = run(pair(lists, lists, client_frame=10, server_frame=12))
    frames = {(x.negotiated, x.location.frame) for x in findings if x.kind_hint == KindHint.ALGORITHM}
    assert frames == {(False, 10), (True, 12)}

    findings, errors = run(pair(lists, lists, client_frame=12, server_frame=10))
    assert errors == []
    session = next(x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.location.frame == 12  # session id keeps the client KEXINIT frame
    assert session.session_id == tls_session.session_id("ssh", FILE, session.location.flow, 12)


def test_ids_stay_unique_when_offer_and_selection_share_a_frame():
    # the client KEXINIT is the later frame, so selection becomes decidable on that same frame
    lists = dict(kex=["k1", "k2"], host=["h"], enc=["c"], mac=["m"])
    findings, _ = run(pair(lists, dict(lists, kex=["k2"]), client_frame=12, server_frame=10))
    ids = [x.id for x in findings]
    assert len(ids) == len(set(ids))
    kex = [(x.raw_name, x.negotiated) for x in findings if x.detector == ssh.DETECTOR_KEX]
    assert kex == [("k1", False), ("k2", True)]


@pytest.mark.parametrize(
    "client_banner, server_banner",
    [("SSH-1.99-OpenSSH_3.9", "SSH-2.0-OpenSSH_9.6"), ("SSH-2.0-a", "SSH-1.99-b")],
)
def test_banners_are_kept_verbatim_client_first_even_when_versions_differ(client_banner, server_banner):
    lists = dict(kex=["k"], host=["h"], enc=["c"], mac=["m"])
    f = flow_of(side(client_banner, frame=10, **lists), side(server_banner, frame=12, **lists))
    findings, errors = run(f)
    session = next(x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["session"]["peer_banners"] == [client_banner, server_banner]
    assert session.raw_name == "SSH-2.0" and session.extra["session"]["version"] == "SSH-2.0"
    assert errors == []


def test_peer_banners_always_has_two_positional_entries():
    lists = dict(kex=["k"], host=["h"], enc=["c"], mac=["m"])
    # a capture that starts after the client banner: only the server banner was seen
    f = flow_of(side("", frame=10, **lists), side("SSH-2.0-srv", frame=12, **lists))
    findings, _ = run(f)
    session = next(x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["session"]["peer_banners"] == ["", "SSH-2.0-srv"]

    f = flow_of(side("SSH-2.0-cli", frame=10, **lists), side("", frame=12, **lists))
    findings, _ = run(f)
    session = next(x for x in findings if x.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["session"]["peer_banners"] == ["SSH-2.0-cli", ""]
