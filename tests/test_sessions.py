"""Negotiated session semantics and published raw network evidence integration."""

import json
from itertools import permutations
from pathlib import Path

import pytest

from quantumtrace.engine import classify_findings
from quantumtrace.engine.sessions import build_sessions
from quantumtrace.evaluation import observations
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import Finding, KindHint, Location, SourceType, Tier, Usage
from quantumtrace.pipeline import run


@pytest.fixture(scope="module")
def kb():
    return load_kb()


def finding(name="0x11EC", **updates):
    data = dict(
        id=name,
        raw_name=name,
        kind_hint=KindHint.GROUP,
        usage=Usage.KEY_EXCHANGE,
        detector="pcap.tls.group",
        negotiated=True,
        session_id="one",
        location=Location(source_type=SourceType.PCAP, file="capture.pcap", flow="flow", frame=2),
    )
    data.update(updates)
    return Finding(**data)


def views(kb, raws):
    return build_sessions(raws, classify_findings(raws, kb))


def safe_cipher():
    return finding("0x1302", kind_hint=KindHint.CIPHER_SUITE, usage=Usage.UNKNOWN)


def protocol(**extra):
    return finding(
        "TLS 1.3",
        kind_hint=KindHint.PROTOCOL_VERSION,
        usage=Usage.UNKNOWN,
        extra={"authentication_observable": False, "certificate_state": "encrypted", **extra},
    )


def test_safe_hybrid_unknown_auth(kb):
    raws = [finding(), safe_cipher(), protocol()]
    sessions, errors = views(kb, raws)
    assert errors == []
    session = sessions[0]
    assert session.negotiated_group == "X25519MLKEM768"
    assert session.negotiated_cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert session.pq_status == "pq_hybrid" and session.verdict_tier == Tier.UNKNOWN
    assert session.cert_key is None and session.cert_sig_alg is None
    assert session.source == "capture.pcap" and session.flow == "flow"
    assert raws[-1].extra["certificate_state"] == "encrypted"


def test_hybrid_with_observed_authentication(kb):
    cert = finding("RSA", kind_hint=KindHint.CERTIFICATE, usage=Usage.AUTHENTICATION, key_size=2048)
    sessions, errors = views(kb, [finding(), safe_cipher(), cert])
    assert not errors
    assert sessions[0].pq_status == "pq_hybrid" and sessions[0].verdict_tier == Tier.CRITICAL
    assert sessions[0].cert_key == "RSA"


def test_offered_certificate_signature_cannot_supply_auth(kb):
    offered = finding("0x0403", kind_hint=KindHint.SIGNATURE_SCHEME, usage=Usage.SIGNATURE, negotiated=False)
    sessions, errors = views(kb, [finding(), safe_cipher(), offered, protocol()])
    assert not errors and sessions[0].verdict_tier == Tier.UNKNOWN
    assert sessions[0].offered_sig_schemes == ["ecdsa_secp256r1_sha256"]


def test_classical_and_medium_dominate_missing_auth(kb):
    sessions, _ = views(kb, [finding("0x001D"), safe_cipher(), protocol()])
    assert sessions[0].pq_status == "classical" and sessions[0].verdict_tier == Tier.CRITICAL
    sessions, _ = views(kb, [finding(), safe_cipher().model_copy(update={"raw_name": "0x1301"}), protocol()])
    assert sessions[0].verdict_tier == Tier.MEDIUM


def test_pure_pq_kex_and_missing_cipher_remain_distinct(kb):
    sessions, _ = views(kb, [finding("ML-KEM-768", kind_hint=KindHint.ALGORITHM), protocol()])
    assert sessions[0].pq_status == "pq_pure" and sessions[0].verdict_tier == Tier.UNKNOWN


def test_clienthello_only_without_metadata(kb):
    raw = finding(negotiated=False, session_id="partial", detector="pcap.tls.group.variant")
    sessions, errors = views(kb, [raw])
    assert not errors
    assert sessions[0].session_id == "partial"
    assert sessions[0].offered_groups == ["X25519MLKEM768"]
    assert sessions[0].negotiated_group is None and sessions[0].negotiated_cipher_suite is None
    assert sessions[0].verdict_tier == Tier.UNKNOWN and sessions[0].pq_status == "unknown"


def test_serverhello_only_null_offers_and_raw_retention(kb):
    extra = {
        "session": {
            "offered_groups": None,
            "offered_cipher_suites": None,
            "offered_sig_schemes": None,
            "negotiated_group": "0x11EC",
            "negotiated_cipher_suite": "0x1302",
            "version": "TLS 1.3",
        }
    }
    raw = protocol(**extra)
    before = raw.model_dump()
    sessions, errors = views(kb, [raw, finding(), safe_cipher()])
    assert not errors
    assert sessions[0].offered_groups == sessions[0].offered_cipher_suites == []
    assert sessions[0].verdict_tier == Tier.UNKNOWN
    assert raw.model_dump() == before


def test_hrr_only_no_negotiation(kb):
    raws = [
        finding(negotiated=False),
        protocol(session={"negotiated_group": None}).model_copy(update={"negotiated": False}),
    ]
    sessions, errors = views(kb, raws)
    assert not errors
    assert sessions[0].negotiated_group is None
    assert sessions[0].pq_status == "unknown" and sessions[0].verdict_tier == Tier.UNKNOWN


def test_raw_ordered_offers_override_sorted_display_evidence(kb):
    raw = protocol(session={"offered_groups": ["0x001D", "0x11EC", "0x0017"]})
    raws = [raw, finding("0x0017", negotiated=False), finding("0x001D", negotiated=False), finding()]
    expected, errors = views(kb, raws)
    assert not errors
    assert expected[0].offered_groups == ["x25519", "X25519MLKEM768", "secp256r1"]
    for order in permutations(raws):
        assert views(kb, list(order)) == (expected, errors)


@pytest.mark.parametrize(
    "field,left,right",
    [
        ("negotiated_group", "0x11EC", "0x001D"),
        ("version", "TLS 1.2", "TLS 1.3"),
        ("offered_groups", ["0x001D"], ["0x11EC"]),
        ("flow", "a", "b"),
        ("peer_banners", ["client", "server"], ["other", "server"]),
    ],
)
def test_conflicting_metadata_no_arbitrary_winner(kb, field, left, right):
    a = protocol(session={field: left})
    b = protocol(session={field: right}).model_copy(update={"id": "other"})
    sessions, errors = views(kb, [a, b])
    assert errors and all(error.detector == "engine.sessions" for error in errors)
    assert sessions[0].pq_status == "unknown" and sessions[0].verdict_tier == Tier.UNKNOWN
    assert views(kb, [b, a]) == (sessions, errors)


def test_contradictory_selected_rows_and_metadata(kb):
    sessions, errors = views(kb, [finding(), protocol(session={"negotiated_group": "0x001D"})])
    assert any("negotiated_group" in error.message for error in errors)
    assert sessions[0].negotiated_group is None


@pytest.mark.parametrize(
    "extra",
    [
        {"session": []},
        {"session": {"offered_groups": 5}},
        {"session": {"version": []}},
        {"authentication_observable": "true"},
        {"certificate_state": "invalid"},
        {"session": {"transport": "quic"}},
        {"session": {"peer_banners": "banner"}},
    ],
)
def test_invalid_metadata_is_recoverable(kb, extra):
    sessions, errors = views(kb, [finding(extra=extra)])
    assert errors and sessions[0].verdict_tier == Tier.UNKNOWN


def test_false_authentication_does_not_display_guessed_cert(kb):
    raw = protocol(session={"cert_key": "RSA", "cert_sig_alg": "SHA256"})
    sessions, errors = views(kb, [raw, finding()])
    assert not errors and sessions[0].cert_key is None and sessions[0].cert_sig_alg is None


def test_certificate_state_observability_conflict(kb):
    sessions, errors = views(kb, [protocol(authentication_observable=True), finding()])
    assert errors and sessions[0].verdict_tier == Tier.UNKNOWN


def test_namespaces_unknown_hex_and_null_iana_version(kb):
    raw = protocol(codepoint="0x0304", iana_name=None)
    sessions, errors = views(kb, [raw, finding("0xFFFF", negotiated=False)])
    assert not errors
    assert sessions[0].version == "TLS 1.3" and sessions[0].offered_groups == ["0xFFFF"]
    assert raw.extra["iana_name"] is None


def test_serverkeyexchange_frame_and_session_isolation(kb):
    raw = finding(
        "0x001D", location=Location(source_type=SourceType.PCAP, file="capture.pcap", flow="flow", frame=17)
    )
    other = finding(session_id="other", negotiated=False)
    sessions, errors = views(kb, [raw, other])
    assert not errors
    assert [session.session_id for session in sessions] == ["one", "other"]
    assert sessions[0].pq_status == "classical" and sessions[1].pq_status == "unknown"
    assert raw.location.frame == 17


def test_plaintext_not_a_session(kb):
    raw = finding("HTTP", kind_hint=KindHint.PLAINTEXT)
    assert views(kb, [raw]) == ([], [])


def test_published_network_samples(kb):
    root = Path(__file__).parent / "fixtures" / "pcap" / "samples"
    for path in sorted(root.glob("*.json")):
        data = json.loads(path.read_text())
        raws = [Finding.model_validate(item) for item in data]
        sessions, errors = views(kb, raws)
        if path.name == "plaintext_http.json":
            assert sessions == [] and errors == []
            continue
        assert len(sessions) == 1, path.name
        assert not errors, (path.name, errors)
        assert sessions[0].source
        assert views(kb, list(reversed(raws))) == (sessions, errors)
        if path.name == "hybrid_vault.json":
            assert sessions[0].pq_status == "pq_hybrid" and sessions[0].verdict_tier == Tier.UNKNOWN
        if path.name.startswith("ssh"):
            assert sessions[0].transport == "ssh" and sessions[0].verdict_tier == Tier.CRITICAL
            assert len(sessions[0].peer_banners) == 2


def test_static_rsa_transport_without_negotiated_group(kb):
    raw = finding("0x009C", kind_hint=KindHint.CIPHER_SUITE, usage=Usage.UNKNOWN)
    sessions, errors = views(kb, [raw, protocol()])
    assert not errors
    assert sessions[0].negotiated_group is None
    assert sessions[0].pq_status == "classical" and sessions[0].verdict_tier == Tier.CRITICAL
    assert sessions[0].cert_key is None


def test_ssh_direction_choices_do_not_create_competing_summary(kb):
    def ssh_raw(name, usage, **updates):
        return finding(
            name,
            kind_hint=KindHint.ALGORITHM,
            usage=usage,
            location=Location(source_type=SourceType.SSH, file="ssh.pcap", flow="ssh"),
            **updates,
        )

    raws = [
        ssh_raw("curve25519-sha256", Usage.KEY_EXCHANGE),
        ssh_raw("rsa-sha2-512", Usage.SIGNATURE),
        ssh_raw("aes256-ctr", Usage.ENCRYPTION, extra={"direction": "client_to_server"}),
        ssh_raw("aes128-ctr", Usage.ENCRYPTION, extra={"direction": "server_to_client"}),
        ssh_raw("SSH-2.0", Usage.UNKNOWN).model_copy(
            update={
                "kind_hint": KindHint.PROTOCOL_VERSION,
                "extra": {
                    "authentication_observable": True,
                    "session": {
                        "transport": "ssh",
                        "negotiated_cipher_suite": "aes256-ctr",
                        "cert_key": "rsa-sha2-512",
                    },
                },
            }
        ),
    ]
    sessions, errors = views(kb, raws)
    assert not errors
    assert sessions[0].negotiated_cipher_suite == "aes256-ctr"
    assert sessions[0].cert_key == "rsa-sha2-512" and sessions[0].transport == "ssh"
    assert sessions[0].verdict_tier == Tier.CRITICAL


def test_live_source_and_arbitrary_metadata_do_not_override_source(kb):
    raw = finding(
        location=Location(source_type=SourceType.LIVE, target="example.invalid:443"),
        extra={"session": {"source": "arbitrary extension"}},
    )
    sessions, errors = views(kb, [raw])
    assert not errors and sessions[0].source == "example.invalid:443"


def test_actual_capture_parser_session_consumption(kb):
    from quantumtrace.scanners.network import plaintext, ssh, tls_session
    from quantumtrace.scanners.network.purepy import read_flows

    path = Path(__file__).resolve().parents[1] / "network-capture" / "network.pcap"
    parsed = read_flows(path)
    items = tls_session.build_findings(parsed, "network.pcap")
    items += ssh.build_findings(parsed, "network.pcap", parser_errors=False)
    items += plaintext.build_findings(parsed, "network.pcap", parser_errors=False)
    raws = [item for item in items if isinstance(item, Finding)]
    assert all(isinstance(item, Finding) for item in items)
    sessions, errors = views(kb, raws)
    assert not errors
    assert sum(session.transport == "tls" for session in sessions) == 97
    assert sum(session.transport == "ssh" for session in sessions) == 24
    assert sum(raw.kind_hint == KindHint.PLAINTEXT for raw in raws) == 14
    assert len(sessions) == len({session.session_id for session in sessions})
    assert views(kb, list(reversed(raws))) == (sessions, errors)


def test_unselected_metadata_never_supplies_negotiated_fields(kb):
    raw = protocol(session={"negotiated_group": "0x11EC", "negotiated_cipher_suite": "0x1302"})
    raw.negotiated = False
    sessions, errors = views(kb, [raw])
    assert not errors
    assert sessions[0].negotiated_group is None and sessions[0].negotiated_cipher_suite is None
    assert sessions[0].pq_status == "unknown" and sessions[0].verdict_tier == Tier.UNKNOWN


def test_known_critical_survives_conflicting_authentication_state(kb):
    cert = finding("RSA", kind_hint=KindHint.CERTIFICATE, usage=Usage.AUTHENTICATION, key_size=2048)
    sessions, errors = views(kb, [cert, finding(), safe_cipher(), protocol()])
    assert errors
    assert sessions[0].verdict_tier == Tier.CRITICAL
    assert sessions[0].cert_key is None and sessions[0].pq_status == "unknown"


def test_undecodable_certificate_is_unauthenticated_not_conflicting(kb):
    raw = protocol(certificate_state="observed", session={"cert_key": None, "cert_sig_alg": None})
    sessions, errors = views(kb, [raw, finding(), safe_cipher()])
    assert not errors
    assert sessions[0].cert_key is None and sessions[0].cert_sig_alg is None
    assert sessions[0].verdict_tier == Tier.UNKNOWN


def test_decoded_certificate_with_false_authentication_still_conflicts(kb):
    cert = finding("RSA", kind_hint=KindHint.CERTIFICATE, usage=Usage.AUTHENTICATION, key_size=2048)
    sessions, errors = views(kb, [cert, finding(), safe_cipher(), protocol(certificate_state="observed")])
    assert errors and sessions[0].verdict_tier == Tier.CRITICAL


def test_starter_session_fields_split_kex_and_authentication():
    """Frozen session fields carry the KEX/authentication split that displays derive (M2/M4)."""
    result = run([Path(__file__).resolve().parents[1] / "network-capture"])
    rows = observations(result)["session"]
    assert len(rows) == len(result.sessions)
    kex_tier = {"pq_hybrid": "SAFE", "pq_pure": "SAFE", "classical": "CRITICAL"}
    for row in rows:
        if row["pq_status"] in kex_tier:
            assert row["tier_kex"] == kex_tier[row["pq_status"]], row["session_id"]
        # A null certificate key means authentication was not observed: never a SAFE verdict.
        if row["cert_key"] is None:
            assert row["verdict_tier"] != Tier.SAFE.value, row["session_id"]
    hybrid = [s for s in result.sessions if s.pq_status == "pq_hybrid"]
    assert len(hybrid) == 7
    assert {(s.version, s.negotiated_group, s.cert_key, s.verdict_tier) for s in hybrid} == {
        ("TLS 1.3", "X25519MLKEM768", None, Tier.UNKNOWN)
    }
    # The UNKNOWN concerns authentication only: the hybrid KEX asset is SAFE and not HNDL-exposed.
    (kex,) = [a for a in result.assets if a.canonical_name == "X25519MLKEM768"]
    assert kex.tier == Tier.SAFE and not kex.hndl_exposed
