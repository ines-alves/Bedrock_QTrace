"""The committed fixture captures against expected.yaml, through the registered adapter."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from quantumtrace.models import Finding, KindHint, ScanError
from quantumtrace.scanners.network import tshark
from quantumtrace.scanners.network.pcap_scanner import PcapScanner

DIR = Path(__file__).resolve().parent / "fixtures" / "pcap"
EXPECTED = yaml.safe_load((DIR / "expected.yaml").read_text())


@pytest.fixture(params=["purepy", "tshark"] if shutil.which("tshark") else ["purepy"])
def parser(request, monkeypatch):
    if request.param == "purepy":
        monkeypatch.setattr(tshark, "tshark_available", lambda: False)


def test_expected_yaml_covers_the_three_fixtures():
    assert sorted(EXPECTED) == [
        "tls12_ecdhe_ecdsa_p256.pcap",
        "tls13_hybrid_keylog.pcap",
        "tls13_offer_hybrid_server_x25519.pcap",
    ]
    assert all((DIR / name).exists() for name in EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_matches_expected(parser, name):
    want = EXPECTED[name]
    out = list(PcapScanner().scan(DIR / name, DIR))
    assert [x for x in out if isinstance(x, ScanError)] == []
    found = [x for x in out if isinstance(x, Finding)]
    assert {f.location.file for f in found} == {name}
    assert {f.location.sni for f in found} == {want["sni"]}
    assert {f.protocol for f in found} == {want["version"]}

    def codes(kind, negotiated):
        return [f.raw_name for f in found if f.kind_hint == kind and f.negotiated is negotiated]

    assert codes(KindHint.CIPHER_SUITE, True) == [want["cipher_suite"]]
    assert codes(KindHint.GROUP, True) == [want["group"]]
    if "offered_groups" in want:
        assert sorted(codes(KindHint.GROUP, False)) == sorted(want["offered_groups"])
    frames = {(f.negotiated, f.location.frame) for f in found if f.kind_hint == KindHint.CIPHER_SUITE}
    assert frames == {(False, want["hello_frames"]["client"]), (True, want["hello_frames"]["server"])}
    flows = {f.location.flow for f in found}
    assert len(flows) == 1 and next(iter(flows)).endswith("->127.0.0.1:443")

    certificates = [f for f in found if f.kind_hint == KindHint.CERTIFICATE]
    session = next(f for f in found if f.kind_hint == KindHint.PROTOCOL_VERSION)
    assert session.extra["authentication_observable"] is want["authentication_observable"]
    assert (len(certificates) == 1) is want["certificate_in_capture"]
    if not certificates:
        assert session.extra["session"]["cert_key"] is None
        assert session.extra["session"]["cert_sig_alg"] is None
        return
    (cert,) = certificates
    expected = want["certificate"]
    assert cert.raw_name == expected["raw_name"] == cert.extra["key_algorithm"]
    assert (cert.curve, cert.key_size) == (expected["curve"], expected["key_size"])
    assert cert.location.frame == expected["frame"] and cert.negotiated is True
    for key in ("signature_algorithm", "signature_algorithm_oid", "not_before", "not_after", "self_signed"):
        assert cert.extra[key] == expected[key]
    assert session.extra["session"]["cert_key"] == cert.raw_name
    assert session.extra["session"]["cert_sig_alg"] == cert.extra["signature_algorithm"]
    assert cert.session_id == session.session_id


def test_keylog_file_sits_next_to_the_hybrid_capture():
    assert (DIR / EXPECTED["tls13_hybrid_keylog.pcap"]["keylog"]).stat().st_size > 0
