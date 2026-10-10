"""The five sample sessions of M2M4-01: real parser output, one session per file.

Regenerate with ``.venv/bin/python tests/test_network_samples.py`` after a parser change; the tests
fail while the committed files differ from the output of the current code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from quantumtrace.models import Finding, KindHint
from quantumtrace.scanners.network import purepy, ssh, tls_session

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "network-capture" / "network.pcap"
SAMPLES = ROOT / "tests" / "fixtures" / "pcap" / "samples"
FILE = "network.pcap"

# name -> (predicate on the session finding). The first matching session in stream order is used.
PICKS = {
    "legacy_rsa_587": lambda s, se: se["service"] == "smtp-starttls" and s.protocol == "TLS 1.2",
    "tls13_x25519_5432": lambda s, se: se["service"] == "postgres" and s.protocol == "TLS 1.3",
    "hybrid_vault": lambda s, se: (
        se["negotiated_group"] == "0x11EC" and (se["sni"] or "").startswith("vault")
    ),
    "ssh_legacy": lambda s, se: (
        se["transport"] == "ssh" and se["negotiated_group"] == "diffie-hellman-group14-sha1"
    ),
    "ssh_modern": lambda s, se: se["transport"] == "ssh" and se["negotiated_group"] == "curve25519-sha256",
}


def build_samples() -> dict[str, str]:
    result = purepy.read_flows(KIT)
    assert result.errors == []
    out = tls_session.build_findings(result, FILE) + ssh.build_findings(result, FILE, parser_errors=False)
    groups: dict[str, list[Finding]] = {}
    for item in out:
        if isinstance(item, Finding):
            groups.setdefault(item.session_id, []).append(item)
    sessions = []
    for findings in groups.values():
        head = next(f for f in findings if f.kind_hint == KindHint.PROTOCOL_VERSION)
        sessions.append((head.location.frame, head.extra["session"]["flow"], head, findings))
    # stream order: the frame of the first packet is monotonic with the stream id in this capture
    sessions.sort(key=lambda s: (s[0] or 0, s[1]))
    files: dict[str, str] = {}
    for name, pick in PICKS.items():
        _, _, _, findings = next(s for s in sessions if pick(s[2], s[2].extra["session"]))
        # session finding first, then the algorithm findings as emitted
        dumped = [f.model_dump(mode="json") for f in findings]
        files[name] = json.dumps(dumped, indent=2, ensure_ascii=False) + "\n"
    return files


@pytest.fixture(scope="module")
def built():
    return build_samples()


def test_committed_samples_match_the_current_parser_output(built):
    assert sorted(p.stem for p in SAMPLES.glob("*.json")) == sorted(PICKS)
    for name, text in built.items():
        assert (SAMPLES / f"{name}.json").read_text(encoding="utf-8") == text, name


def test_each_sample_is_one_session_with_offered_and_negotiated_findings(built):
    for name, text in built.items():
        findings = [Finding.model_validate(d) for d in json.loads(text)]
        assert len({f.session_id for f in findings}) == 1, name
        heads = [f for f in findings if f.kind_hint == KindHint.PROTOCOL_VERSION]
        assert len(heads) == 1 and heads[0].negotiated is True, name
        assert any(f.negotiated for f in findings if f is not heads[0]), name
        assert any(not f.negotiated for f in findings), name


def test_sample_profiles(built):
    def head(name):
        return next(d for d in json.loads(built[name]) if d["kind_hint"] == KindHint.PROTOCOL_VERSION.value)

    assert head("legacy_rsa_587")["extra"]["session"]["service"] == "smtp-starttls"
    assert head("legacy_rsa_587")["extra"]["session"]["negotiated_group"] is None
    assert head("tls13_x25519_5432")["extra"]["session"]["negotiated_group"] == "0x001D"
    assert head("hybrid_vault")["extra"]["session"]["negotiated_group"] == "0x11EC"
    legacy, modern = head("ssh_legacy"), head("ssh_modern")
    assert legacy["extra"]["session"]["cert_key"] == "ssh-rsa"
    assert modern["extra"]["session"]["cert_key"] == "rsa-sha2-512"
    assert modern["location"]["source_type"] == "ssh"


if __name__ == "__main__":
    if "--write" not in sys.argv and len(sys.argv) > 1:
        raise SystemExit("usage: test_network_samples.py [--write]")
    SAMPLES.mkdir(parents=True, exist_ok=True)
    for sample, content in build_samples().items():
        (SAMPLES / f"{sample}.json").write_text(content, encoding="utf-8")
        print(f"wrote {SAMPLES.relative_to(ROOT) / (sample + '.json')}")
