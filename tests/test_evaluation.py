"""Golden gates must measure evidence and expose missing coverage honestly."""

from copy import deepcopy
from pathlib import Path

import pytest

from quantumtrace.evaluation import Metrics, evaluate, identity, load_rows, match, observations, subset
from quantumtrace.models import (
    Finding,
    KindHint,
    Location,
    RiskSummary,
    ScanError,
    ScanResult,
    SourceType,
    Usage,
)
from quantumtrace.pipeline import _run, run

ROOT = Path(__file__).resolve().parents[1]


def finding(line=10, raw="SHA-384", usage=Usage.HASH, **kwargs):
    return Finding(
        id=f"{raw}-{line}",
        raw_name=raw,
        kind_hint=KindHint.ALGORITHM,
        usage=usage,
        detector="test",
        location=Location(source_type=SourceType.CODE, file="sample.py", line=line),
        **kwargs,
    )


def result(*findings):
    return ScanResult(
        tool_version="test",
        scan_id="test",
        started_at="2026-09-14T00:00:00+00:00",
        finished_at="2026-09-14T00:00:00+00:00",
        inputs=[],
        findings=list(findings),
        assets=[],
        summary=RiskSummary(
            score=0,
            grade="A",
            readiness_pct=100,
            counts_by_tier={},
            counts_by_source={},
            score_by_source={},
            hndl_exposed_count=0,
            top_risks=[],
        ),
    )


def row(line=10, canonical="SHA-384", tier="SAFE"):
    return dict(
        kind="asset",
        source="sample.py",
        source_type="code",
        line=line,
        canonical=canonical,
        usage="hash",
        tier=tier,
    )


def test_unique_occurrences_tolerance_and_duplicate_emissions():
    f = finding(12)
    r = evaluate(
        [row()], result(f, f.model_copy(update={"detector": "second", "id": "second"})), required={"code"}
    )
    assert r.passed
    assert r.metrics["overall"] == Metrics(1, 1, 1, 1)
    assert not evaluate([row(), row()], result(f), required={"code"}).passed
    assert not evaluate([row()], result(finding(13)), required={"code"}).passed


def test_maximum_matching_does_not_greedily_steal_a_line():
    wants = [row(10), row(12)]
    got = [dict(row(10), line=10), dict(row(8), line=8)]
    matched, ambiguous = match(wants, got)
    assert len(matched) == 2 and not ambiguous
    reversed_match, _ = match(wants[::-1], got[::-1])
    assert len(reversed_match) == 2


def test_wrong_tier_keeps_detection_metrics_and_fails_classification():
    r = evaluate([row(tier="CRITICAL")], result(finding()), required={"code"})
    assert r.metrics["code"].precision == 1
    assert r.metrics["code"].recall == 1
    assert r.metrics["code"].tier_accuracy == 0
    assert not r.passed and any("wrong tier" in s for s in r.failures)


def test_wrong_canonical_reports_miss_false_positive_and_classification():
    r = evaluate([row(canonical="SHA-512")], result(finding()), required={"code"})
    assert r.metrics["code"].precision == r.metrics["code"].recall == 0
    assert any("wrong algorithm" in s for s in r.diagnostics)
    assert any("false positive" in s for s in r.diagnostics)
    assert not r.passed


def test_wrong_flags_fail_even_when_tier_is_correct():
    want = dict(row(), classically_broken=True, hndl_exposed=True)
    r = evaluate([want], result(finding()), required={"code"})
    assert not r.passed
    assert any("classically_broken" in s for s in r.failures)
    assert any("hndl_exposed" in s for s in r.failures)


def test_empty_data_is_na_but_missing_adapter_is_zero():
    empty = evaluate([], result(), required=set())
    assert empty.metrics["overall"].precision is None
    assert empty.metrics["overall"].recall is None
    assert not empty.passed
    missing = evaluate([row()], result(), required={"code"})
    assert missing.metrics["code"].precision == missing.metrics["code"].recall == 0
    assert not missing.passed


def test_unconfirmed_sources_and_unassessed_files_cannot_pass():
    f = finding().model_copy(
        update={"location": Location(source_type=SourceType.CODE, file="other.py", line=1)}
    )
    r = evaluate([row()], result(finding(), f), required={"code", "kms"})
    assert not r.passed and r.unassessed == {"code": 1}
    assert any("kms" in s for s in r.failures)


def test_scan_errors_are_failures():
    data = result(finding())
    data.errors = [ScanError(detector="missing", message="unavailable")]
    r = evaluate([row()], data, required={"code"})
    assert r.metrics["overall"].precision == 1 and not r.passed
    assert any("scan error" in s for s in r.failures)


def test_info_notes_are_not_coverage_failures():
    data = result(finding())
    data.errors = [ScanError(detector="code.java.manifest", path="pom.xml", message="note", severity="info")]
    r = evaluate([row()], data, required={"code"})
    assert r.passed and not any("scan error" in s for s in r.failures)


def test_threshold_allows_small_detection_loss_but_safe_misses_fail():
    wants = [row(i * 10, "SHA-1", "MEDIUM") for i in range(20)]
    got = result(*(finding(i * 10, "SHA-1") for i in range(19)))
    r = evaluate(wants, got, required={"code"})
    assert r.metrics["overall"].recall == 0.95 and r.passed
    wants[-1] = row(190)
    assert not evaluate(wants, got, required={"code"}).passed


def test_session_ambiguity_and_reuse_fail():
    want = dict(kind="session", source="network.pcap", session_sni="vault.lab", tier_session="UNKNOWN")
    got = [
        dict(source="network.pcap", session_sni="vault.lab", session_id="a"),
        dict(source="network.pcap", session_sni="vault.lab", session_id="b"),
    ]
    matched, ambiguous = match([want], got)
    assert not matched and ambiguous == [0]
    matched, _ = match([want, want], got[:1])
    assert len(matched) == 1
    assert not identity(want, dict(got[0], source="nested/network.pcap"))


def test_recursive_metadata_and_negotiated_selectors():
    assert subset(
        {"nested": {"flag": True}, "flags": ["a"]},
        {"nested": {"flag": True, "other": 3}, "flags": ["a", "b"]},
    )
    assert not subset(True, 1)
    assert identity(dict(row(), negotiated=False), dict(row(), states=[True, False]))
    assert not identity(dict(row(), negotiated=True), dict(row(), negotiated=None))


def test_raw_counts_do_not_inflate_algorithm_metrics():
    wants = [
        row(),
        dict(kind="count", source="sample.py", source_type="code", metric="occurrences", count=1),
        dict(
            kind="finding", source="sample.py", source_type="code", kind_hint="algorithm", raw_name="SHA-384"
        ),
    ]
    r = evaluate(wants, result(finding(), finding()), required={"code"})
    assert r.passed and r.metrics["overall"].matched == 1
    wants[1]["count"] = 2
    assert not evaluate(wants, result(finding()), required={"code"}).passed


def test_protocol_containers_and_hygiene_are_not_algorithm_accuracy():
    f = finding(raw="TLS_RSA_WITH_AES_128_CBC_SHA", usage=Usage.UNKNOWN).model_copy(
        update={"kind_hint": KindHint.CIPHER_SUITE}
    )
    h = finding(raw="random.getrandbits", usage=Usage.RNG, extra={"hygiene_only": True})
    got = observations(result(f, h))["asset"]
    assert got and all(r["asset_type"] == "algorithm" for r in got)
    assert not any(r["canonical"] in {h.raw_name, f.raw_name} for r in got)


def test_schema_and_relative_source_validation(tmp_path):
    path = tmp_path / "rows.yaml"
    path.write_text("- kind: asset\n  source: ../private.py\n  canonical: SHA-384\n  tier: SAFE\n")
    with pytest.raises(ValueError, match="repository-relative"):
        load_rows(path, ROOT / "docs/golden.schema.json")
    path.write_text("- kind: guessed\n")
    with pytest.raises(Exception):
        load_rows(path, ROOT / "docs/golden.schema.json")
    session = "- kind: session\n  source: {}\n  session_id: abc\n  tier_session: UNKNOWN\n"
    path.write_text(session.format("network-capture/network.pcap"))
    with pytest.raises(ValueError, match="session_id"):
        load_rows(path, ROOT / "docs/golden.schema.json")
    path.write_text(session.format("tests/fixtures/pcap/fixed.pcap"))
    assert load_rows(path, ROOT / "docs/golden.schema.json")[0]["session_id"] == "abc"


def test_real_owner_code_golden_is_measured_not_seeded():
    rows = load_rows(ROOT / "tests/golden/expected.yaml", ROOT / "docs/golden.schema.json")
    rows = [r for r in rows if r.get("source_type") == "code"]
    paths = [ROOT / p for p in sorted({r["source"] for r in rows})]
    data = _run(paths, scan_root=ROOT)
    report = evaluate(rows, data, required={"code"})
    assert report.passed, (report.failures, report.diagnostics)
    assert report.metrics["code"].expected == 51
    assert not data.errors
    original = deepcopy(data.model_dump())
    evaluate(rows[::-1], data, required={"code"})
    assert data.model_dump() == original


def test_fixed_root_and_direct_file_paths_are_distinct():
    path = ROOT / "network-capture/network.pcap"
    fixed = _run([path], scan_root=ROOT)
    direct = run([path])
    assert {f.location.file for f in fixed.findings} == {"network-capture/network.pcap"}
    assert {f.location.file for f in direct.findings} == {"network.pcap"}
    assert len(fixed.sessions) == len(direct.sessions) == 121
    assert {s.session_id for s in fixed.sessions}.isdisjoint({s.session_id for s in direct.sessions})
    assert not fixed.errors and not direct.errors


def test_hybrid_session_keeps_unknown_authentication_and_safe_kex():
    data = _run([ROOT / "network-capture/network.pcap"], scan_root=ROOT)
    got = observations(data)
    hybrids = [s for s in got["session"] if s["negotiated_group"] == "X25519MLKEM768"]
    assert len(hybrids) == 7
    assert all(
        s["tier_kex"] == "SAFE" and s["tier_session"] == "UNKNOWN" and s["cert_key"] is None for s in hybrids
    )
    wants = [
        dict(
            kind="session",
            source=s["source"],
            source_type=s["source_type"],
            session_sni=s["session_sni"],
            transport="tls",
            tier_session="UNKNOWN",
            tier_kex="SAFE",
            negotiated_group="X25519MLKEM768",
        )
        for s in hybrids
    ]
    # This tests evaluator behavior against real session projections, not owner-confirmed ground truth.
    report = evaluate(wants, data, required=set())
    assert not any("wrong tier" in f or "missed" in f or "ambiguous" in f for f in report.failures)
    assert not report.passed  # session assertions alone must never establish algorithm accuracy
    wants[0]["tier_session"] = "SAFE"
    assert any("wrong tier_session" in f for f in evaluate(wants, data, required=set()).failures)


def test_explicit_container_assertion_does_not_inflate_metrics():
    f = finding(raw="TLS_RSA_WITH_AES_128_CBC_SHA", usage=Usage.UNKNOWN).model_copy(
        update={"kind_hint": KindHint.CIPHER_SUITE}
    )
    data = result(f)
    inventory = observations(data)["inventory"]
    assert inventory
    container = inventory[0]
    want = dict(
        kind="asset",
        source="sample.py",
        source_type="code",
        asset_type="protocol",
        canonical=container["canonical"],
        tier=container["tier"],
    )
    report = evaluate([want], data, required=set())
    assert report.metrics["overall"].matched == 0
    assert not any("missed" in d for d in report.diagnostics)
    assert not report.passed


@pytest.mark.parametrize("code", [0, 1, 2])
def test_cli_eval_propagates_gate_exit_codes(monkeypatch, code):
    from typer.testing import CliRunner

    from quantumtrace import cli, evaluation

    monkeypatch.setattr(evaluation, "main", lambda argv: code)
    assert CliRunner().invoke(cli.app, ["eval"]).exit_code == code


def test_optional_source_type_uses_observed_source_without_basename_guessing():
    want = row()
    del want["source_type"]
    report = evaluate([want], result(finding()), required={"code"})
    assert report.passed and report.metrics["code"] == Metrics(1, 1, 1, 1)
