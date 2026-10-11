"""API routes serve valid views of one ScanResult and publish the OpenAPI schema the frontend types come from.

httpx is not installed, so the route functions are called directly instead of through TestClient.
"""

import asyncio
import os
import sys
import types
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException

import api.main as main
from api.main import (
    ScanRequest,
    SinglePageApp,
    app,
    browse,
    cbom,
    report_md,
    result,
    scan,
    scoring,
    source,
    validate,
)
from quantumtrace.kb.loader import KnowledgeBaseError
from quantumtrace.models import ScanResult
from quantumtrace.output.cyclonedx import build_cbom
from quantumtrace.output.markdown import render_markdown_summary


@pytest.fixture(autouse=True)
def _no_scan_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Docker image sets QTRACE_SCAN_ROOTS; tests must not depend on the environment they run in."""
    monkeypatch.delenv("QTRACE_SCAN_ROOTS", raising=False)


@pytest.fixture
def sample(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ScanResult:
    """The bundled sample, with out/report.json redirected so no real scan output interferes."""
    monkeypatch.setattr(main, "REPORT", tmp_path / "out" / "report.json")
    return ScanResult.model_validate_json(main.SAMPLE.read_text())


def _stub_pipeline(monkeypatch: pytest.MonkeyPatch, sample: ScanResult) -> list[list[Path]]:
    calls: list[list[Path]] = []
    module = types.ModuleType("quantumtrace.pipeline")

    def run(inputs: list[Path]) -> ScanResult:
        calls.append(inputs)
        return sample

    module.run = run  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quantumtrace.pipeline", module)
    return calls


def test_nothing_is_served_until_a_scan_has_run(monkeypatch: pytest.MonkeyPatch, sample: ScanResult):
    assert source() == {"source": "none"}
    for route in (result, cbom, validate, report_md):
        with pytest.raises(HTTPException) as error:
            route()
        assert error.value.status_code == 404 and "No scan yet" in error.value.detail
    _stub_pipeline(monkeypatch, sample)
    assert main.scan_starter_kit() == sample
    assert source() == {"source": "scan"} and result() == sample


def test_openapi_exposes_scan_result():
    schema = app.openapi()
    ref = schema["paths"]["/api/result"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert ref["$ref"].endswith("/ScanResult")
    assert {"ScanResult", "CryptoAsset", "Finding", "TLSSession", "RiskSummary"} <= set(
        schema["components"]["schemas"]
    )
    assert {"/api/scan", "/api/cbom", "/api/validate", "/api/report.md", "/api/scoring"} <= set(
        schema["paths"]
    )


def test_cbom_and_validate_use_the_current_result(sample: ScanResult):
    main.REPORT.parent.mkdir(exist_ok=True)
    main.REPORT.write_text(sample.model_dump_json())
    assert cbom() == build_cbom(sample)
    assert validate().model_dump() == {"valid": True, "errors": []}


def test_report_md_is_the_markdown_summary(sample: ScanResult):
    main.REPORT.parent.mkdir(exist_ok=True)
    main.REPORT.write_text(sample.model_dump_json())
    response = report_md()
    assert response.media_type == "text/markdown"
    assert response.body.decode() == render_markdown_summary(sample)


def test_scoring_serves_engine_data_and_reports_unavailable(monkeypatch: pytest.MonkeyPatch):
    assert {"tier_weights", "exposure", "grade_bands"} <= set(scoring())

    def broken() -> None:
        raise KnowledgeBaseError("scoring.yaml: missing")

    monkeypatch.setattr(main, "load_scoring", broken)
    with pytest.raises(HTTPException) as error:
        scoring()
    assert error.value.status_code == 503 and "scoring.yaml" in error.value.detail


def test_scan_is_503_when_the_pipeline_is_not_available(monkeypatch: pytest.MonkeyPatch, sample: ScanResult):
    monkeypatch.setitem(sys.modules, "quantumtrace.pipeline", None)
    with pytest.raises(HTTPException) as error:
        scan(ScanRequest(paths=["sample-repos"]))
    assert error.value.status_code == 503 and "pipeline.run" in error.value.detail


def test_scan_runs_the_pipeline_stores_the_report_and_result_reads_it_back(
    monkeypatch: pytest.MonkeyPatch, sample: ScanResult
):
    calls = _stub_pipeline(monkeypatch, sample)
    scanned = scan(ScanRequest(paths=["sample-repos", "cloud-posture"]))
    assert calls == [[main.ROOT / "sample-repos", main.ROOT / "cloud-posture"]]
    assert scanned == sample and main.REPORT.exists()
    assert result() == sample


def test_scan_rejects_missing_paths_before_running(monkeypatch: pytest.MonkeyPatch, sample: ScanResult):
    calls = _stub_pipeline(monkeypatch, sample)
    with pytest.raises(HTTPException) as error:
        scan(ScanRequest(paths=["sample-repos", "no-such-dir"]))
    assert error.value.status_code == 400 and "no-such-dir" in error.value.detail
    assert "sample-repos" not in error.value.detail and calls == [] and not main.REPORT.exists()


def test_scan_requires_at_least_one_path():
    with pytest.raises(ValueError):
        ScanRequest(paths=[])


def test_scan_is_limited_to_the_configured_roots(monkeypatch: pytest.MonkeyPatch, sample: ScanResult):
    calls = _stub_pipeline(monkeypatch, sample)
    monkeypatch.setenv("QTRACE_SCAN_ROOTS", str(main.ROOT / "sample-repos"))
    for outside in ("cloud-posture", "sample-repos/../cloud-posture", "/etc"):
        with pytest.raises(HTTPException) as error:
            scan(ScanRequest(paths=[outside]))
        assert error.value.status_code == 400 and outside in error.value.detail
    assert calls == []
    scan(ScanRequest(paths=["sample-repos"]))
    assert calls == [[main.ROOT / "sample-repos"]]


def _serve(directory: Path, path: str):
    scope = {"type": "http", "method": "GET", "headers": []}
    return asyncio.run(SinglePageApp(directory=directory, html=True).get_response(path, scope))


def test_single_page_app_falls_back_to_index_but_not_for_api_or_asset_paths(tmp_path: Path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<html>app</html>")
    (tmp_path / "assets" / "a.js").write_text("js")
    assert _serve(tmp_path, "assets/a.js").path == str(tmp_path / "assets" / "a.js")
    assert _serve(tmp_path, "code-config").path == str(tmp_path / "index.html")
    for missing in ("api/typo", "assets/missing.js"):
        with pytest.raises(StarletteHTTPException) as error:
            _serve(tmp_path, missing)
        assert error.value.status_code == 404


def test_source_is_none_until_a_scan_is_stored(monkeypatch: pytest.MonkeyPatch, sample: ScanResult):
    assert source() == {"source": "none"}
    calls = _stub_pipeline(monkeypatch, sample)
    scan(ScanRequest(paths=["sample-repos"]))
    assert calls and source() == {"source": "scan"}


def test_starter_kit_scan_runs_the_pipeline_over_the_three_kit_folders(
    monkeypatch: pytest.MonkeyPatch, sample: ScanResult
):
    calls = _stub_pipeline(monkeypatch, sample)
    main.scan_starter_kit()
    assert calls == [[main.ROOT / name for name in ("sample-repos", "cloud-posture", "network-capture")]]
    assert main.REPORT.exists()


def test_browse_lists_folders_first_and_hides_tooling():
    top = browse()
    names = [entry.name for entry in top.entries]
    assert top.path == "" and top.parent is None
    assert {"sample-repos", "cloud-posture", "network-capture"} <= set(names)
    assert not {".git", ".venv", "node_modules", "out"} & set(names)
    dirs = [entry.is_dir for entry in top.entries]
    assert dirs == sorted(dirs, reverse=True)
    inside = browse("sample-repos")
    assert inside.parent == "" and all(entry.path.startswith("sample-repos/") for entry in inside.entries)
    assert not [entry.name for entry in inside.entries if entry.name.lower().startswith("readme")]
    with pytest.raises(HTTPException) as error:
        browse("sample-repos/README.md")
    assert error.value.status_code == 400


def test_browse_follows_the_configured_scan_roots(monkeypatch: pytest.MonkeyPatch):
    roots = [main.ROOT / "sample-repos", main.ROOT / "cloud-posture"]
    monkeypatch.setenv("QTRACE_SCAN_ROOTS", os.pathsep.join(str(root) for root in roots))
    top = browse()
    assert [entry.name for entry in top.entries] == ["cloud-posture", "sample-repos"] and top.parent is None
    assert browse("sample-repos").parent == ""
    with pytest.raises(HTTPException) as error:
        browse("network-capture")
    assert error.value.status_code == 400


def _recording_pipeline(monkeypatch: pytest.MonkeyPatch, sample: ScanResult) -> list[object]:
    """A stub pipeline that records the scanner selection each run was given."""
    seen: list[object] = []
    module = types.ModuleType("quantumtrace.pipeline")

    def run(inputs: list[Path], probes=None, options=None) -> ScanResult:
        seen.append(None if options is None else options.scanner_names)
        return sample

    module.run = run  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quantumtrace.pipeline", module)
    return seen


def test_types_select_the_scanners_for_the_kit_and_for_folders(
    monkeypatch: pytest.MonkeyPatch, sample: ScanResult
):
    seen = _recording_pipeline(monkeypatch, sample)
    scan(ScanRequest(paths=["sample-repos"]))
    scan(ScanRequest(paths=["sample-repos"], types=["code", "cloud", "network"]))
    assert seen == [None, None]  # nothing named, or everything named: every scanner runs
    main.scan_starter_kit(main.StarterKitRequest(types=["cloud"]))
    scan(ScanRequest(paths=["sample-repos"], types=["network", "cloud"]))
    assert seen[2] == ["cloud.acm", "cloud.kms", "cloud.loadbalancer"]
    assert seen[3] == ["cloud.acm", "cloud.kms", "cloud.loadbalancer", "pcap"]
    assert sorted(main.SCAN_TYPES["code"]) == [
        "code.manifest",
        "code.regex",
        "config.keyfile",
        "config.webserver",
    ]


def test_unknown_or_empty_types_are_refused_before_running(
    monkeypatch: pytest.MonkeyPatch, sample: ScanResult
):
    seen = _recording_pipeline(monkeypatch, sample)
    for bad, text in (([], "at least one"), (["binary"], "unknown scan type: binary")):
        with pytest.raises(HTTPException) as error:
            scan(ScanRequest(paths=["sample-repos"], types=bad))
        assert error.value.status_code == 400 and text in error.value.detail
    assert seen == [] and not main.REPORT.exists()


def _with_test_code(sample: ScanResult) -> ScanResult:
    """The sample with its Python and Go findings marked as test code."""
    marked = sample.model_copy(deep=True)
    for finding in marked.findings:
        if finding.language in {"python", "go"}:
            finding.in_test_code = True
    return marked


def test_result_without_test_code_is_scored_again_by_the_engine(sample: ScanResult):
    from datetime import datetime

    from quantumtrace.engine import analyze

    marked = _with_test_code(sample)
    kept = [f for f in marked.findings if not f.in_test_code]
    assert 0 < len(kept) < len(marked.findings)
    main.REPORT.parent.mkdir(exist_ok=True)
    main.REPORT.write_text(marked.model_dump_json())

    assert result().findings == marked.findings  # the default is the full scan
    assert result(include_tests=True) == result()
    cut = result(include_tests=False)
    assert cut.findings == kept and not any(f.in_test_code for f in cut.findings)
    assets, summary = analyze(kept, scan_started_at=datetime.fromisoformat(marked.started_at))
    assert cut.assets == assets and cut.summary == summary
    assert cut.scan_id == marked.scan_id and cut.inputs == marked.inputs
    assert {fid for a in cut.assets for fid in a.finding_ids} <= {f.id for f in kept}
    assert result(include_tests=False).roadmap == cut.roadmap
    # The stored scan is untouched by asking for the other view.
    assert result() == result(include_tests=True)


def test_result_without_test_code_is_the_scan_itself_when_it_has_none(sample: ScanResult):
    assert not any(f.in_test_code for f in sample.findings)
    main.REPORT.parent.mkdir(exist_ok=True)
    main.REPORT.write_text(sample.model_dump_json())
    assert result(include_tests=False) == result()
