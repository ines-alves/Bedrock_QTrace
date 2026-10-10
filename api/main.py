"""Thin HTTP layer: serves a ScanResult and its CBOM, report and scoring views, no business logic."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from quantumtrace.kb.loader import KnowledgeBaseError, load_scoring
from quantumtrace.models import ScanResult
from quantumtrace.output.cyclonedx import build_cbom, validate_cbom
from quantumtrace.output.markdown import render_markdown_summary

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "out" / "report.json"
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"
DIST = ROOT / "frontend" / "dist"

app = FastAPI(title="QuantumTrace")


class ScanRequest(BaseModel):
    """Inputs to scan, relative to the repository root or absolute."""

    paths: list[str] = Field(min_length=1)


class Validation(BaseModel):
    valid: bool
    errors: list[str]


def _current() -> ScanResult:
    """Latest scan from out/report.json, or the bundled sample when no scan has run."""
    return ScanResult.model_validate_json((REPORT if REPORT.exists() else SAMPLE).read_text())


def _pipeline_run() -> Callable[..., ScanResult]:
    """Import lazily: pipeline.run belongs to M1 and may not be on this branch yet."""
    try:
        from quantumtrace.pipeline import run
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="pipeline.run is not available in this build") from exc
    return run


@app.get("/api/result", response_model=ScanResult)
def result() -> ScanResult:
    return _current()


@app.post("/api/scan", response_model=ScanResult)
def scan(request: ScanRequest) -> ScanResult:
    """Scan server-side paths, store the result as out/report.json and return it."""
    run = _pipeline_run()
    paths = [ROOT / item for item in request.paths]
    missing = [item for item, path in zip(request.paths, paths, strict=True) if not path.exists()]
    if missing:
        raise HTTPException(status_code=400, detail=f"paths not found: {', '.join(missing)}")
    scanned = run(paths)
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(scanned.model_dump_json())
    return scanned


@app.get("/api/cbom")
def cbom() -> dict[str, Any]:
    return build_cbom(_current())


@app.get("/api/validate", response_model=Validation)
def validate() -> Validation:
    errors = validate_cbom(build_cbom(_current()))
    return Validation(valid=not errors, errors=errors)


@app.get("/api/report.md", response_class=PlainTextResponse)
def report_md() -> PlainTextResponse:
    return PlainTextResponse(render_markdown_summary(_current()), media_type="text/markdown")


@app.get("/api/scoring")
def scoring() -> dict[str, Any]:
    """The engine's scoring data, read-only and outside ScanResult."""
    try:
        return load_scoring().as_dict()
    except KnowledgeBaseError as exc:
        raise HTTPException(status_code=503, detail=f"scoring data unavailable: {exc}") from exc


# Registered last so the routes above win. The Vite dev server proxies /api, so no CORS is needed.
if DIST.is_dir():
    app.mount("/", StaticFiles(directory=DIST, html=True), name="frontend")
