"""Thin HTTP layer: serves a ScanResult and its CBOM, report and scoring views, no business logic."""

import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from api import archive
from quantumtrace.kb.loader import KnowledgeBaseError, load_scoring
from quantumtrace.models import ScanResult
from quantumtrace.output.cyclonedx import build_cbom, redact_result, validate_cbom
from quantumtrace.output.markdown import render_markdown_summary

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "out" / "report.json"
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"
DIST = ROOT / "frontend" / "dist"
UPLOADS = ROOT / "out" / "uploads"

app = FastAPI(title="QuantumTrace")


class ScanRequest(BaseModel):
    """Inputs to scan, relative to the repository root or absolute."""

    paths: list[str] = Field(min_length=1)


class Validation(BaseModel):
    valid: bool
    errors: list[str]


def _current() -> ScanResult:
    """Latest scan from out/report.json, or the bundled sample when no scan has run.

    Every endpoint reads through here, so no served output carries more than a key file's header line.
    """
    return redact_result(ScanResult.model_validate_json((REPORT if REPORT.exists() else SAMPLE).read_text()))


class Entry(BaseModel):
    name: str
    path: str
    is_dir: bool


class Listing(BaseModel):
    """One folder for the scan picker; path and parent are usable as /api/scan inputs."""

    path: str
    parent: str | None
    entries: list[Entry]
    truncated: bool


MAX_ENTRIES = 300
_NOT_SCANNABLE = {"node_modules", "__pycache__", "out", "dist"}


def _shown(path: Path) -> str:
    """Repo-relative spelling ('' for the repo root) so the same string works as a scan input."""
    if not path.is_relative_to(ROOT):
        return path.as_posix()
    return "" if path == ROOT else path.relative_to(ROOT).as_posix()


def _outside_scan_roots(path: Path) -> bool:
    """True when QTRACE_SCAN_ROOTS (os.pathsep separated, set in the Docker image) does not cover path."""
    roots = os.environ.get("QTRACE_SCAN_ROOTS")
    return roots is not None and not any(
        path.resolve().is_relative_to(Path(root).resolve()) for root in roots.split(os.pathsep)
    )


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


@app.get("/api/source")
def source() -> dict[str, str]:
    """Whether /api/result is a scan run here or the bundled sample."""
    return {"source": "scan" if REPORT.exists() else "sample"}


def _store(scanned: ScanResult) -> ScanResult:
    """Redact a fresh scan, keep it as out/report.json and return it."""
    scanned = redact_result(scanned)
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(scanned.model_dump_json())
    return scanned


@app.post("/api/scan", response_model=ScanResult)
def scan(request: ScanRequest) -> ScanResult:
    """Scan server-side paths, store the result as out/report.json and return it."""
    run = _pipeline_run()
    paths = [ROOT / item for item in request.paths]
    outside = [item for item, path in zip(request.paths, paths, strict=True) if _outside_scan_roots(path)]
    if outside:
        raise HTTPException(
            status_code=400, detail=f"paths outside the allowed scan roots: {', '.join(outside)}"
        )
    missing = [item for item, path in zip(request.paths, paths, strict=True) if not path.exists()]
    if missing:
        raise HTTPException(status_code=400, detail=f"paths not found: {', '.join(missing)}")
    return _store(run(paths))


class GithubRequest(BaseModel):
    url: str


@app.post("/api/scan/upload", response_model=ScanResult)
def scan_upload(file: UploadFile) -> ScanResult:
    """Scan a zipped repository sent from the browser."""
    run = _pipeline_run()
    with tempfile.TemporaryDirectory() as folder:
        zipped = Path(folder) / "upload.zip"
        written = 0
        with zipped.open("wb") as out:
            while chunk := file.file.read(1024 * 1024):
                written += len(chunk)
                if written > archive.MAX_ARCHIVE_BYTES:
                    raise HTTPException(status_code=413, detail="The archive is larger than the 50 MB limit.")
                out.write(chunk)
        label = f"{Path(file.filename or 'archive.zip').name} (uploaded)"
        return _store(archive.scan_zip(zipped, label, UPLOADS, run))


@app.post("/api/scan/github", response_model=ScanResult)
def scan_github(request: GithubRequest) -> ScanResult:
    """Download a public GitHub repository as a zip and scan it."""
    run = _pipeline_run()
    url, label = archive.github_zip_url(request.url)
    with tempfile.TemporaryDirectory() as folder:
        zipped = Path(folder) / "repository.zip"
        archive.download(url, zipped)
        return _store(archive.scan_zip(zipped, label, UPLOADS, run))


@app.get("/api/browse", response_model=Listing)
def browse(path: str = "") -> Listing:
    """List a folder so the UI can offer buttons instead of typed paths; follows the scan roots of /api/scan."""
    target = (ROOT / path).resolve()
    roots = os.environ.get("QTRACE_SCAN_ROOTS")
    if roots and not path:
        children = [Path(root) for root in roots.split(os.pathsep) if Path(root).is_dir()]
        parent = None
    else:
        if _outside_scan_roots(target):
            raise HTTPException(status_code=400, detail=f"path outside the allowed scan roots: {path}")
        if not target.is_dir():
            raise HTTPException(status_code=400, detail=f"not a folder: {path}")
        children = [
            child
            for child in target.iterdir()
            if not child.name.startswith(".")
            and child.name not in _NOT_SCANNABLE
            and not child.name.lower().startswith("readme")
        ]
        parent = (
            None
            if target == ROOT
            else ""
            if roots and _outside_scan_roots(target.parent)
            else _shown(target.parent)
        )
    children.sort(key=lambda child: (not child.is_dir(), child.name.lower()))
    entries = [Entry(name=child.name, path=_shown(child), is_dir=child.is_dir()) for child in children]
    return Listing(
        path=_shown(target) if path else "",
        parent=parent,
        entries=entries[:MAX_ENTRIES],
        truncated=len(entries) > MAX_ENTRIES,
    )


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


class SinglePageApp(StaticFiles):
    """Serve index.html for client-side routes such as /code-config, but keep 404 for unknown /api and /assets paths."""

    async def get_response(self, path, scope):  # type: ignore[no-untyped-def]
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404 or path.startswith(("api/", "assets/")):
                raise
            return await super().get_response("index.html", scope)


# Registered last so the routes above win. The Vite dev server proxies /api, so no CORS is needed.
if DIST.is_dir():
    app.mount("/", SinglePageApp(directory=DIST, html=True), name="frontend")
