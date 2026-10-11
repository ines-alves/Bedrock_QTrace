"""Thin HTTP layer: serves a ScanResult and its CBOM, report and scoring views, no business logic."""

import os
import shutil
import tempfile
from collections.abc import Callable
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Form, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from api import archive
from quantumtrace.engine import classify_findings
from quantumtrace.engine.aggregate import aggregate
from quantumtrace.engine.roadmap import build_roadmap
from quantumtrace.engine.score import score
from quantumtrace.engine.sessions import build_sessions
from quantumtrace.kb.loader import KnowledgeBaseError, load_kb, load_scoring
from quantumtrace.models import ScanOptions, ScanResult
from quantumtrace.output.cyclonedx import build_cbom, redact_result, validate_cbom
from quantumtrace.output.markdown import render_markdown_summary

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "out" / "report.json"
# The starter kit that ships with the app; "scan the starter kit" runs the pipeline over these folders.
STARTER_KIT = ("sample-repos", "cloud-posture", "network-capture")
# A prebuilt result for the tests and the frontend types. The API never serves it.
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"
DIST = ROOT / "frontend" / "dist"
UPLOADS = ROOT / "out" / "uploads"

# What the Code, Cloud and Network boxes stand for: the scanners that look for that kind of evidence.
SCAN_TYPES: dict[str, tuple[str, ...]] = {
    "code": ("code.regex", "code.manifest", "config.keyfile", "config.webserver"),
    "cloud": ("cloud.kms", "cloud.loadbalancer", "cloud.acm"),
    "network": ("pcap",),
}

app = FastAPI(title="QuantumTrace")


class ScanRequest(BaseModel):
    """Inputs to scan, relative to the repository root or absolute."""

    paths: list[str] = Field(min_length=1)
    types: list[str] | None = None


def _options(types: list[str] | None) -> ScanOptions | None:
    """Scanner selection for the chosen types; None (every scanner) when no type was named or all were."""
    if types is None:
        return None
    unknown = sorted(set(types) - set(SCAN_TYPES))
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"unknown scan type: {', '.join(unknown)}. Choose from code, cloud, network.",
        )
    if not types:
        raise HTTPException(status_code=400, detail="Pick at least one of code, cloud and network.")
    if set(types) == set(SCAN_TYPES):
        return None
    return ScanOptions(scanner_names=sorted({name for kind in set(types) for name in SCAN_TYPES[kind]}))


def _runner(run: Callable[..., ScanResult], types: list[str] | None) -> Callable[..., ScanResult]:
    """The pipeline entry point with the chosen scanner selection applied."""
    options = _options(types)
    return run if options is None else partial(run, options=options)


class Validation(BaseModel):
    valid: bool
    errors: list[str]


def _current() -> ScanResult:
    """The stored scan (out/report.json); 404 while nothing has been scanned or loaded.

    Every endpoint reads through here, so no served output carries more than a key file's header line.
    """
    if not REPORT.exists():
        raise HTTPException(status_code=404, detail="No scan yet. Scan something first.")
    return redact_result(ScanResult.model_validate_json(REPORT.read_text()))


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


def _without_test_code(full: ScanResult) -> ScanResult:
    """The same scan with every test-code finding left out and the engine run again on what remains.

    Assets, score, tier counts, roadmap and sessions all come from the engine's own functions, so the
    numbers are exactly what a scan of the non-test evidence would give. Nothing is scored here.
    """
    findings = [finding for finding in full.findings if not finding.in_test_code]
    if len(findings) == len(full.findings):
        return full
    knowledge = load_kb()
    roots = classify_findings(findings, knowledge, datetime.fromisoformat(full.started_at))
    evidence = aggregate(roots)
    assets, summary = score(evidence, knowledge.scoring)
    sessions, _ = build_sessions(findings, roots)
    return full.model_copy(
        update={
            "findings": findings,
            "assets": assets,
            "sessions": sessions,
            "summary": summary,
            "roadmap": build_roadmap(evidence),
        }
    )


@app.get("/api/result", response_model=ScanResult)
def result(include_tests: bool = True) -> ScanResult:
    """The stored scan. `include_tests=false` drops test-code findings and scores what remains."""
    current = _current()
    return current if include_tests else _without_test_code(current)


@app.get("/api/source")
def source() -> dict[str, str]:
    """Whether a scan is stored: `scan`, or `none` while the dashboard is empty."""
    return {"source": "scan" if REPORT.exists() else "none"}


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
    return _store(_runner(run, request.types)(paths))


class GithubRequest(BaseModel):
    url: str
    types: list[str] | None = None


class StarterKitRequest(BaseModel):
    types: list[str] | None = None


@app.delete("/api/scan")
def clear_scan() -> dict[str, str]:
    """Forget the stored scan and its unpacked uploads; the dashboard is empty until the next scan."""
    REPORT.unlink(missing_ok=True)
    shutil.rmtree(UPLOADS, ignore_errors=True)
    return {"source": "none"}


@app.post("/api/scan/starter-kit", response_model=ScanResult)
def scan_starter_kit(request: StarterKitRequest | None = None) -> ScanResult:
    """Scan the whole starter kit that ships with the app, exactly like any other folders."""
    return scan(ScanRequest(paths=list(STARTER_KIT), types=request.types if request else None))


@app.post("/api/scan/upload", response_model=ScanResult)
def scan_upload(file: UploadFile, types: Annotated[str | None, Form()] = None) -> ScanResult:
    """Scan a zipped repository sent from the browser; `types` is a comma separated list such as code,cloud."""
    run = _runner(_pipeline_run(), None if types is None else [t for t in types.split(",") if t])
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
    run = _runner(_pipeline_run(), request.types)
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
