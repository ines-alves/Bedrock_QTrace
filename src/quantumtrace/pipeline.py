"""Deterministic input routing and recoverable scan orchestration."""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quantumtrace import __version__
from quantumtrace.engine import classify_findings
from quantumtrace.engine.aggregate import aggregate
from quantumtrace.engine.score import score
from quantumtrace.engine.sessions import build_sessions
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import Finding, ScanError, ScanOptions, ScanResult
from quantumtrace.scanners.base import Scanner, select_scanners

# Owner detection modules self-register; absent deliveries are not replaced by M1 scanners.
_ADAPTER_MODULES = (
    "quantumtrace.scanners.cloud.acm",
    "quantumtrace.scanners.cloud.kms",
    "quantumtrace.scanners.cloud.loadbalancer",
    "quantumtrace.scanners.code.engine",
    "quantumtrace.scanners.code.manifests",
)


def _load_adapters() -> list[ScanError]:
    errors = []
    for module in _ADAPTER_MODULES:
        try:
            importlib.import_module(module)
        except Exception as exc:
            errors.append(
                ScanError(detector="pipeline", message=f"adapter {module}: {type(exc).__name__}: {exc}")
            )
    return errors


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _files(
    inputs: list[str | Path], options: ScanOptions, errors: list[ScanError]
) -> list[tuple[Path, Path]]:
    files: dict[Path, tuple[Path, Path]] = {}
    excluded = set(options.exclude_dirs)

    def visit(path: Path, root: Path) -> None:
        try:
            if path.is_dir():
                if path.name in excluded or path.is_symlink():
                    return
                for child in sorted(path.iterdir()):
                    visit(child, root)
            elif path.is_file():
                real = path.resolve()
                files.setdefault(real, (path, root))
            else:
                errors.append(
                    ScanError(detector="pipeline", path=str(path), message="missing or unsupported input")
                )
        except OSError as exc:
            errors.append(ScanError(detector="pipeline", path=str(path), message=f"input traversal: {exc}"))

    # Outer directory roots win over their descendants and explicit overlapping files.
    paths = sorted({Path(item).absolute() for item in inputs}, key=lambda path: (len(path.parts), str(path)))
    for path in paths:
        try:
            visit(path, path if path.is_dir() else path.parent)
        except OSError as exc:
            errors.append(ScanError(detector="pipeline", path=str(path), message=f"input traversal: {exc}"))
    return sorted(files.values(), key=lambda item: (str(item[1]), str(item[0])))


def _route(path: Path, scanners: list[Scanner], errors: list[ScanError]) -> Scanner | None:
    for scanner in sorted(scanners, key=lambda scanner: ("generic_json" in scanner.name, scanner.name)):
        try:
            if scanner.can_handle(path):
                return scanner
        except Exception as exc:
            errors.append(
                ScanError(
                    detector=scanner.name, path=str(path), message=f"can_handle: {type(exc).__name__}: {exc}"
                )
            )
    return None


def run(
    inputs: list[str | Path], probes: list[str] | None = None, options: ScanOptions | None = None
) -> ScanResult:
    """Run published adapters, preserve partial results, and return the native shared model."""
    started = datetime.now(UTC)
    settings = options if options is not None else ScanOptions()
    errors = _load_adapters()
    try:
        scanners = select_scanners(settings.scanner_names)
    except ValueError as exc:
        errors.append(ScanError(detector="pipeline", message=str(exc)))
        scanners = []
    findings = []
    for path, root in _files(inputs, settings, errors):
        scanner = _route(path, scanners, errors)
        if scanner is None:
            errors.append(
                ScanError(detector="pipeline", path=str(path), message="no selected scanner supports input")
            )
            continue
        try:
            for item in scanner.scan(path, root):
                if isinstance(item, Finding):
                    findings.append(item)
                elif isinstance(item, ScanError):
                    errors.append(item)
                else:
                    errors.append(
                        ScanError(detector=scanner.name, path=str(path), message="invalid scanner result")
                    )
        except Exception as exc:
            errors.append(
                ScanError(detector=scanner.name, path=str(path), message=f"scan: {type(exc).__name__}: {exc}")
            )
    for target in sorted(set(probes or [])):
        errors.append(
            ScanError(
                detector="pipeline.probe", path=target, message="requested probe adapter is unavailable"
            )
        )
    # Keep distinct metadata emissions even when scanner IDs coincide; repeated identical rows are idempotent.
    findings = sorted(
        {_dump(item.model_dump(mode="json")): item for item in findings}.values(),
        key=lambda item: (item.id, _dump(item.model_dump(mode="json"))),
    )
    knowledge = load_kb()
    roots = classify_findings(findings, knowledge, started)
    assets, summary = score(aggregate(roots), knowledge.scoring)
    sessions, session_errors = build_sessions(findings, roots)
    errors.extend(session_errors)
    errors = [
        ScanError.model_validate(json.loads(payload))
        for payload in sorted({_dump(item.model_dump(mode="json")) for item in errors})
    ]
    normalized_inputs = sorted({str(Path(item).absolute()) for item in inputs})
    normalized_options = settings.model_dump(mode="json")
    normalized_options["exclude_dirs"] = sorted(set(settings.exclude_dirs))
    if settings.scanner_names is not None:
        normalized_options["scanner_names"] = sorted(set(settings.scanner_names))
    identity: dict[str, Any] = {
        "inputs": normalized_inputs,
        "probes": sorted(set(probes or [])),
        "options": normalized_options,
        "findings": [item.model_dump(mode="json") for item in findings],
    }
    # Source timestamp is retained metadata, but never enters a scan identity.
    for identity_row in identity["findings"]:
        identity_row["extra"].pop("source_timestamp", None)
    scan_id = hashlib.sha256(_dump(identity).encode()).hexdigest()[:16]
    return ScanResult(
        tool_version=__version__,
        scan_id=scan_id,
        started_at=started.isoformat(),
        finished_at=datetime.now(UTC).isoformat(),
        inputs=normalized_inputs,
        findings=findings,
        assets=assets,
        sessions=sessions,
        summary=summary,
        errors=errors,
    )
