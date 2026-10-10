"""Thin HTTP layer: serves a ScanResult, no business logic."""

from pathlib import Path

from fastapi import FastAPI

from quantumtrace.models import ScanResult

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "out" / "report.json"
SAMPLE = ROOT / "tests" / "fixtures" / "scan_result_sample.json"

app = FastAPI(title="QuantumTrace")


@app.get("/api/result", response_model=ScanResult)
def result() -> ScanResult:
    """Latest scan from out/report.json, or the bundled sample when no scan has run."""
    return ScanResult.model_validate_json((REPORT if REPORT.exists() else SAMPLE).read_text())
