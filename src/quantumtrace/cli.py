"""Installed CLI for scans, native and owner reports, evaluation and the API UI."""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from quantumtrace.models import ScanResult, Tier
from quantumtrace.output.report_json import write_json_document, write_report_json
from quantumtrace.pipeline import run

app = typer.Typer(no_args_is_help=True, help="Inventory cryptography and plan post-quantum migration.")
console = Console()
errors = Console(stderr=True)


def _fail(message: str) -> NoReturn:
    errors.print(f"[red]Error:[/red] {escape(message)}")
    raise typer.Exit(2)


def _writers(formats: str) -> tuple[tuple[str, ...], dict[str, Any]]:
    names = tuple(dict.fromkeys(part.strip().lower() for part in formats.split(",")))
    unknown = sorted(set(names) - {"json", "cbom", "md"})
    if unknown:
        _fail(f"Unsupported format: {', '.join(unknown) or '<empty>'}. Choose json, cbom or md.")
    writers: dict[str, Any] = {}
    try:
        if "cbom" in names:
            module = importlib.import_module("quantumtrace.output.cyclonedx")
            writers["build_cbom"] = module.build_cbom
            writers["validate_cbom"] = module.validate_cbom
        if "md" in names:
            writers["md"] = importlib.import_module("quantumtrace.output.markdown").write_markdown_summary
    except (ImportError, AttributeError) as exc:
        _fail(f"Requested output writer is unavailable: {exc}")
    return names, writers


def _summary(result: ScanResult) -> None:
    summary = result.summary
    console.print(
        f"Grade {summary.grade} | Risk score {summary.score}/100 | "
        f"Quantum readiness {summary.readiness_pct:.1f}%"
    )
    counts = Table(title="Scored assets")
    for tier in Tier:
        counts.add_column(tier.value)
    counts.add_row(*(str(summary.counts_by_tier.get(tier.value, 0)) for tier in Tier))
    console.print(counts)
    by_id = {asset.asset_id: asset for asset in result.assets}
    risks = Table(title="Top risks")
    for column in ("Algorithm", "Usage", "Tier", "Risk points"):
        risks.add_column(column)
    for asset_id in summary.top_risks[:10]:
        if asset_id in by_id:
            asset = by_id[asset_id]
            parameters = " / ".join(
                str(value) for value in (asset.key_size, asset.curve, asset.mode) if value
            )
            label = asset.canonical_name + (f" ({parameters})" if parameters else "")
            risks.add_row(escape(label), asset.usage.value, asset.tier.value, f"{asset.risk_points:.2f}")
    if risks.row_count:
        console.print(risks)
    if result.errors:
        errors.print(f"[yellow]Coverage incomplete: {len(result.errors)} error(s).[/yellow]")
        for error in result.errors:
            errors.print(escape(f"{error.detector}: {error.path or '<scan>'}: {error.message}"))


@app.command()
def scan(
    paths: Annotated[list[Path], typer.Argument(help="Files or directories to scan.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output directory.")] = Path("out"),
    formats: Annotated[str, typer.Option("--format", "-f", help="Comma-separated json,cbom,md.")] = "json",
    probe: Annotated[
        list[str] | None, typer.Option("--probe", help="Explicit host:port; repeatable.")
    ] = None,
) -> None:
    """Scan inputs, write selected reports and display risk and coverage."""
    names, writers = _writers(formats)
    try:
        inputs: list[str | Path] = list(paths)
        result = run(inputs, probes=probe)
        cbom = None
        if "cbom" in names:
            cbom = writers["build_cbom"](result)
            validation = writers["validate_cbom"](cbom)
            if validation:
                _fail("CBOM validation failed: " + "; ".join(validation))
        for name in names:
            if name == "json":
                write_report_json(result, out / "report.json")
            elif name == "cbom":
                assert cbom is not None
                write_json_document(cbom, out / "cbom.json")
            else:
                writers["md"](result, out / "summary.md")
    except typer.Exit:
        raise
    except Exception as exc:
        _fail(f"Scan or report generation failed: {exc}")
    _summary(result)
    console.print("Reports: " + escape(str(out)))
    if result.errors:
        raise typer.Exit(2)


@app.command("eval")
def evaluate() -> None:
    """Evaluate golden accuracy when task 1.12 is available."""
    script = Path.cwd() / "scripts" / "eval.py"
    if not script.is_file():
        _fail("Evaluation is unavailable: scripts/eval.py is planned for task 1.12.")
    try:
        completed = subprocess.run([sys.executable, str(script)], check=False)
    except OSError as exc:
        _fail(f"Evaluation failed: {exc}")
    if completed.returncode:
        raise typer.Exit(2)


@app.command()
def ui(
    host: Annotated[str, typer.Option(help="API bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535, help="API port.")] = 8000,
) -> None:
    """Serve M4's API and built frontend from the repository root."""
    root = Path.cwd()
    if (root / "api" / "main.py").is_file() and str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        module = importlib.import_module("api.main")
        if not hasattr(module, "app"):
            _fail("UI is unavailable: api.main:app has not been delivered.")
        uvicorn = importlib.import_module("uvicorn")
        uvicorn.run("api.main:app", host=host, port=port)
    except typer.Exit:
        raise
    except (ImportError, OSError, RuntimeError) as exc:
        _fail(f"UI is unavailable: {exc}")
    except SystemExit as exc:
        if exc.code:
            _fail("UI server failed to start.")


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
