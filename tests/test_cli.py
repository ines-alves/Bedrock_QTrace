"""CLI exit semantics, real output integration and explicit unavailable features."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from quantumtrace import cli
from quantumtrace.models import ScanError, ScanResult
from quantumtrace.output.cyclonedx import validate_cbom

runner = CliRunner()


@pytest.fixture
def sample(monkeypatch):
    path = Path(__file__).parent / "fixtures" / "scan_result_sample.json"
    result = ScanResult.model_validate_json(path.read_text())
    result.errors = []
    monkeypatch.setattr(cli, "run", lambda *args, **kwargs: result)
    return result


def test_help_and_complete_scan_default_native_output(sample, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    help_result = runner.invoke(cli.app, ["--help"])
    assert help_result.exit_code == 0 and all(name in help_result.output for name in ("scan", "eval", "ui"))
    result = runner.invoke(cli.app, ["scan", "input"])
    assert result.exit_code == 0 and "Grade" in result.output and "Scored assets" in result.output
    assert ScanResult.model_validate_json((tmp_path / "out" / "report.json").read_text()) == sample


def test_real_starter_partial_scan_writes_all_requested_valid_reports(tmp_path):
    root = Path(__file__).resolve().parents[1]
    invocation = runner.invoke(
        cli.app,
        [
            "scan",
            str(root / "sample-repos"),
            str(root / "cloud-posture"),
            str(root / "network-capture"),
            "--out",
            str(tmp_path),
            "--format",
            "json,cbom,md",
        ],
    )
    assert invocation.exit_code == 2 and "Coverage incomplete: 3" in invocation.output
    result = ScanResult.model_validate_json((tmp_path / "report.json").read_text())
    assert (len(result.findings), len(result.assets), len(result.sessions)) == (1056, 660, 121)
    assert result.roadmap and result.summary.score == 60
    assert len(result.errors) == 3
    cbom = json.loads((tmp_path / "cbom.json").read_text())
    assert validate_cbom(cbom) == [] and len(cbom["components"]) == 665
    markdown = (tmp_path / "summary.md").read_text()
    assert "cryptography" in markdown and "Phase 0" in markdown


def test_real_complete_capture_scan_and_missing_input(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = runner.invoke(
        cli.app, ["scan", str(root / "network-capture" / "network.pcap"), "--out", str(tmp_path / "complete")]
    )
    assert result.exit_code == 0
    report = ScanResult.model_validate_json((tmp_path / "complete" / "report.json").read_text())
    assert len(report.sessions) == 121 and not report.errors
    missing = runner.invoke(cli.app, ["scan", str(tmp_path / "missing"), "--out", str(tmp_path / "partial")])
    assert missing.exit_code == 2 and "missing or unsupported input" in " ".join(missing.output.split())
    assert ScanResult.model_validate_json((tmp_path / "partial" / "report.json").read_text()).errors


@pytest.mark.parametrize("formats", ["pdf", "", "json,invalid", "json,"])
def test_invalid_formats_fail_before_scan(monkeypatch, tmp_path, formats):
    def fail(*args, **kwargs):
        raise AssertionError("invalid format must not scan")

    monkeypatch.setattr(cli, "run", fail)
    result = runner.invoke(cli.app, ["scan", "input", "--format", formats, "--out", str(tmp_path)])
    assert result.exit_code == 2 and "Unsupported format" in result.output
    assert not list(tmp_path.iterdir())


def test_missing_writer_fails_before_scan(monkeypatch, tmp_path):
    def missing(name):
        raise ImportError("owner writer absent")

    monkeypatch.setattr(cli.importlib, "import_module", missing)
    result = runner.invoke(cli.app, ["scan", "input", "--format", "md", "--out", str(tmp_path)])
    assert result.exit_code == 2 and "writer is unavailable" in result.output
    assert not list(tmp_path.iterdir())


def test_invalid_cbom_is_never_written(sample, monkeypatch, tmp_path):
    owner = SimpleNamespace(build_cbom=lambda result: {}, validate_cbom=lambda cbom: ["invalid reference"])
    monkeypatch.setattr(cli.importlib, "import_module", lambda name: owner)
    result = runner.invoke(cli.app, ["scan", "input", "--format", "json,cbom", "--out", str(tmp_path)])
    assert result.exit_code == 2 and "CBOM validation failed: invalid reference" in result.output
    assert not list(tmp_path.iterdir())


def test_filesystem_failure_is_exit_two_and_preserves_existing_file(sample, tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("existing")
    result = runner.invoke(cli.app, ["scan", "input", "--out", str(blocked)])
    assert result.exit_code == 2 and "cannot write JSON report" in result.output
    assert blocked.read_text() == "existing"


def test_repeated_explicit_probes_delegate_without_changing_targets(sample, monkeypatch, tmp_path):
    calls = []

    def capture(paths, probes):
        calls.append((paths, probes))
        sample.errors = [
            ScanError(detector="pipeline.probe", path=target, message="unavailable") for target in probes
        ]
        return sample

    monkeypatch.setattr(cli, "run", capture)
    result = runner.invoke(
        cli.app,
        ["scan", "input", "--probe", "example.com:443", "--probe", "[::1]:443", "--out", str(tmp_path)],
    )
    assert result.exit_code == 2 and calls == [([Path("input")], ["example.com:443", "[::1]:443"])]
    assert len(ScanResult.model_validate_json((tmp_path / "report.json").read_text()).errors) == 2


def test_eval_missing_repository_is_explicit(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 2 and "Evaluation setup failed" in result.output


def test_ui_uses_owner_app_and_uvicorn_without_starting_server(monkeypatch):
    calls = []
    owner = SimpleNamespace(app=object())
    server = SimpleNamespace(run=lambda app, **options: calls.append((app, options)))
    monkeypatch.setattr(cli.importlib, "import_module", lambda name: owner if name == "api.main" else server)
    result = runner.invoke(cli.app, ["ui", "--port", "8123"])
    assert result.exit_code == 0 and calls == [("api.main:app", {"host": "127.0.0.1", "port": 8123})]


def test_ui_unavailable_and_invalid_port(monkeypatch):
    def unavailable(name):
        raise ImportError("API not delivered")

    monkeypatch.setattr(cli.importlib, "import_module", unavailable)
    assert runner.invoke(cli.app, ["ui"]).exit_code == 2
    assert runner.invoke(cli.app, ["ui", "--port", "0"]).exit_code == 2


def test_ui_server_start_failure_is_exit_two(monkeypatch):
    def failed_server(*args, **kwargs):
        raise SystemExit(3)

    owner = SimpleNamespace(app=object())
    server = SimpleNamespace(run=failed_server)
    monkeypatch.setattr(cli.importlib, "import_module", lambda name: owner if name == "api.main" else server)
    result = runner.invoke(cli.app, ["ui"])
    assert result.exit_code == 2 and "UI server failed to start" in result.output
