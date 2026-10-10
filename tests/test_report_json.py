"""Native contract preservation and failure-safe file replacement."""

import json
from pathlib import Path

import pytest

from quantumtrace.models import RoadmapItem, ScanResult
from quantumtrace.output import report_json


def sample():
    path = Path(__file__).parent / "fixtures" / "scan_result_sample.json"
    return ScanResult.model_validate_json(path.read_text())


def test_native_roundtrip_unicode_partial_errors_and_optional_roadmap(tmp_path):
    result = sample()
    result.roadmap = None
    target = tmp_path / "nested" / "report.json"
    report_json.write_report_json(result, target)
    assert "roadmap" not in json.loads(target.read_text())
    assert ScanResult.model_validate_json(target.read_text()) == result
    result.roadmap = [RoadmapItem(phase=0, action="Réparer", asset_ids=[], occurrence_count=1)]
    before = result.model_dump(mode="json")
    report_json.write_report_json(result, target)
    assert "Réparer" in target.read_text() and target.read_bytes().endswith(b"\n")
    assert ScanResult.model_validate_json(target.read_text()) == result
    assert result.model_dump(mode="json") == before
    assert len(list(target.parent.iterdir())) == 1


@pytest.mark.parametrize("stage", ["fsync", "replace"])
def test_failure_preserves_previous_report_and_cleans_temporary_file(monkeypatch, tmp_path, stage):
    target = tmp_path / "report.json"
    target.write_text("previous report")

    def fail(*args):
        raise OSError("injected filesystem failure")

    monkeypatch.setattr(report_json.os, stage, fail)
    with pytest.raises(OSError, match="cannot write JSON report"):
        report_json.write_report_json(sample(), target)
    assert target.read_text() == "previous report"
    assert list(tmp_path.iterdir()) == [target]


def test_serialization_failure_does_not_touch_destination(tmp_path):
    target = tmp_path / "report.json"
    target.write_text("previous report")
    with pytest.raises(ValueError):
        report_json.write_json_document({"value": float("nan")}, target)
    assert target.read_text() == "previous report" and list(tmp_path.iterdir()) == [target]


def test_invalid_parent_reports_destination(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("existing")
    with pytest.raises(OSError, match="report.json"):
        report_json.write_report_json(sample(), blocked / "report.json")
    assert blocked.read_text() == "existing"
