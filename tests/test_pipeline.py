"""Routing, error recovery, evidence preservation and available-adapter integration."""

from pathlib import Path

import pytest

from quantumtrace import pipeline
from quantumtrace.models import (
    Finding,
    KindHint,
    Location,
    ScanError,
    ScanOptions,
    ScanResult,
    SourceType,
    Usage,
)
from quantumtrace.scanners import base


class FakeScanner:
    source_type = SourceType.CODE

    def __init__(self, name="fixture", suffix=".raw", fail=False):
        self.name, self.suffix, self.fail = name, suffix, fail
        self.calls = []

    def can_handle(self, path):
        return path.suffix == self.suffix

    def scan(self, path, root):
        self.calls.append((path, root))
        yield Finding(
            id=path.relative_to(root).as_posix(),
            raw_name="RSA",
            kind_hint=KindHint.ALGORITHM,
            usage=Usage.SIGNATURE,
            key_size=2048,
            detector=self.name,
            location=Location(source_type=SourceType.CODE, file=path.relative_to(root).as_posix()),
            extra={"arbitrary": {"preserved": True}},
        )
        if self.fail:
            yield ScanError(detector=self.name, path=path.name, message="partial")
            raise RuntimeError("after usable evidence")


@pytest.fixture
def fake(monkeypatch):
    scanner = FakeScanner()
    monkeypatch.setattr(base, "REGISTRY", [scanner])
    monkeypatch.setattr(pipeline, "_load_adapters", lambda: [])
    return scanner


def test_overlapping_paths_order_roots_and_stable_ids(fake, tmp_path):
    folder = tmp_path / "nested"
    folder.mkdir()
    one = folder / "a.raw"
    one.write_text("fixture")
    two = tmp_path / "b.raw"
    two.write_text("fixture")
    result = pipeline.run([one, tmp_path, folder, two, tmp_path])
    assert [item.location.file for item in result.findings] == ["b.raw", "nested/a.raw"]
    assert len(fake.calls) == 2
    assert all(root == tmp_path for _, root in fake.calls)
    repeat = pipeline.run([tmp_path, two, folder, one])
    assert repeat.scan_id == result.scan_id
    assert repeat.findings == result.findings and repeat.assets == result.assets
    assert repeat.summary == result.summary
    assert ScanResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings[0].extra == {"arbitrary": {"preserved": True}}


def test_direct_file_uses_parent_root(fake, tmp_path):
    folder = tmp_path / "nested"
    folder.mkdir()
    path = folder / "a.raw"
    path.write_text("fixture")
    assert pipeline.run([path]).findings[0].location.file == "a.raw"
    assert pipeline.run([tmp_path]).findings[0].location.file == "nested/a.raw"


def test_exclusions_and_symlink_cycle(fake, tmp_path):
    (tmp_path / "a.raw").write_text("fixture")
    ignored = tmp_path / "agents"
    ignored.mkdir()
    (ignored / "b.raw").write_text("fixture")
    (tmp_path / "cycle").symlink_to(tmp_path, target_is_directory=True)
    (tmp_path / "same.raw").symlink_to(tmp_path / "a.raw")
    assert len(pipeline.run([tmp_path]).findings) == 1
    assert len(fake.calls) == 1
    assert len(pipeline.run([tmp_path], options=ScanOptions(exclude_dirs=[])).findings) == 2


def test_selection_generic_last_and_first_specific_wins(fake, monkeypatch, tmp_path):
    path = tmp_path / "a.raw"
    path.write_text("fixture")
    specific = FakeScanner("specific")
    generic = FakeScanner("a.generic_json")
    monkeypatch.setattr(base, "REGISTRY", [generic, specific, fake])
    result = pipeline.run([path])
    assert result.findings[0].detector == "fixture"
    selected = pipeline.run([path], options=ScanOptions(scanner_names=["a.generic_json"]))
    assert selected.findings[0].detector == generic.name
    empty = pipeline.run([path], options=ScanOptions(scanner_names=[]))
    assert not empty.findings and "no selected scanner" in empty.errors[0].message
    unknown = pipeline.run([path], options=ScanOptions(scanner_names=["missing"]))
    assert any("unknown scanner names: missing" in error.message for error in unknown.errors)
    assert not unknown.findings


def test_errors_after_yield_do_not_lose_findings(fake, tmp_path):
    fake.fail = True
    path = tmp_path / "a.raw"
    path.write_text("fixture")
    result = pipeline.run([path, tmp_path / "missing"])
    assert len(result.findings) == len(result.assets) == 1
    assert any(error.message == "partial" for error in result.errors)
    assert any("RuntimeError: after usable evidence" in error.message for error in result.errors)
    assert any("missing or unsupported" in error.message for error in result.errors)


def test_can_handle_failure_allows_other_handler(fake, monkeypatch, tmp_path):
    class Broken(FakeScanner):
        def can_handle(self, path):
            raise RuntimeError("bad sniffer")

    monkeypatch.setattr(base, "REGISTRY", [Broken("a"), fake])
    path = tmp_path / "a.raw"
    path.write_text("fixture")
    result = pipeline.run([path])
    assert len(result.findings) == 1
    assert any("can_handle" in error.message for error in result.errors)


def test_invalid_emissions_and_no_implicit_probe(fake, monkeypatch, tmp_path):
    class Invalid(FakeScanner):
        def scan(self, path, root):
            yield "invalid"

    monkeypatch.setattr(base, "REGISTRY", [Invalid()])
    path = tmp_path / "a.raw"
    path.write_text("fixture")
    result = pipeline.run([path], probes=["example.invalid:443"])
    assert len(result.errors) == 2
    assert any("probe adapter is unavailable" in error.message for error in result.errors)
    assert any("invalid scanner result" in error.message for error in result.errors)
    assert pipeline.run([]).errors == []


def test_identical_findings_dedupe_but_changed_metadata_survives(fake, monkeypatch, tmp_path):
    class Multiple(FakeScanner):
        def scan(self, path, root):
            raw = next(super().scan(path, root))
            yield raw
            yield raw
            yield raw.model_copy(update={"confidence": 0.3, "negotiated": True})

    monkeypatch.setattr(base, "REGISTRY", [Multiple()])
    path = tmp_path / "a.raw"
    path.write_text("fixture")
    result = pipeline.run([path])
    assert len(result.findings) == 2 and len(result.assets) == 1
    assert len(result.assets[0].occurrences) == 1


def test_scan_reference_timestamp_and_identity(fake, monkeypatch, tmp_path):
    from datetime import UTC, datetime

    starts = []
    original = pipeline.classify_findings

    def classify(findings, kb, started):
        starts.append(started)
        return original(findings, kb, started)

    monkeypatch.setattr(pipeline, "classify_findings", classify)
    path = tmp_path / "a.raw"
    path.write_text("fixture")
    first = pipeline.run([path])
    second = pipeline.run([path])
    assert starts == [datetime.fromisoformat(first.started_at), datetime.fromisoformat(second.started_at)]
    assert starts[0].tzinfo == UTC
    assert first.scan_id == second.scan_id


def test_published_adapters_and_incomplete_starter_coverage():
    root = Path(__file__).resolve().parents[1]
    result = pipeline.run([root / "sample-repos", root / "cloud-posture", root / "network-capture"])
    assert sum(raw.location.source_type == SourceType.KMS for raw in result.findings) == 10
    assert any(raw.location.source_type == SourceType.CODE for raw in result.findings)
    assert any(raw.location.source_type == SourceType.LOADBALANCER for raw in result.findings)
    assert not result.sessions  # M2 has not yet supplied a registered capture adapter.
    assert any(error.path.endswith(".pcap") for error in result.errors)
    assert any("acm" in (error.path or "") for error in result.errors)
    assert result.summary.counts_by_source["kms"]["CRITICAL"] > 0


def test_source_timestamp_does_not_enter_scan_identity(fake, monkeypatch, tmp_path):
    class Timestamped(FakeScanner):
        stamp = "2026-10-10T00:00:00Z"

        def scan(self, path, root):
            raw = next(super().scan(path, root))
            raw.extra["source_timestamp"] = self.stamp
            yield raw

    scanner = Timestamped()
    monkeypatch.setattr(base, "REGISTRY", [scanner])
    path = tmp_path / "a.raw"
    path.write_text("fixture")
    first = pipeline.run([path])
    scanner.stamp = "2026-10-11T00:00:00Z"
    second = pipeline.run([path])
    assert first.scan_id == second.scan_id
    assert first.findings[0].extra["source_timestamp"] != second.findings[0].extra["source_timestamp"]


def test_adapter_import_failure_is_visible(monkeypatch):
    def fail(name):
        raise ImportError("adapter dependency absent")

    monkeypatch.setattr(pipeline.importlib, "import_module", fail)
    errors = pipeline._load_adapters()
    assert len(errors) == 3
    assert all("ImportError: adapter dependency absent" in error.message for error in errors)


def test_pipeline_consumes_session_findings_and_partial_errors(fake, monkeypatch, tmp_path):
    import json

    fixture = Path(__file__).parent / "fixtures" / "pcap" / "samples" / "hybrid_vault.json"
    raws = [Finding.model_validate(item) for item in json.loads(fixture.read_text())]

    class NetworkFixture(FakeScanner):
        def scan(self, path, root):
            yield from raws
            yield ScanError(detector="pcap", path="network.pcap", message="fixture partial coverage")

    monkeypatch.setattr(base, "REGISTRY", [NetworkFixture()])
    path = tmp_path / "network.raw"
    path.write_text("fixture")
    result = pipeline.run([path])
    assert len(result.sessions) == 1 and result.sessions[0].pq_status == "pq_hybrid"
    assert any(error.message == "fixture partial coverage" for error in result.errors)
    assert ScanResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings == sorted(
        raws, key=lambda raw: (raw.id, pipeline._dump(raw.model_dump(mode="json")))
    )
