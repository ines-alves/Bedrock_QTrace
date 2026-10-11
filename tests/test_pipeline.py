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
    assert sum(session.transport == "tls" for session in result.sessions) == 97
    assert sum(session.transport == "ssh" for session in result.sessions) == 24
    assert (
        sum(
            raw.kind_hint == KindHint.PLAINTEXT and raw.location.source_type == SourceType.PCAP
            for raw in result.findings
        )
        == 14
    )
    assert not any(Path(error.path or "").suffix == ".pcap" for error in result.errors)
    assert sum(raw.location.source_type == SourceType.ACM for raw in result.findings) == 5
    assert not any("acm" in (error.path or "") for error in result.errors)
    assert result.summary.counts_by_source["kms"]["CRITICAL"] > 0
    assert any(raw.kind_hint == KindHint.LIBRARY for raw in result.findings)
    assert not any(Path(error.path or "").name in {"requirements.txt", "go.mod"} for error in result.errors)


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
    assert len(errors) == len(pipeline._ADAPTER_MODULES)
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


def test_acm_routing_certificate_joins_and_source_timestamp_hygiene():
    from datetime import UTC, datetime

    from quantumtrace.engine import classify_findings
    from quantumtrace.kb.loader import load_kb
    from quantumtrace.models import Tier

    root = Path(__file__).resolve().parents[1]
    result = pipeline.run([root / "cloud-posture"])
    certs = [raw for raw in result.findings if raw.location.source_type == SourceType.ACM]
    assert len(certs) == 5 and len({raw.location.resource_id for raw in certs}) == 5
    assert all(raw.kind_hint == KindHint.CERTIFICATE and raw.usage == Usage.AUTHENTICATION for raw in certs)
    assert not any("acm_certificates.json" in (error.path or "") for error in result.errors)
    spellings = {raw.raw_name for raw in certs} | {raw.extra["signature_algorithm"] for raw in certs}
    assert len(spellings) == 7
    classified = classify_findings(certs, load_kb(), datetime(2030, 1, 1, tzinfo=UTC))
    assert all(not row.node.normalized.unknown_reasons for tree in classified for row in tree.children)
    certificates = [
        asset
        for asset in result.assets
        if asset.components and any(site.source_type == SourceType.ACM for site in asset.occurrences)
    ]
    assert len(certificates) == 5
    assert all(asset.asset_type == "certificate" for asset in certificates)
    assert all(asset.max_points == 0 and asset.tier == Tier.CRITICAL for asset in certificates)
    by_id = {asset.asset_id: asset for asset in result.assets}
    for cert in certificates:
        assert len(cert.component_of) == 1
        listener = by_id[cert.component_of[0]]
        assert listener.tier == Tier.CRITICAL and cert.asset_id in listener.components
        assert cert.max_points == listener.max_points == 0
    actions = {advice.action for tree in classified for advice in tree.recommendations}
    assert "Review imported certificate renewal ownership." in actions
    assert "Renew the expired in-use certificate." in actions
    # Even the 2030 scan fallback uses the actual 2026 dump date when supplied.
    assert "Plan certificate renewal within 90 days." in actions
    assert all(raw.extra["source_timestamp"] == "2026-09-14T09:38:19Z" for raw in certs)
    assert ScanResult.model_validate_json(result.model_dump_json()) == result


def test_manifest_loader_inventory_exclusion_and_markdown_integration(tmp_path):
    from quantumtrace.output.markdown import render_markdown_summary

    assert "quantumtrace.scanners.code.manifests" in pipeline._ADAPTER_MODULES
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("cryptography==46.0.5\nPyJWT>=2.8\n")
    code = tmp_path / "crypto.py"
    code.write_text('import hashlib\nhashlib.sha256(b"message")\n')
    baseline = pipeline.run([code], options=ScanOptions(scanner_names=["code.regex"]))
    result = pipeline.run([code, manifest])
    libraries = [raw for raw in result.findings if raw.kind_hint == KindHint.LIBRARY]
    assert {raw.raw_name for raw in libraries} == {"cryptography==46.0.5", "PyJWT"}
    assert not result.errors
    assert result.summary == baseline.summary
    library_ids = {raw.id for raw in libraries}
    inventory = [asset for asset in result.assets if library_ids.intersection(asset.finding_ids)]
    assert len(inventory) == 2
    assert all(asset.risk_points == asset.max_points == 0 for asset in inventory)
    assert not {asset.asset_id for asset in inventory}.intersection(result.summary.top_risks)
    assert ScanResult.model_validate_json(result.model_dump_json()) == result
    markdown = render_markdown_summary(result)
    assert "cryptography" in markdown and "PyJWT" in markdown

    broken = tmp_path / "pom.xml"
    broken.write_text("<project><dependencies>")
    partial = pipeline.run([manifest, broken], options=ScanOptions(scanner_names=["code.manifest"]))
    assert partial.findings == libraries
    assert len(partial.errors) == 1 and partial.errors[0].detector == "code.java.manifest"
    assert "not well-formed XML" in partial.errors[0].message
    assert "not well-formed XML" in render_markdown_summary(partial)


def test_real_pcap_selection_stability_and_unobservable_authentication():
    from quantumtrace.models import Tier

    root = Path(__file__).resolve().parents[1]
    capture = root / "network-capture" / "network.pcap"
    options = ScanOptions(scanner_names=["pcap"])
    first = pipeline.run([capture], options=options)
    second = pipeline.run([capture], options=options)
    assert not first.errors and not second.errors
    assert first.scan_id == second.scan_id
    assert first.findings == second.findings and first.assets == second.assets
    assert first.sessions == second.sessions and first.summary == second.summary
    assert len(first.sessions) == 121
    assert all(raw.location.file == "network.pcap" for raw in first.findings)
    assert not any(raw.kind_hint == KindHint.CERTIFICATE for raw in first.findings)
    tls_ids = {session.session_id for session in first.sessions if session.transport == "tls"}
    observed_auth = [
        raw.extra["authentication_observable"]
        for raw in first.findings
        if "authentication_observable" in raw.extra and raw.session_id in tls_ids
    ]
    assert observed_auth and not any(observed_auth)
    tls = [session for session in first.sessions if session.transport == "tls"]
    assert all(session.cert_key is None and session.cert_sig_alg is None for session in tls)
    hybrids = [session for session in tls if session.pq_status == "pq_hybrid"]
    assert hybrids and all(session.verdict_tier == Tier.UNKNOWN for session in hybrids)
    assert ScanResult.model_validate_json(first.model_dump_json()) == first


def test_registered_pcap_empty_capture_error(tmp_path):
    path = tmp_path / "empty.PCAP"
    path.touch()
    result = pipeline.run([path], options=ScanOptions(scanner_names=["pcap"]))
    assert not result.findings and not result.sessions
    assert len(result.errors) == 1
    assert result.errors[0].detector == "pcap" and result.errors[0].path == "empty.PCAP"
    assert result.errors[0].message == "capture is empty"


def test_real_cbom_certificate_validity_and_policy_dependencies():
    from quantumtrace.output.cyclonedx import build_cbom, validate_cbom

    root = Path(__file__).resolve().parents[1]
    result = pipeline.run([root / "cloud-posture", root / "sample-repos", root / "network-capture"])
    cbom = build_cbom(result)
    assert validate_cbom(cbom) == []
    components = {component["bom-ref"]: component for component in cbom["components"]}
    findings = {raw.id: raw for raw in result.findings}
    certificates = [asset for asset in result.assets if asset.asset_type == "certificate"]
    assert len(certificates) == 5
    for asset in certificates:
        assert asset.risk_points == asset.max_points == 0 and asset.components
        raw = findings[asset.finding_ids[0]]
        props = components[asset.asset_id]["cryptoProperties"]["certificateProperties"]
        assert props["notValidBefore"] == raw.extra["not_before"]
        assert props["notValidAfter"] == raw.extra["not_after"]
        assert props["subjectName"] == raw.extra["domain"]
    dependencies = {row["ref"]: row["dependsOn"] for row in cbom["dependencies"]}
    policies = [
        asset
        for asset in result.assets
        if asset.components
        and not asset.component_of
        and any(findings[fid].kind_hint == KindHint.POLICY for fid in asset.finding_ids)
    ]
    assert policies
    for asset in policies:
        assert dependencies[asset.asset_id] == asset.components
        assert "cipherSuites" not in components[asset.asset_id]["cryptoProperties"]["protocolProperties"]
    assert ScanResult.model_validate_json(result.model_dump_json()) == result


def test_reports_keep_inputs_as_given_and_no_local_path_prefix(tmp_path, monkeypatch):
    (tmp_path / "kit").mkdir()
    (tmp_path / "kit" / "server.key").write_text("not scanned yet\n")
    monkeypatch.chdir(tmp_path)
    result = pipeline.run(["kit", "./kit/"])
    assert result.inputs == ["kit"]
    # The key-file scanner owns .key files; its error path follows the same cwd-relative convention.
    assert [error.path for error in result.errors] == ["kit/server.key"]
    assert str(tmp_path) not in result.model_dump_json()
    assert pipeline.run(["kit"]).scan_id == result.scan_id


def test_inputs_outside_working_directory_stay_absolute(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "server.key").write_text("not scanned yet\n")
    (tmp_path / "work").mkdir()
    monkeypatch.chdir(tmp_path / "work")
    result = pipeline.run([outside])
    assert result.inputs == [outside.as_posix()]
    assert [error.path for error in result.errors] == [(outside / "server.key").as_posix()]


def test_walked_files_are_reported_only_when_they_may_hold_key_material_or_tls_config(tmp_path, monkeypatch):
    # Key and certificate files now have a scanner: unreadable ones are its coverage errors. A server
    # config without TLS settings (nginx.conf here) is covered and silent.
    kit = tmp_path / "kit"
    (kit / "static").mkdir(parents=True)
    skipped = ("README.md", "LICENSE", "notes.txt", "static/app.js", "setup.cfg", "data.json", "Makefile")
    reported = ("server.key", "certs.pem", "id_rsa", "id_ed25519.pub", "keystore.p12")
    for name in (*skipped, *reported, "nginx.conf"):
        (kit / name).write_text("unsupported\n")
    monkeypatch.chdir(tmp_path)
    walked = pipeline.run(["kit"])
    assert sorted(error.path for error in walked.errors) == sorted(f"kit/{name}" for name in reported)
    assert {error.message for error in walked.errors} == {"no key, certificate or keystore recognized"}
    assert pipeline.skipped_files(["kit"]) == sorted(f"kit/{name}" for name in skipped)
    named = pipeline.run(["kit/README.md", "kit/static/app.js"])
    assert [error.path for error in named.errors] == ["kit/README.md", "kit/static/app.js"]
    assert pipeline.skipped_files(["kit/README.md"]) == []
