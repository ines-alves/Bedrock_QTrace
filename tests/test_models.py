"""Behavioral checks for the frozen shared serialization contracts."""

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from quantumtrace.models import (
    CryptoAsset,
    Finding,
    KindHint,
    Location,
    Recommendation,
    RiskSummary,
    RoadmapItem,
    ScanError,
    ScanOptions,
    ScanResult,
    SourceType,
    Threat,
    Tier,
    TLSSession,
    Usage,
)


def make_finding(**changes: Any) -> Finding:
    """Create raw evidence without assigning a classification."""
    values = {
        "id": "finding-1",
        "raw_name": "x25519",
        "kind_hint": KindHint.GROUP,
        "detector": "network.fixture",
        "location": Location(source_type=SourceType.PCAP, file="fixture.pcap", frame=1),
    }
    return Finding.model_validate(values | changes)


def make_asset(**changes: Any) -> CryptoAsset:
    """Create an engine output for contract tests without running an engine."""
    values = {
        "asset_id": "crypto/fixture",
        "canonical_name": "X25519",
        "family": "ECDH",
        "asset_type": "algorithm",
        "primitive": "key-agree",
        "usage": Usage.KEY_EXCHANGE,
        "tier": Tier.CRITICAL,
        "threat": Threat.SHOR,
        "rationale": "Fixture classification supplied by the caller.",
    }
    return CryptoAsset.model_validate(values | changes)


def make_session(**changes: Any) -> TLSSession:
    """Build a session with explicitly unobservable certificate evidence."""
    values = {
        "session_id": "session-1",
        "flow": "client:12345 -> server:443",
        "sni": None,
        "version": "TLS 1.3",
        "pq_status": "pq_hybrid",
        "verdict_tier": Tier.UNKNOWN,
        "source": "fixture.pcap",
    }
    return TLSSession.model_validate(values | changes)


def make_result(**changes: Any) -> ScanResult:
    """Build a mixed-source integration payload with every verdict tier."""
    summary = RiskSummary(
        score=50,
        grade="D",
        readiness_pct=25,
        counts_by_tier={tier.value: 1 for tier in Tier},
        counts_by_source={"pcap": {"UNKNOWN": 1}, "kms": {"CRITICAL": 1}},
        score_by_source={"pcap": 50, "kms": 100},
        hndl_exposed_count=1,
        top_risks=["crypto/CRITICAL"],
    )
    findings = [
        make_finding(
            negotiated=True,
            extra={"authentication_observable": False, "source_timestamp": "2026-09-14T00:00:00Z"},
        ),
        make_finding(
            id="finding-2",
            raw_name="RSA_2048",
            kind_hint=KindHint.KEY,
            location=Location(source_type=SourceType.KMS, resource_id="fixture-key"),
            extra={"origin": "EXTERNAL", "state": "Enabled", "public_exposure": False},
        ),
        make_finding(
            id="finding-3",
            raw_name="HTTP",
            kind_hint=KindHint.PLAINTEXT,
            location=Location(source_type=SourceType.LOADBALANCER, resource_id="fixture-listener"),
            extra={"hygiene_only": True, "owner_extension": {"data": [1, 2]}},
        ),
        make_finding(id="finding-4", negotiated=False, confidence=0.4),
        make_finding(
            id="finding-5",
            kind_hint=KindHint.CERTIFICATE,
            location=Location(source_type=SourceType.ACM, resource_id="fixture-certificate"),
        ),
    ]
    values = {
        "tool_version": "0.1.0",
        "scan_id": "fixture-scan",
        "started_at": "2026-09-14T00:00:00Z",
        "finished_at": "2026-09-14T00:00:01Z",
        "inputs": ["fixture.pcap", "fixture.json"],
        "findings": findings,
        "assets": [make_asset(asset_id=f"crypto/{tier.value}", tier=tier) for tier in Tier],
        "sessions": [make_session(), make_session(session_id="ssh-1", transport="ssh", service="ssh")],
        "summary": summary,
        "errors": [ScanError(detector="fixture", path="unreadable", message="fixture failure")],
    }
    return ScanResult.model_validate(values | changes)


def test_scan_result_round_trip_preserves_metadata_and_unknown_evidence() -> None:
    result = make_result()
    payload = json.loads(result.model_dump_json())
    assert ScanResult.model_validate_json(result.model_dump_json()) == result
    assert payload["sessions"][0]["cert_key"] is None
    assert payload["sessions"][0]["sni"] is None
    assert payload["sessions"][0]["verdict_tier"] == "UNKNOWN"
    assert payload["sessions"][1]["transport"] == "ssh"
    assert payload["findings"][2]["extra"]["owner_extension"] == {"data": [1, 2]}
    assert payload["findings"][0]["negotiated"] is True
    assert payload["findings"][3]["negotiated"] is False
    assert payload["findings"][3]["confidence"] == 0.4
    assert payload["findings"][4]["location"]["source_type"] == "acm"
    assert {asset["tier"] for asset in payload["assets"]} == {"CRITICAL", "MEDIUM", "SAFE", "UNKNOWN"}
    assert "roadmap" not in payload


@pytest.mark.parametrize("confidence", [-0.01, 1.01, float("nan"), float("inf"), -float("inf")])
def test_confidence_rejects_values_outside_unit_interval(confidence: float) -> None:
    with pytest.raises(ValidationError, match="confidence"):
        make_finding(confidence=confidence)


@pytest.mark.parametrize("confidence", [0, 0.75, 1])
def test_confidence_accepts_boundaries(confidence: float) -> None:
    assert make_finding(confidence=confidence).confidence == confidence


def test_nullable_fields_keep_required_semantics() -> None:
    recommendation = Recommendation(action="fixture", target_algorithm=None, standard=None, priority=1)
    assert recommendation.target_algorithm is None
    with pytest.raises(ValidationError, match="target_algorithm"):
        Recommendation.model_validate({"action": "fixture", "standard": None, "priority": 1})
    session = make_session().model_dump()
    del session["sni"]
    with pytest.raises(ValidationError, match="sni"):
        TLSSession.model_validate(session)


def mutable_defaults(model: BaseModel) -> Iterator[tuple[str, list[Any] | dict[str, Any]]]:
    """Enumerate mutable default fields without hard-coding their names."""
    for name, field in type(model).model_fields.items():
        value = getattr(model, name)
        if field.default_factory is not None and isinstance(value, (list, dict)):
            yield name, value


def test_all_collection_defaults_are_isolated() -> None:
    older_payload = make_result().model_dump()
    del older_payload["sessions"]
    del older_payload["errors"]
    pairs = [
        (make_finding(), make_finding()),
        (make_asset(), make_asset()),
        (make_session(), make_session()),
        (ScanResult.model_validate(older_payload), ScanResult.model_validate(older_payload)),
        (ScanOptions(), ScanOptions()),
        (
            RoadmapItem(phase=0, action="fixture", occurrence_count=0),
            RoadmapItem(phase=0, action="fixture", occurrence_count=0),
        ),
    ]
    for first, second in pairs:
        for name, value in mutable_defaults(first):
            original = getattr(second, name).copy()
            assert value is not getattr(second, name), name
            if isinstance(value, list):
                value.append("mutation")
            else:
                value["mutation"] = True
            assert getattr(second, name) == original, name


@pytest.mark.parametrize(
    "roadmap", [None, [], [RoadmapItem(phase=3, action="migrate", asset_ids=["a"], occurrence_count=2)]]
)
def test_roadmap_absence_empty_and_populated_round_trip(roadmap: list[RoadmapItem] | None) -> None:
    result = make_result(roadmap=roadmap)
    payload = result.model_dump(mode="json")
    assert ("roadmap" in payload) is (roadmap is not None)
    assert ScanResult.model_validate_json(result.model_dump_json()).roadmap == roadmap
    assert ScanResult.model_validate(payload).roadmap == roadmap


def test_older_payload_without_optional_collections_is_accepted() -> None:
    payload = make_result().model_dump(mode="json")
    del payload["sessions"]
    del payload["errors"]
    result = ScanResult.model_validate(payload)
    assert result.sessions == []
    assert result.errors == []
    assert result.roadmap is None


@pytest.mark.parametrize("changes", [{"phase": -1}, {"phase": 4}, {"occurrence_count": -1}])
def test_invalid_roadmap_bounds(changes: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        RoadmapItem.model_validate({"phase": 0, "action": "fixture", "occurrence_count": 0} | changes)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_json_schema_remains_typed_and_validates_results(mode: Any) -> None:
    schema = ScanResult.model_json_schema(mode=mode)
    assert "RoadmapItem" in schema["$defs"]
    assert "roadmap" not in schema["required"]
    validator = Draft202012Validator(schema)
    validator.validate(make_result().model_dump(mode="json"))
    validator.validate(make_result(roadmap=[]).model_dump(mode="json"))
    validator.validate(
        make_result(roadmap=[RoadmapItem(phase=0, action="fixture", occurrence_count=1)]).model_dump(
            mode="json"
        )
    )
    payload = make_result().model_dump(mode="json")
    payload["roadmap"] = [{"phase": 4, "action": "fixture", "asset_ids": [], "occurrence_count": 0}]
    assert list(validator.iter_errors(payload))


def test_fastapi_openapi_uses_typed_shared_result_schema() -> None:
    app = FastAPI()

    @app.get("/fixture", response_model=ScanResult)
    def fixture_result() -> ScanResult:
        return make_result()

    schemas = app.openapi()["components"]["schemas"]
    assert "roadmap" in schemas["ScanResult"]["properties"]
    assert "roadmap" not in schemas["ScanResult"]["required"]
    assert schemas["RoadmapItem"]["properties"]["phase"]["enum"] == [0, 1, 2, 3]


def test_scan_options_defaults_and_explicit_empty_selection() -> None:
    options = ScanOptions()
    assert options.exclude_dirs == [".git", "node_modules", "venv", ".venv", "vendor", "out", "agents"]
    assert options.scanner_names is None
    assert ScanOptions(exclude_dirs=[], scanner_names=[]).model_dump() == {
        "exclude_dirs": [],
        "scanner_names": [],
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"scanner_names": [""]},
        {"scanner_names": [" "]},
        {"scanner_names": "code.python"},
        {"exclude_dirs": [""]},
        {"exclude_dirs": ["a/b"]},
        {"exclude_dirs": ["a\\b"]},
        {"exclude_dirs": [".."]},
        {"exclude_dirs": [" "]},
        {"unknown_option": True},
    ],
)
def test_invalid_scan_options_are_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ScanOptions.model_validate(payload)
