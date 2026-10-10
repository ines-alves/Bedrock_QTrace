"""Hand-counted phase priority over retained physical evidence."""

import random
from pathlib import Path

from quantumtrace.engine import classify_findings
from quantumtrace.engine.aggregate import aggregate
from quantumtrace.engine.roadmap import build_roadmap
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import Finding, KindHint, Location, SourceType, Usage
from quantumtrace.pipeline import run


def raw(name, line, **updates):
    values = dict(
        id=str(line),
        raw_name=name,
        detector="fixture",
        kind_hint=KindHint.ALGORITHM,
        usage=Usage.UNKNOWN,
        location=Location(source_type=SourceType.CODE, file="code.py", line=line),
    )
    values.update(updates)
    return Finding(**values)


def evidence(findings):
    return aggregate(classify_findings(findings, load_kb()))


def phases(items, asset):
    return {item.phase for item in items if asset.asset_id in item.asset_ids}


def test_priority_safe_maintenance_trace_exclusions_and_unique_counts():
    findings = [
        raw("RSA", 1, usage=Usage.SIGNATURE, key_size=1024),
        raw("RSA", 2, usage=Usage.SIGNATURE, key_size=2048),
        raw("RSA", 3, usage=Usage.KEY_EXCHANGE, key_size=2048),
        raw("AES", 4, usage=Usage.ENCRYPTION, key_size=128),
        raw("AES", 5, usage=Usage.ENCRYPTION, key_size=256, mode="ecb"),
        raw("plaintext", 6, kind_hint=KindHint.PLAINTEXT),
        raw("unknown-mechanism", 7),
        raw("AES", 8, usage=Usage.ENCRYPTION, key_size=128),
        raw("X25519MLKEM768", 9, kind_hint=KindHint.GROUP, usage=Usage.KEY_EXCHANGE),
        raw("cryptography", 10, kind_hint=KindHint.LIBRARY),
    ]
    findings += [findings[3], findings[3].model_copy(update={"detector": "second"})]
    result = evidence(findings)
    items = build_roadmap(result)
    assert items == sorted(items, key=lambda item: (item.phase, item.action))
    for asset in result.assets:
        if asset.canonical_name == "RSA" and not asset.component_of:
            assert phases(items, asset) == (
                {0} if asset.key_size == 1024 else {1} if asset.usage == Usage.KEY_EXCHANGE else {2}
            )
        if asset.canonical_name == "AES" and asset.key_size == 128:
            actions = [item for item in items if asset.asset_id in item.asset_ids]
            assert phases(items, asset) == {3} and all(item.occurrence_count == 2 for item in actions)
        if asset.canonical_name == "AES" and asset.mode == "ecb":
            assert phases(items, asset) == {0}
        if asset.component_of or asset.canonical_name in {"X25519MLKEM768", "cryptography"}:
            assert not phases(items, asset)
    assert any("uncertain" in item.action for item in items)
    assert any("encrypted transport" in item.action and item.phase == 0 for item in items)
    random.Random(123).shuffle(findings)
    assert build_roadmap(evidence(findings)) == items


def test_offered_only_is_not_merged_with_negotiated_action_state():
    base = raw("RSA", 1, usage=Usage.KEY_EXCHANGE, key_size=2048)
    offered = base.model_copy(
        update={
            "negotiated": False,
            "location": Location(source_type=SourceType.PCAP, file="capture", flow="offered"),
        }
    )
    code = base.model_copy(update={"id": "code", "negotiated": True})
    items = build_roadmap(evidence([offered, code]))
    assert any(item.action.startswith("Review offered-only") for item in items)
    assert any(not item.action.startswith("Review offered-only") and item.phase == 1 for item in items)
    assert all(item.occurrence_count == 1 for item in items)


def test_real_pipeline_roadmap_preserves_hygiene_and_valid_asset_links():
    root = Path(__file__).resolve().parents[1]
    result = run([root / "cloud-posture", root / "sample-repos"])
    assert result.roadmap and {item.phase for item in result.roadmap} == {0, 1, 2, 3}
    asset_ids = {asset.asset_id for asset in result.assets}
    assert all(set(item.asset_ids) <= asset_ids and item.occurrence_count > 0 for item in result.roadmap)
    assert any(item.phase == 0 and "hard-coded" in item.action for item in result.roadmap)
    assert any(item.phase == 0 and "expired in-use" in item.action for item in result.roadmap)
