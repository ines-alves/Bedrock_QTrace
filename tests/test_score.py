"""Hand-calculated risk policy and preserved-evidence regression tests."""

from dataclasses import replace
from itertools import permutations
from math import log2

import pytest

from quantumtrace.engine import analyze
from quantumtrace.engine.aggregate import aggregate
from quantumtrace.engine.classify import classify
from quantumtrace.engine.decompose import decompose
from quantumtrace.engine.score import _score, score
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import Finding, KindHint, Location, SourceType, Tier, Usage


@pytest.fixture(scope="module")
def kb():
    return load_kb()


def finding(name="RSA", **updates):
    data = dict(
        id="one",
        raw_name=name,
        kind_hint=KindHint.ALGORITHM,
        usage=Usage.SIGNATURE,
        key_size=2048,
        detector="fixture",
        location=Location(source_type=SourceType.CODE, file="a.py", line=10),
    )
    data.update(updates)
    return Finding(**data)


def run(kb, findings):
    roots = [classify(decompose(item, kb).root, kb) for item in findings]
    return score(aggregate(roots), kb.scoring)


@pytest.mark.parametrize(
    "source,negotiated,usage,extra,test,weight",
    [
        (SourceType.CODE, None, Usage.SIGNATURE, {}, False, 1),
        (SourceType.CODE, None, Usage.SIGNATURE, {}, True, 0.3),
        (SourceType.CONFIG, None, Usage.SIGNATURE, {}, True, 0.3),
        (SourceType.KEYFILE, None, Usage.SIGNATURE, {}, True, 0.3),
        (SourceType.KEYFILE, None, Usage.SIGNATURE, {}, False, 1),
        (SourceType.KMS, None, Usage.SIGNATURE, {}, True, 1),
        (SourceType.PCAP, True, Usage.KEY_EXCHANGE, {}, False, 1.5),
        (SourceType.LIVE, True, Usage.SIGNATURE, {}, False, 1.2),
        (SourceType.SSH, False, Usage.KEY_EXCHANGE, {}, False, 0.4),
        (SourceType.PCAP, None, Usage.KEY_EXCHANGE, {}, False, 1),
        (SourceType.KMS, None, Usage.SIGNATURE, {"state": "Enabled"}, False, 1.2),
        (SourceType.KMS, None, Usage.SIGNATURE, {"state": "Disabled"}, False, 0.3),
        (SourceType.KMS, None, Usage.SIGNATURE, {"state": "PendingDeletion"}, False, 0.3),
        (SourceType.KMS, None, Usage.SIGNATURE, {}, False, 1),
        (SourceType.LOADBALANCER, False, Usage.KEY_EXCHANGE, {"public_exposure": True}, False, 1.5),
        (SourceType.LOADBALANCER, False, Usage.KEY_EXCHANGE, {}, False, 1),
    ],
)
def test_exposure_hand_arithmetic(kb, source, negotiated, usage, extra, test, weight):
    raw = finding(
        location=Location(source_type=source, file="a"),
        negotiated=negotiated,
        usage=usage,
        extra=extra,
        in_test_code=test,
        confidence=0.8,
    )
    assets, summary = run(kb, [raw])
    assert assets[0].risk_points == pytest.approx(10 * weight * 1.2 * 0.8)
    assert assets[0].max_points == pytest.approx(15 * weight * 1.2 * 0.8)
    assert summary.score == 67
    assert summary.readiness_pct == 0


@pytest.mark.parametrize("count", [1, 2, 31, 40])
def test_occurrence_cap_and_duplicate_detectors(kb, count):
    raws = [
        finding(id=str(i), location=Location(source_type=SourceType.CODE, file="a", line=i + 1))
        for i in range(count)
    ]
    assets, _ = run(kb, [*raws, *raws, raws[0].model_copy(update={"detector": "other"})])
    assert len(assets) == 1
    assert assets[0].risk_points == pytest.approx(10 * (1 + log2(1 + min(count, 31)) / 5))


@pytest.mark.parametrize(
    "name,size,usage,weight,broken",
    [
        ("RSA", 1024, Usage.SIGNATURE, 10, 1.5),
        ("AES", 128, Usage.ENCRYPTION, 4, 1),
        ("unrecognized", None, Usage.UNKNOWN, 2, 1),
        ("AES", 256, Usage.ENCRYPTION, 0, 1),
    ],
)
def test_tier_weights_and_broken_multiplier(kb, name, size, usage, weight, broken):
    assets, summary = run(kb, [finding(name, key_size=size, usage=usage)])
    assert assets[0].risk_points == pytest.approx(weight * broken * 1.2)
    assert assets[0].max_points == pytest.approx(18)
    assert summary.score == round(100 * weight * broken / 15)


def test_effective_confidence(kb):
    raw = finding("AES", key_size=None, usage=Usage.ENCRYPTION)
    assets, _ = run(kb, [raw])
    assert assets[0].risk_points == pytest.approx(4 * 1.2 * 0.5)
    assert raw.confidence == 1


def test_max_confidence_and_exposure_are_independent(kb):
    one = finding(confidence=0.9, in_test_code=True)
    two = finding(id="two", confidence=0.2, location=one.location.model_copy(update={"line": 20}))
    assets, _ = run(kb, [one, two])
    assert assets[0].risk_points == pytest.approx(10 * 1 * (1 + log2(3) / 5) * 0.9)


def test_source_filtering_and_same_record_floor(kb):
    code = finding(usage=Usage.KEY_EXCHANGE, negotiated=True)
    offered = finding(
        id="offer",
        usage=Usage.KEY_EXCHANGE,
        negotiated=False,
        location=Location(source_type=SourceType.PCAP, flow="a"),
    )
    safe = finding(
        "AES",
        id="safe",
        usage=Usage.ENCRYPTION,
        key_size=256,
        location=Location(source_type=SourceType.PCAP, flow="b"),
    )
    assets, summary = run(kb, [code, offered, safe])
    assert summary.score < 60
    assert summary.score_by_source == {"code": 67, "pcap": 19}
    rsa = next(asset for asset in assets if asset.canonical_name == "RSA")
    assert rsa.hndl_exposed and rsa.negotiated
    active = offered.model_copy(update={"negotiated": True})
    _, active_summary = run(
        kb,
        [
            code,
            active,
            *[
                safe.model_copy(
                    update={"id": str(i), "location": safe.location.model_copy(update={"flow": str(i)})}
                )
                for i in range(30)
            ],
        ],
    )
    assert active_summary.score == 60
    assert active_summary.score_by_source["pcap"] == 60
    assert active_summary.score_by_source["code"] == 67


def test_source_tier_and_flags_do_not_leak(kb):
    one = classify(decompose(finding(), kb).root, kb)
    two = replace(
        one,
        tier=Tier.UNKNOWN,
        classically_broken=False,
        node=replace(
            one.node,
            normalized=replace(
                one.node.normalized,
                finding=finding(id="other", location=Location(source_type=SourceType.CONFIG, file="b")),
            ),
        ),
    )
    _, summary = score(aggregate([one, two]), kb.scoring)
    assert summary.counts_by_source["config"]["UNKNOWN"] == 1
    assert summary.score_by_source["config"] == 13
    assert summary.score_by_source["code"] == 67


@pytest.mark.parametrize(
    "name,size,confidence,expected,readiness",
    [
        ("AES", 256, 1, 0, 100),
        ("unknown", None, 1, 13, 0),
        ("RSA", 2048, 0, 0, 0),
    ],
)
def test_safe_unknown_zero(kb, name, size, confidence, expected, readiness):
    _, summary = run(kb, [finding(name, key_size=size, confidence=confidence, usage=Usage.ENCRYPTION)])
    assert summary.score == expected
    assert summary.readiness_pct == readiness


def test_empty_and_excluded_inputs(kb):
    assert analyze([])[1].score == 0
    raws = [
        finding("plaintext", kind_hint=KindHint.PLAINTEXT),
        finding("RSA", extra={"hygiene_only": True}),
        finding("package", kind_hint=KindHint.LIBRARY),
    ]
    assets, summary = run(kb, raws)
    assert len(assets) == 3
    assert all(asset.max_points == 0 for asset in assets)
    assert summary.score == 0 and summary.grade == "A" and summary.readiness_pct == 0
    assert sum(summary.counts_by_tier.values()) == 0
    assert summary.top_risks == []


def test_hndl_with_zero_confidence_has_zero_total(kb):
    _, summary = run(
        kb,
        [
            finding(
                usage=Usage.KEY_EXCHANGE,
                negotiated=True,
                confidence=0,
                location=Location(source_type=SourceType.PCAP, flow="a"),
            )
        ],
    )
    assert summary.score == 0 and summary.grade == "A"


@pytest.mark.parametrize(
    "value,grade",
    [
        (0, "A"),
        (10, "A"),
        (11, "B"),
        (25, "B"),
        (26, "C"),
        (40, "C"),
        (41, "D"),
        (60, "D"),
        (61, "E"),
        (80, "E"),
        (81, "F"),
        (100, "F"),
    ],
)
def test_grade_boundaries(kb, value, grade, monkeypatch):
    from quantumtrace.engine.score import _Points

    root = classify(decompose(finding(), kb).root, kb)
    from importlib import import_module

    monkeypatch.setattr(
        import_module("quantumtrace.engine.score"),
        "_points",
        lambda *args: _Points(Tier.CRITICAL, value, 100, False, False),
    )
    _, summary = score(aggregate([root]), kb.scoring)
    assert summary.score == value and summary.grade == grade


def test_rounding_and_clamp(kb):
    from quantumtrace.engine.score import _Points

    assert _score([_Points(Tier.MEDIUM, 10.5, 100, False, False)], kb.scoring) == 10
    assert _score([_Points(Tier.MEDIUM, 11.5, 100, False, False)], kb.scoring) == 12
    assert _score([_Points(Tier.CRITICAL, 200, 100, False, False)], kb.scoring) == 100


def test_analyze_determinism_links_and_no_mutation():
    raws = [
        finding(
            "0xC02F",
            kind_hint=KindHint.CIPHER_SUITE,
            key_size=None,
            usage=Usage.UNKNOWN,
            negotiated=True,
            location=Location(source_type=SourceType.PCAP, flow="a"),
        ),
        finding("AES", id="safe", usage=Usage.ENCRYPTION, key_size=256),
    ]
    before = [raw.model_dump() for raw in raws]
    expected = analyze(raws)
    assert any(asset.components and asset.max_points == 0 for asset in expected[0])
    assert all(asset.tier != Tier.UNKNOWN for asset in expected[0] if asset.canonical_name == "AES")
    for order in permutations(raws):
        assert analyze(list(order)) == expected
    assert [raw.model_dump() for raw in raws] == before
    ids = {asset.asset_id for asset in expected[0]}
    assert all(set(asset.components + asset.component_of) <= ids for asset in expected[0])


def test_readiness_excludes_unknown_and_containers(kb):
    raws = [
        finding(),
        finding("AES", id="safe", key_size=256, usage=Usage.ENCRYPTION),
        finding("unrecognized", id="unknown", key_size=None),
    ]
    _, summary = run(kb, raws)
    assert summary.readiness_pct == 50
    assert summary.counts_by_tier == {"CRITICAL": 1, "MEDIUM": 0, "SAFE": 1, "UNKNOWN": 1}


def test_score_copies_assets_and_leaves_raw_evidence_unchanged(kb):
    root = classify(decompose(finding(), kb).root, kb)
    result = aggregate([root])
    assets, summary = score(result, kb.scoring)
    assert result.assets[0].risk_points == 0 and result.assets[0].max_points == 0
    assets[0].occurrences[0].file = "changed"
    assert root.node.normalized.finding.location.file == "a.py"
    assert result.assets[0].occurrences[0].file == "a.py"
    assert summary.top_risks == [assets[0].asset_id]


def test_top_risks_points_and_stable_ties(kb):
    raws = [
        finding(),
        finding(usage=Usage.ENCRYPTION, id="second"),
        finding("RSA", key_size=1024, id="broken"),
        finding("AES", key_size=256, usage=Usage.ENCRYPTION, id="safe"),
    ]
    assets, summary = run(kb, raws)
    assert assets == sorted(assets, key=lambda asset: (-asset.risk_points, asset.asset_id))
    assert summary.top_risks == [asset.asset_id for asset in assets if asset.risk_points > 0]
    assert assets[0].classically_broken
