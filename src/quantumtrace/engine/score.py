"""Risk arithmetic over retained, source-filtered physical evidence."""

from __future__ import annotations

from dataclasses import dataclass
from math import fsum, log2

from quantumtrace.engine.aggregate import PATH_SOURCES, Aggregation
from quantumtrace.engine.classify import ClassifiedNode, summarize_verdict
from quantumtrace.kb.loader import Scoring
from quantumtrace.models import CryptoAsset, RiskSummary, SourceType, Tier, Usage

_TRANSIT = {SourceType.PCAP, SourceType.LIVE, SourceType.SSH}


def exposure(row: ClassifiedNode, policy: Scoring) -> float:
    """Choose the applicable exposure without inferring absent state/negotiation."""
    finding = row.node.normalized.finding
    source = finding.location.source_type
    categories = []
    if source in _TRANSIT:
        if finding.negotiated is True:
            categories.append(
                "negotiated_key_exchange"
                if row.node.normalized.identity.usage == Usage.KEY_EXCHANGE
                else "negotiated_other"
            )
        elif finding.negotiated is False:
            categories.append("offered_only")
    if source == SourceType.LOADBALANCER and finding.extra.get("public_exposure") is True:
        categories.append("public_loadbalancer_policy")
    if source == SourceType.KMS:
        state = finding.extra.get("state")
        if state == "Enabled":
            categories.append("kms_enabled")
        elif state in {"Disabled", "PendingDeletion"}:
            categories.append("kms_inactive")
    if source in PATH_SOURCES and finding.in_test_code:
        categories.append("test_only")
    if not categories:
        categories.append("production")
    weights = {str(key): value for key, value in policy.exposure.items()}
    return max(weights[key] for key in categories)


@dataclass(frozen=True)
class _Points:
    tier: Tier
    risk: float
    maximum: float
    hndl: bool
    active_hndl: bool


def _points(result: Aggregation, asset_id: str, policy: Scoring, source: SourceType | None) -> _Points | None:
    sites = [
        tuple(
            row
            for row in site.records
            if row.scoreable
            and (source is None or row.node.normalized.finding.location.source_type == source)
        )
        for site in result.evidence_index[asset_id]
    ]
    relevant = [site for site in sites if site]
    rows = tuple(row for site in relevant for row in site)
    if not rows:
        return None
    tier = summarize_verdict(rows).tier
    factor = 1 + log2(1 + min(len(relevant), policy.occurrence.cap)) / policy.occurrence.log_divisor
    common = max(exposure(row, policy) for row in rows) * factor * max(row.confidence for row in rows)
    broken = policy.broken_multiplier if any(row.classically_broken for row in rows) else 1.0
    return _Points(
        tier,
        policy.tier_weights[tier] * broken * common,
        policy.tier_weights[Tier.CRITICAL] * policy.broken_multiplier * common,
        any(row.hndl_exposed for row in rows),
        any(row.hndl_exposed and row.node.normalized.finding.negotiated is True for row in rows),
    )


def _score(points: list[_Points], policy: Scoring) -> int:
    maximum = fsum(point.maximum for point in points)
    if maximum == 0:
        return 0
    base = 100 * fsum(point.risk for point in points) / maximum
    floor = policy.hndl_floor.score if any(point.active_hndl for point in points) else 0
    return max(0, min(100, round(max(base, floor))))


def _counts(points: list[_Points]) -> dict[str, int]:
    return {tier.value: sum(point.tier == tier for point in points) for tier in Tier}


def score(result: Aggregation, policy: Scoring) -> tuple[list[CryptoAsset], RiskSummary]:
    """Return independently copied scored assets and summaries; never mutate evidence."""
    assets = [asset.model_copy(deep=True) for asset in result.assets]
    points = []
    for asset in assets:
        point = _points(result, asset.asset_id, policy, None)
        asset.risk_points = point.risk if point else 0.0
        asset.max_points = point.maximum if point else 0.0
        if point:
            points.append(point)
    sources = sorted(
        {
            row.node.normalized.finding.location.source_type
            for sites in result.evidence_index.values()
            for site in sites
            for row in site.records
        },
        key=lambda source: source.value,
    )
    by_source = {
        source.value: [
            point
            for asset in assets
            if (point := _points(result, asset.asset_id, policy, source)) is not None
        ]
        for source in sources
    }
    value = _score(points, policy)
    grade = next(band.grade for band in policy.grade_bands if band.minimum <= value <= band.maximum)
    known = [point for point in points if point.tier != Tier.UNKNOWN]
    assets.sort(key=lambda asset: (-asset.risk_points, asset.asset_id))
    return assets, RiskSummary(
        score=value,
        grade=grade,
        readiness_pct=100 * sum(point.tier == Tier.SAFE for point in known) / len(known) if known else 0.0,
        counts_by_tier=_counts(points),
        counts_by_source={source: _counts(rows) for source, rows in by_source.items()},
        score_by_source={source: _score(rows, policy) for source, rows in by_source.items()},
        hndl_exposed_count=sum(point.hndl for point in points),
        top_risks=[asset.asset_id for asset in assets if asset.risk_points > 0],
    )
