"""Planning phases from private evidence; dates are not regulatory assertions."""

from __future__ import annotations

from typing import Literal

from quantumtrace.engine.aggregate import Aggregation
from quantumtrace.engine.classify import ClassifiedNode
from quantumtrace.models import RoadmapItem, SourceType, Threat, Tier, Usage

Phase = Literal[0, 1, 2, 3]
_TRANSIT = {SourceType.PCAP, SourceType.LIVE, SourceType.SSH}
_REVIEW = "Resolve uncertain cryptographic evidence and usage before selecting a migration."


def _phase(row: ClassifiedNode) -> Phase:
    usage = row.node.normalized.identity.usage
    if row.tier == Tier.UNKNOWN:
        return 0
    if row.threat == Threat.GROVER:
        return 3
    if usage == Usage.KEY_EXCHANGE:
        return 1
    if usage in {Usage.SIGNATURE, Usage.AUTHENTICATION}:
        return 2
    if row.threat == Threat.SHOR:
        return 1 if usage == Usage.ENCRYPTION else 0
    return 3


def build_roadmap(evidence: Aggregation) -> list[RoadmapItem]:
    """Union actions by phase with unique physical sites and retained asset links.

    Containers and hybrid trace halves are not migration mechanisms. Maintenance
    comes from root policy records and is independent of quantum score or tier.
    Broken assets never repeat their migration actions in a later phase.
    """
    groups: dict[tuple[Phase, str], tuple[set[str], set[str]]] = {}

    def add(phase: Phase, action: str, asset_id: str, occurrence_id: str) -> None:
        assets, sites = groups.setdefault((phase, action), (set(), set()))
        assets.add(asset_id)
        sites.add(occurrence_id)

    for asset_id, sites in evidence.evidence_index.items():
        broken = any(row.scoreable and row.classically_broken for site in sites for row in site.records)
        for site in sites:
            for row in site.records:
                if row.node.parent_id is None:
                    for advice in row.maintenance:
                        add(0, advice.action, asset_id, site.occurrence_id)
                if not row.scoreable or row.tier == Tier.SAFE:
                    continue
                phase = 0 if broken else _phase(row)
                actions = (
                    [_REVIEW]
                    if not broken and phase == 0
                    else [advice.action for advice in row.recommendations if advice not in row.maintenance]
                )
                if not actions:
                    actions = ["Review and replace the observed vulnerable cryptographic mechanism."]
                raw = row.node.normalized.finding
                for action in actions:
                    if raw.location.source_type in _TRANSIT and raw.negotiated is False:
                        action = "Review offered-only capability: " + action
                    add(phase, action, asset_id, site.occurrence_id)
    return [
        RoadmapItem(phase=phase, action=action, asset_ids=sorted(assets), occurrence_count=len(sites))
        for (phase, action), (assets, sites) in sorted(groups.items())
    ]
