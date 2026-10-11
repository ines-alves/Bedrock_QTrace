"""Deterministic public assets plus private, source-preserving scoring evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Iterable, Mapping

from quantumtrace.engine.classify import ClassifiedNode
from quantumtrace.models import CryptoAsset, Finding, KindHint, Location, SourceType, Threat, Tier

# Path-based sources whose scanners mark files under test/example/mock paths (in_test_code).
PATH_SOURCES = frozenset({SourceType.CODE, SourceType.CONFIG, SourceType.KEYFILE, SourceType.BINARY})
_PRECEDENCE = {Tier.SAFE: 0, Tier.UNKNOWN: 1, Tier.MEDIUM: 2, Tier.CRITICAL: 3}


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _id(prefix: str, payload: object) -> str:
    return prefix + hashlib.sha256(_json(payload).encode()).hexdigest()[:24]


def _site(finding: Finding) -> tuple[object, ...]:
    """Physical evidence, independent of detector/snippet/confidence/negotiation.

    Repeated packets for a known flow/session are one occurrence. Frames distinguish
    otherwise unlocated packets; evidence without a locator uses the scanner ID.
    """
    loc = finding.location
    values = (loc.file, loc.line, loc.flow, loc.resource_id, loc.target, finding.session_id)
    fallback: object = None
    if loc.flow is None and finding.session_id is None and loc.resource_id is None and loc.line is None:
        if loc.frame is not None or loc.sni is not None:
            fallback = (loc.frame, loc.sni)
    if not any(value is not None for value in values) and fallback is None:
        fallback = finding.id
    return (loc.source_type.value, *values, fallback)


def _key(row: ClassifiedNode) -> str:
    finding = row.node.normalized.finding
    loc = finding.location
    scope: object = None
    if loc.resource_id is not None:
        scope = ("resource", loc.resource_id)
    elif (
        finding.kind_hint == KindHint.CERTIFICATE
        or loc.source_type == SourceType.KEYFILE
        or (finding.kind_hint == KindHint.KEY and loc.source_type not in {SourceType.CODE, SourceType.CONFIG})
    ):
        scope = ("material", _site(finding))
    elif row.node.kind == "container" and (finding.session_id is not None or loc.flow is not None):
        scope = ("session", loc.source_type, loc.file, finding.session_id, loc.flow, loc.target)
    # Trace and warning records cannot absorb scored evidence, nor override hybrids.
    parts: list[object] = [
        asdict(row.node.normalized.identity),
        row.node.kind,
        row.scoreable,
        row.exclusions,
        scope,
    ]
    # A hand-rolled implementation is its own asset, so its advice never lands on library call sites.
    # The marker is appended only when present, so every other asset id is unchanged.
    if finding.extra.get("hand_rolled") is True:
        parts.append("hand_rolled")
    return _json(parts)


@dataclass(frozen=True)
class EvidenceOccurrence:
    """One physical site; every distinct detector/state/provenance record survives.

    Scoring must filter records by source and scoreable before computing maximum
    confidence/exposure or negotiated HNDL. Never use public union flags for that.
    """

    occurrence_id: str
    records: tuple[ClassifiedNode, ...]

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(row.node.normalized.finding for row in self.records)


@dataclass(frozen=True)
class Aggregation:
    assets: tuple[CryptoAsset, ...]
    evidence_index: Mapping[str, tuple[EvidenceOccurrence, ...]]
    issues: tuple[str, ...] = ()


def _record_key(row: ClassifiedNode) -> str:
    # Full metadata is used only for deduplication/order, never for asset/site IDs.
    return _json(
        [
            row.node.normalized.finding.model_dump(mode="json"),
            asdict(row.node.normalized.identity),
            [asdict(item) for item in row.node.normalized.provenance],
            row.node.normalized.notes,
            row.node.node_id,
            row.node.role,
            row.confidence,
            row.rationale,
            row.tier,
            row.exclusions,
            [asdict(item) for item in row.recommendations],
            row.to_asset().model_dump(mode="json"),
        ]
    )


def _project(asset_id: str, rows: tuple[ClassifiedNode, ...]) -> CryptoAsset:
    tier = max((row.tier for row in rows), key=_PRECEDENCE.__getitem__)
    winner = next(row for row in rows if row.tier == tier)
    asset = winner.to_asset()
    asset.asset_id = asset_id
    asset.tier = tier
    threats = {row.threat for row in rows if row.tier == tier}
    asset.threat = next(iter(threats)) if len(threats) == 1 else Threat.UNKNOWN
    for field in ("classically_broken", "hndl_exposed", "deprecated_pqc_draft"):
        setattr(asset, field, any(getattr(row, field) for row in rows))
    # Optional facts require agreement from every retained observation. In particular
    # a final-standard name must not certify a merged pre-standard alias.
    for field in ("oid", "classical_security_bits", "nist_quantum_level", "pqc_standard", "forward_secrecy"):
        values = {getattr(row, field) for row in rows}
        setattr(asset, field, next(iter(values)) if len(values) == 1 else None)
    asset.rationale = "\n".join(sorted({row.rationale for row in rows}))
    advice = {item for row in rows for item in row.recommendations}
    asset.recommendations = [
        item.to_recommendation()
        for item in sorted(
            advice,
            key=lambda item: (item.priority, item.action, item.target_algorithm or "", item.standard or ""),
        )
    ]
    locations: dict[str, Location] = {}
    for row in rows:
        finding = row.node.normalized.finding
        site = _json(_site(finding))
        location = finding.location
        previous = locations.get(site)
        if previous is None or _json(location.model_dump(mode="json")) < _json(
            previous.model_dump(mode="json")
        ):
            locations[site] = location
    asset.occurrences = [locations[key].model_copy(deep=True) for key in sorted(locations)]
    asset.finding_ids = sorted({row.node.normalized.finding.id for row in rows})
    states = {row.node.normalized.finding.negotiated for row in rows}
    asset.negotiated = True if True in states else (False if states == {False} else None)
    located = [
        row.node.normalized.finding
        for row in rows
        if row.node.normalized.finding.location.source_type in PATH_SOURCES
    ]
    asset.in_test_code_only = bool(located) and all(finding.in_test_code for finding in located)
    asset.component_of = []
    asset.components = []
    return asset


def aggregate(roots: Iterable[ClassifiedNode]) -> Aggregation:
    """Aggregate classified trees without loading KB, reading time or assigning points.

    Original Findings remain read-only references; public assets are independent
    mutable projections. Pass roots with their children, not orphan flattened rows.
    Cloud joins use explicit certificate_arns; unavailable references are issues.
    """
    grouped: dict[str, dict[str, ClassifiedNode]] = {}
    edges: set[tuple[str, str]] = set()
    certificates: dict[str, set[str]] = {}
    listeners: dict[str, set[str]] = {}

    def visit(row: ClassifiedNode) -> str:
        # A single-part code composite (e.g. AES/ECB/PKCS5Padding -> AES) adds no asset of its own:
        # its evidence is a subset of its part, which carries it. Protocol, certificate and cloud
        # resource containers, and composites with several parts (SHA1withRSA), stay published.
        if (
            row.node.kind == "container"
            and len(row.children) == 1
            and row.node.normalized.identity.asset_type == "algorithm"
            and row.node.normalized.finding.location.source_type == SourceType.CODE
        ):
            return visit(row.children[0])
        key = _key(row)
        asset_id = _id("asset-", json.loads(key))
        grouped.setdefault(asset_id, {})[_record_key(row)] = row
        finding = row.node.normalized.finding
        resource = finding.location.resource_id
        if row.node.parent_id is None and resource:
            if finding.kind_hint == KindHint.CERTIFICATE:
                certificates.setdefault(resource, set()).add(asset_id)
            if (
                finding.kind_hint == KindHint.POLICY
                and finding.location.source_type == SourceType.LOADBALANCER
            ):
                refs = finding.extra.get("certificate_arns")
                if isinstance(refs, list):
                    listeners.setdefault(asset_id, set()).update(ref for ref in refs if isinstance(ref, str))
        for child in row.children:
            child_id = visit(child)
            if child_id != asset_id:
                edges.add((asset_id, child_id))
        return asset_id

    for root in roots:
        visit(root)
    issues = set()
    for listener, refs in listeners.items():
        for ref in refs:
            matches = certificates.get(ref)
            if matches:
                edges.update((listener, match) for match in matches if listener != match)
            else:
                issues.add(f"{listener}: certificate reference {ref!r} has no observed certificate.")
    assets = {}
    index = {}
    for asset_id in sorted(grouped):
        rows = tuple(grouped[asset_id][key] for key in sorted(grouped[asset_id]))
        assets[asset_id] = _project(asset_id, rows)
        sites: dict[str, list[ClassifiedNode]] = {}
        for row in rows:
            site_id = _id("occurrence-", _site(row.node.normalized.finding))
            sites.setdefault(site_id, []).append(row)
        index[asset_id] = tuple(EvidenceOccurrence(key, tuple(sites[key])) for key in sorted(sites))
    for parent, child in sorted(edges):
        assets[parent].components.append(child)
        assets[child].component_of.append(parent)
    for listener, refs in sorted(listeners.items()):
        asset = assets[listener]
        if any(ref not in certificates for ref in refs):
            if _PRECEDENCE[asset.tier] < _PRECEDENCE[Tier.UNKNOWN]:
                asset.tier, asset.threat = Tier.UNKNOWN, Threat.UNKNOWN
            asset.rationale += "\nReferenced authentication evidence is missing; no certificate key inferred."
        if refs:
            asset.rationale += "\nExplicit certificate references: " + ", ".join(sorted(refs)) + "."
            matched = sorted({match for ref in refs for match in certificates.get(ref, ())})
            for match in matched:
                cert = assets[match]
                asset.rationale += f"\nCertificate {match}: {cert.tier.value}. {cert.rationale}"
            advice = {
                _json(item.model_dump(mode="json")): item
                for child in [asset, *(assets[match] for match in matched)]
                for item in child.recommendations
            }
            asset.recommendations = [
                item.model_copy(deep=True)
                for item in sorted(
                    advice.values(),
                    key=lambda item: (
                        item.priority,
                        item.action,
                        item.target_algorithm or "",
                        item.standard or "",
                    ),
                )
            ]
    # Monotone container summaries also propagate explicit certificate joins through
    # nested policy containers. Atomic hybrids never take their trace children's tier.
    for _ in range(len(assets)):
        changed = False
        for asset_id, asset in assets.items():
            rows = tuple(grouped[asset_id].values())
            if rows[0].node.kind != "container" and asset_id not in listeners:
                continue
            children = [assets[child] for child in asset.components]
            tier = max([asset.tier, *(child.tier for child in children)], key=_PRECEDENCE.__getitem__)
            broken = asset.classically_broken or any(child.classically_broken for child in children)
            hndl = asset.hndl_exposed or any(child.hndl_exposed for child in children)
            if (tier, broken, hndl) != (asset.tier, asset.classically_broken, asset.hndl_exposed):
                asset.tier, asset.classically_broken, asset.hndl_exposed = tier, broken, hndl
                threats = {child.threat for child in children if child.tier == tier}
                asset.threat = next(iter(threats)) if len(threats) == 1 else Threat.UNKNOWN
                changed = True
        if not changed:
            break
    for asset_id, asset in assets.items():
        if grouped[asset_id] and next(iter(grouped[asset_id].values())).node.kind == "container":
            asset.rationale += (
                "\nAggregated components: "
                + "; ".join(f"{child}={assets[child].tier.value}" for child in asset.components)
                + f". Overall {asset.tier.value}; CRITICAL > MEDIUM > UNKNOWN > SAFE."
            )
    return Aggregation(tuple(assets.values()), MappingProxyType(index), tuple(sorted(issues)))
