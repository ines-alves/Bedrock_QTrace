"""Deterministic classification, aggregation, and risk scoring."""

from datetime import datetime

from quantumtrace.engine.aggregate import aggregate
from quantumtrace.engine.classify import classify
from quantumtrace.engine.decompose import decompose
from quantumtrace.engine.registries import CloudRegistry, TLSRegistry
from quantumtrace.engine.score import score
from quantumtrace.kb.loader import KnowledgeBase, load_kb
from quantumtrace.models import CryptoAsset, Finding, RiskSummary


def analyze(
    findings: list[Finding],
    *,
    kb: KnowledgeBase | None = None,
    scan_started_at: datetime | None = None,
) -> tuple[list[CryptoAsset], RiskSummary]:
    """Classify raw evidence and score it using packaged KB/owner registries.

    No clock, scanner invocation or session assembly occurs here. The optional
    explicit timestamp is used only for deterministic cloud hygiene classification.
    """
    knowledge = kb if kb is not None else load_kb()
    tls = TLSRegistry()
    cloud = CloudRegistry(tls)
    roots = []
    for finding in findings:
        result = decompose(finding, knowledge, registry=tls, named_registry=tls, cloud_registry=cloud)
        if result.root is not None:
            roots.append(classify(result.root, knowledge, scan_started_at=scan_started_at))
    return score(aggregate(roots), knowledge.scoring)


__all__ = ["analyze"]
