"""Offline golden evaluation of unique evidence, independently of aggregate counts."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from quantumtrace.engine import classify_findings
from quantumtrace.engine.aggregate import _site
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import ScanResult
from quantumtrace.pipeline import _run

Row = dict[str, Any]
REQUIRED = {"code", "pcap", "ssh", "kms", "loadbalancer", "acm"}


def subset(want: Any, got: Any) -> bool:
    """Compare recursive metadata subsets; list assertions require all stated elements."""
    if isinstance(want, dict):
        return isinstance(got, dict) and all(k in got and subset(v, got[k]) for k, v in want.items())
    if isinstance(want, list):
        return isinstance(got, list) and all(v in got for v in want)
    return type(want) is type(got) and want == got


def observations(result: ScanResult) -> dict[str, list[Row]]:
    """Retain per-source classification/state rather than aggregated asset flags."""
    assets: dict[str, Row] = {}
    inventory: dict[str, Row] = {}
    findings: dict[str, Row] = {}
    session_sources: dict[str, set[tuple[str, str]]] = {}
    for finding in result.findings:
        loc = finding.location.model_dump(mode="json")
        identity = list(_site(finding))
        row = {**loc, "source": loc["file"], **finding.model_dump(mode="json")}
        row["resource"] = loc["resource_id"]
        row["resource_alias"] = finding.extra.get("alias")
        # Raw occurrences distinguish algorithms and states, but not detector/snippet copies.
        key = json.dumps(
            [identity, finding.raw_name, finding.kind_hint.value, finding.usage.value, finding.negotiated],
            sort_keys=True,
        )
        previous = findings.get(key)
        if previous is not None:
            row["conflicting_metadata"] = (
                previous.get("conflicting_metadata", False) or previous["extra"] != row["extra"]
            )
        findings[key] = row
        if finding.session_id:
            session_sources.setdefault(finding.session_id, set()).add((loc["file"], loc["source_type"]))
    for root in classify_findings(
        result.findings, load_kb(), scan_started_at=datetime.fromisoformat(result.started_at)
    ):
        for classified in root.walk():
            if not classified.scoreable and classified.node.kind != "container":
                continue
            f = classified.node.normalized.finding
            a = classified.to_asset()
            loc = f.location.model_dump(mode="json")
            canonical = a.canonical_name
            if canonical in {"AES", "RSA", "DH", "DSA"} and a.key_size is not None:
                canonical += f"-{a.key_size}"
            row = {
                **a.model_dump(mode="json"),
                **loc,
                "source": loc["file"],
                "canonical": canonical,
                "resource": loc["resource_id"],
                "resource_alias": f.extra.get("alias"),
                "negotiated": f.negotiated,
            }
            key = json.dumps(
                [_site(f), canonical, a.usage.value, a.asset_type, a.mode, a.curve, a.parameter_set],
                sort_keys=True,
            )
            pool = assets if classified.scoreable else inventory
            previous = pool.get(key)
            if previous is not None:
                row["conflicting_classification"] = previous.get("conflicting_classification", False)
                for flag in ("tier", "classically_broken", "hndl_exposed"):
                    if previous[flag] != row[flag]:
                        row["conflicting_classification"] = True
                # Keep negotiation states of this physical occurrence for selectors.
                row["states"] = list(set(previous.get("states", [previous["negotiated"]]) + [f.negotiated]))
            pool[key] = row
    sessions = []
    for session in result.sessions:
        for source, source_type in sorted(session_sources.get(session.session_id, set())):
            # A TLS view may have both pcap and ssh source records: transport selects its namespace.
            if source_type != ("ssh" if session.transport == "ssh" else "pcap"):
                continue
            kex = {
                r["tier"]
                for r in assets.values()
                if r["source"] == source
                and r.get("flow") == session.flow
                and r["usage"] == "key_exchange"
                and True in r.get("states", [r["negotiated"]])
            }
            sessions.append(
                {
                    **session.model_dump(mode="json"),
                    "source": source,
                    "source_type": source_type,
                    "session_sni": session.sni,
                    "tier_session": session.verdict_tier.value,
                    "tier_kex": next(iter(kex)) if len(kex) == 1 else None,
                }
            )

    def sort_key(r: Row) -> str:
        return json.dumps(r, sort_keys=True)

    return {
        "asset": sorted(assets.values(), key=sort_key),
        "inventory": sorted(inventory.values(), key=sort_key),
        "finding": sorted(findings.values(), key=sort_key),
        "session": sorted(sessions, key=sort_key),
    }


def identity(want: Row, got: Row, *, algorithm: bool = True) -> bool:
    """Exact source/resource selectors, with two-line tolerance for code evidence."""
    fields = ["source", "source_type", "resource", "resource_alias", "session_id", "session_sni", "transport"]
    if algorithm:
        fields += ["canonical", "usage", "asset_type", "kind_hint", "raw_name"]
    for key in fields:
        if key in want and want[key] != got.get(key):
            return False
    if "negotiated" in want and want["negotiated"] not in got.get("states", [got.get("negotiated")]):
        return False
    return "line" not in want or (got.get("line") is not None and abs(want["line"] - got["line"]) <= 2)


def match(rows: list[Row], observed: list[Row]) -> tuple[dict[int, int], list[int]]:
    """Maximum one-to-one matching; nearest lines first, independent of input order."""
    candidates = {}
    ambiguous = []
    for i, row in enumerate(rows):
        c = [j for j, got in enumerate(observed) if identity(row, got)]
        c.sort(key=lambda j: (abs(row.get("line", 0) - (observed[j].get("line") or 0)), j))
        if row["kind"] == "session" and len(c) > 1:
            ambiguous.append(i)
            c = []
        candidates[i] = c
    assigned: dict[int, int] = {}

    def assign(i: int, seen: set[int]) -> bool:
        for j in candidates[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in assigned or assign(assigned[j], seen):
                assigned[j] = i
                return True
        return False

    for i in sorted(candidates, key=lambda i: (len(candidates[i]), json.dumps(rows[i], sort_keys=True))):
        assign(i, set())
    return {i: j for j, i in assigned.items()}, ambiguous


@dataclass
class Metrics:
    expected: int = 0
    observed: int = 0
    matched: int = 0
    correct_tier: int = 0

    @property
    def precision(self) -> float | None:
        return self.matched / self.observed if self.observed else (0.0 if self.expected else None)

    @property
    def recall(self) -> float | None:
        return self.matched / self.expected if self.expected else (0.0 if self.observed else None)

    @property
    def tier_accuracy(self) -> float | None:
        return self.correct_tier / self.matched if self.matched else None


@dataclass
class Evaluation:
    metrics: dict[str, Metrics] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    unassessed: dict[str, int] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        overall = self.metrics["overall"]
        return (
            not self.failures
            and overall.expected > 0
            and all(
                m.precision is not None and m.recall is not None and m.precision >= 0.95 and m.recall >= 0.95
                for m in self.metrics.values()
                if m.expected or m.observed
            )
        )


def evaluate(rows: list[Row], result: ScanResult, *, required: set[str] | None = None) -> Evaluation:
    """Measure confirmed algorithm rows; missing coverage and assertions fail separately."""
    data = observations(result)
    report = Evaluation(
        metrics={s: Metrics() for s in sorted(required if required is not None else REQUIRED)}
    )
    confirmed = {
        (r["source"], r.get("source_type"))
        for r in rows
        if r["kind"] == "asset" and r.get("asset_type", "algorithm") == "algorithm"
    }
    for source_type in sorted(required if required is not None else REQUIRED):
        if not any(t == source_type for _, t in confirmed) and not any(
            "source_type" not in r
            and r["kind"] == "asset"
            and any(g["source_type"] == source_type and identity(r, g) for g in data["asset"])
            for r in rows
        ):
            report.failures.append(f"unconfirmed golden algorithm coverage: {source_type}")
    for row in data["asset"]:
        if not any(row["source"] == s and (t is None or t == row["source_type"]) for s, t in confirmed):
            t = row["source_type"]
            report.unassessed[t] = report.unassessed.get(t, 0) + 1
    if report.unassessed:
        report.failures.append("unassessed algorithm evidence outside confirmed golden scope")
    for kind in ("asset", "finding"):
        if any(g.get("conflicting_metadata") or g.get("conflicting_classification") for g in data[kind]):
            report.failures.append(f"conflicting {kind} evidence")
    for kind in ("asset", "finding", "session"):
        wants = sorted([r for r in rows if r["kind"] == kind], key=lambda r: json.dumps(r, sort_keys=True))
        got = data[kind]
        if kind == "asset":
            got = [
                g
                for g in got
                if any(g["source"] == s and (t is None or g["source_type"] == t) for s, t in confirmed)
            ]
            got += [
                g
                for g in data["inventory"]
                if any(
                    identity(r, g)
                    for r in wants
                    if r.get("asset_type") in {"protocol", "certificate", "related-crypto-material"}
                )
            ]
        matched, ambiguous = match(wants, got)
        for i in ambiguous:
            report.failures.append(f"ambiguous session: {wants[i]}")
        for i, row in enumerate(wants):
            possible_types = {g["source_type"] for g in data[kind] if g["source"] == row["source"]}
            t = row.get(
                "source_type", next(iter(possible_types)) if len(possible_types) == 1 else "unspecified"
            )
            if i in matched:
                t = got[matched[i]]["source_type"]
            m = report.metrics.setdefault(t, Metrics())
            measured = kind == "asset" and row.get("asset_type", "algorithm") == "algorithm"
            if measured:
                m.expected += 1
            if i not in matched:
                report.diagnostics.append(f"missed {kind}: {row}")
                if kind != "asset" or row.get("tier") == "SAFE":
                    report.failures.append(f"missing required safety/evidence assertion: {row}")
                if kind == "asset":
                    nearby = [
                        g
                        for j, g in enumerate(got)
                        if j not in matched.values() and identity(row, g, algorithm=False)
                    ]
                    if len(nearby) == 1:
                        report.diagnostics.append(
                            f"wrong algorithm/usage at {row['source']}:{row.get('line')}: "
                            f"expected {row['canonical']}, observed {nearby[0]['canonical']}"
                        )
                continue
            g = got[matched[i]]
            if measured:
                m.matched += 1
                m.correct_tier += row["tier"] == g["tier"]
            fields = (
                ("tier", "classically_broken", "hndl_exposed")
                if kind == "asset"
                else (("tier_session", "tier_kex", "negotiated_group") if kind == "session" else ("extra",))
            )
            for key in fields:
                if key in row and not subset(row[key], g.get(key)):
                    report.failures.append(f"wrong {key}: {row}; observed={g.get(key)!r}")
            if g.get("conflicting_metadata") or g.get("conflicting_classification"):
                report.failures.append(f"conflicting evidence: {row}")
        if kind == "asset":
            for j, g in enumerate(got):
                if g["asset_type"] != "algorithm":
                    continue
                report.metrics.setdefault(g["source_type"], Metrics()).observed += 1
                if j not in matched.values():
                    report.diagnostics.append(
                        f"false positive/unmatched algorithm: {g['source']}:{g.get('line')} "
                        f"{g['canonical']} {g['usage']}"
                    )
    for row in (r for r in rows if r["kind"] == "count"):
        count = count_observations(row, data)
        if count != row["count"]:
            report.failures.append(f"wrong count: {row}; observed={count}")
    if len({s.session_id for s in result.sessions}) != len(result.sessions):
        report.failures.append("duplicate session IDs in produced session views")
    for error in result.errors:
        report.failures.append(f"scan error: {error.detector} {error.path}: {error.message}")
    overall = Metrics()
    for m in report.metrics.values():
        for key in ("expected", "observed", "matched", "correct_tier"):
            setattr(overall, key, getattr(overall, key) + getattr(m, key))
    report.metrics["overall"] = overall
    return report


def count_observations(row: Row, data: dict[str, list[Row]]) -> int:
    """Count raw occurrences, resources or session IDs without creating true positives."""
    selected = [g for g in data["session" if row["metric"] == "sessions" else "finding"] if identity(row, g)]
    if row["metric"] == "sessions":
        return len({g["session_id"] for g in selected})
    if row["metric"] == "resources":
        return len({g["resource"] for g in selected if g["resource"] is not None})
    return len(selected)


def load_rows(path: Path, schema: Path) -> list[Row]:
    """Validate contributed golden rows before scanning any inputs."""
    rows = yaml.safe_load(path.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(schema.read_text(encoding="utf-8"))).validate(rows)
    for row in rows:
        source = Path(row["source"])
        if source.is_absolute() or ".." in source.parts:
            raise ValueError("golden sources must be repository-relative")
        # Session IDs hash Location.file, so starter rows must use portable selectors.
        if "session_id" in row and source.parts[:1] == ("network-capture",):
            raise ValueError("starter network golden rows must not use literal session_id selectors")
    return rows


def main(argv: list[str] | None = None) -> int:
    """Run the repository golden gate; 0 passes, 1 fails accuracy, 2 is invalid setup."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path.cwd(), help="repository containing starter/golden inputs"
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        rows = load_rows(root / "tests/golden/expected.yaml", root / "docs/golden.schema.json")
        result = _run(
            [
                p
                for directory in ("sample-repos", "cloud-posture")
                for p in sorted((root / directory).rglob("*"))
                if p.is_file() and p.name != "README.md"
            ]
            + [root / "network-capture/network.pcap"],
            scan_root=root,
        )
        report = evaluate(rows, result)
        seeds = load_rows(root / "tests/golden/provisional.yaml", root / "docs/golden.schema.json")
        observed = observations(result)
        provisional = [(r, count_observations(r, observed)) for r in seeds]
        for row, count in provisional:
            if count != row["count"]:
                report.failures.append(f"provisional count mismatch: {row}; observed={count}")
    except Exception as exc:
        print(f"Evaluation setup failed: {type(exc).__name__}: {exc}")
        return 2
    print("Confirmed algorithm occurrences only; unconfirmed sources do not establish accuracy.")
    print(
        "Overall below covers confirmed rows ONLY; full-starter accuracy remains unmeasured if coverage fails."
    )
    print("source       expected observed matched precision recall tier_accuracy")
    for source, m in report.metrics.items():

        def fmt(x: float | None) -> str:
            return "N/A" if x is None else f"{x:.4f}"

        print(
            f"{source:12} {m.expected:8} {m.observed:8} {m.matched:7} "
            f"{fmt(m.precision):>9} {fmt(m.recall):>6} {fmt(m.tier_accuracy):>13}"
        )
    print(f"Unassessed algorithm occurrences: {dict(sorted(report.unassessed.items()))}")
    for row, count in provisional:
        print(
            f"Provisional Appendix D count (not owner-confirmed): {row['source_type']} "
            f"{row.get('transport', row['metric'])}: expected={row['count']} observed={count}"
        )
    for diagnostic in report.diagnostics:
        print(f"DETAIL: {diagnostic}")
    for failure in report.failures:
        print(f"FAIL: {failure}")
    print(
        f"Gate: {'PASS' if report.passed else 'FAIL'}; precision/recall >=0.95 plus assertions and coverage"
    )
    return 0 if report.passed else 1
