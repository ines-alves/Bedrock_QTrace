"""Markdown executive summary of a ScanResult (M3D-08, PLAN 7.7).

The report is a rendering of the result: nothing is classified, scored or ranked here. Numbers come from
RiskSummary, the ranking is RiskSummary.top_risks (ordered asset ids; repeated ids dropped, ids that do not
resolve against ScanResult.assets are listed under Report diagnostics, never replaced by an own ranking).

Rendering rules agreed with M1:
- Evidence is location only (file and line, flow and frame, sni, resource id, target); snippets are never
  printed, so the report cannot leak what a scanner failed to redact.
- Hygiene-only warnings and library findings are read from ScanResult.findings (they belong to no asset).
  Warnings are shown for every source and stay outside the quantum-risk totals.
- Unordered inputs (assets, findings, occurrences, sessions, roadmap items, errors, inputs) are sorted, so
  the same result gives the same text. started_at and finished_at are omitted; scan_id is kept.
- The roadmap section is omitted when ScanResult.roadmap is None. Phases are planning targets.
- Table cells escape backslash, pipe and `<` (no raw HTML) and collapse line breaks.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from quantumtrace.models import (
    CryptoAsset,
    Finding,
    KindHint,
    Location,
    ScanResult,
    TLSSession,
)

TOP_RISKS_LIMIT = 10
OCCURRENCES_SHOWN = 3
SESSIONS_SHOWN = 10
ERRORS_SHOWN = 50
ROADMAP_ASSETS_SHOWN = 10

TIER_ORDER = ("CRITICAL", "MEDIUM", "UNKNOWN", "SAFE")
PHASE_LABELS = {0: "this week", 1: "now", 2: "by 2027", 3: "by 2030"}


# ---------------------------------------------------------------- text helpers


def _cell(value: object) -> str:
    """One line of safe inline Markdown: no table breaks, no raw HTML."""
    if value is None or value == "":
        return "-"
    text = str(value)
    for char in ("\r\n", "\n", "\r", "\t"):
        text = text.replace(char, " ")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").strip() or "-"


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = [
        "| " + " | ".join(_cell(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_cell(c) for c in row) + " |" for row in rows)
    return lines


def _tier_index(tier: str) -> int:
    return TIER_ORDER.index(tier) if tier in TIER_ORDER else len(TIER_ORDER)


# ---------------------------------------------------------------- evidence


def _location_key(loc: Location) -> tuple:
    return (
        loc.source_type.value,
        loc.file or "",
        -1 if loc.line is None else loc.line,
        loc.flow or "",
        -1 if loc.frame is None else loc.frame,
        loc.sni or "",
        loc.resource_id or "",
        loc.target or "",
    )


def _location_text(loc: Location) -> str:
    parts: list[str] = []
    if loc.file:
        parts.append(f"{loc.file}:{loc.line}" if loc.line is not None else loc.file)
    if loc.flow:
        parts.append(f"flow {loc.flow}")
    if loc.frame is not None:
        parts.append(f"frame {loc.frame}")
    if loc.sni:
        parts.append(f"sni {loc.sni}")
    if loc.resource_id:
        parts.append(f"resource {loc.resource_id}")
    if loc.target:
        parts.append(f"target {loc.target}")
    return f"{loc.source_type.value}: {' '.join(parts)}" if parts else loc.source_type.value


def _evidence(locations: list[Location], shown: int = OCCURRENCES_SHOWN) -> str:
    unique = {_location_key(loc): loc for loc in locations}
    ordered = [unique[key] for key in sorted(unique)]
    texts = [_location_text(loc) for loc in ordered[:shown]]
    if len(ordered) > shown:
        texts.append(f"+{len(ordered) - shown} more")
    return "; ".join(texts)


def _recommendation(asset: CryptoAsset) -> str:
    if not asset.recommendations:
        return ""
    rec = min(
        asset.recommendations,
        key=lambda r: (r.priority, r.action, r.target_algorithm or "", r.standard or ""),
    )
    details = [f"target: {rec.target_algorithm}"] if rec.target_algorithm else []
    if rec.standard:
        details.append(f"standard: {rec.standard}")
    return rec.action + (f" ({'; '.join(details)})" if details else "")


def _asset_label(asset: CryptoAsset) -> str:
    """Name, then the parameters the name does not already carry, then the id.

    The engine's canonical_name can be a bare family ("RSA"), so two assets that differ only in key size,
    curve or mode would otherwise read the same; the id alone is an opaque hash.
    """
    name = asset.canonical_name.lower()
    candidates = [
        (str(asset.key_size), f"{asset.key_size}-bit") if asset.key_size is not None else None,
        (asset.curve.lower(), asset.curve) if asset.curve else None,
        (asset.mode.lower(), asset.mode) if asset.mode else None,
        (asset.parameter_set.lower(), asset.parameter_set) if asset.parameter_set else None,
    ]
    params = [text for needle, text in filter(None, candidates) if needle not in name]
    return " ".join([asset.canonical_name, *params]) + f" ({asset.asset_id})"


# ---------------------------------------------------------------- sections


def _header(result: ScanResult) -> list[str]:
    lines = ["# QuantumTrace summary", ""]
    lines.append(f"- Scan: {_cell(result.scan_id)}")
    lines.append(f"- Tool version: {_cell(result.tool_version)}")
    lines.append(f"- Schema version: {_cell(result.schema_version)}")
    inputs = sorted(result.inputs)
    lines.append("- Inputs: " + (", ".join(_cell(i) for i in inputs) if inputs else "none"))
    return lines


def _score_section(result: ScanResult) -> list[str]:
    s = result.summary
    return [
        "## Score",
        "",
        f"- Quantum risk score: {s.score}/100 (higher is worse)",
        f"- Grade: {s.grade}",
        f"- Readiness: {s.readiness_pct:.1f}% of eligible classified assets are SAFE",
        f"- Assets exposed to harvest now, decrypt later: {s.hndl_exposed_count}",
    ]


def _counts_section(result: ScanResult) -> list[str]:
    s = result.summary
    extra = sorted(
        (set(s.counts_by_tier) | {t for c in s.counts_by_source.values() for t in c}) - set(TIER_ORDER)
    )
    tiers = list(TIER_ORDER) + extra
    lines = ["## Counts by tier", ""]
    lines += _table(["Tier", "Assets"], [[t, s.counts_by_tier.get(t, 0)] for t in tiers])
    sources = sorted(set(s.counts_by_source) | set(s.score_by_source))
    lines += ["", "## Counts by source", ""]
    if not sources:
        lines.append("No per-source results.")
        return lines
    rows = [
        [src, *(s.counts_by_source.get(src, {}).get(t, 0) for t in tiers), s.score_by_source.get(src)]
        for src in sources
    ]
    lines += _table(["Source", *tiers, "Score"], rows)
    return lines


def _top_risks_section(ranked: list[CryptoAsset], valid_total: int, unresolved: list[str]) -> list[str]:
    lines = ["## Top risks", ""]
    if not ranked:
        lines.append("No ranked risks in this result.")
        return lines
    rows = []
    for rank, asset in enumerate(ranked, start=1):
        flags = []
        if asset.hndl_exposed:
            flags.append("HNDL")
        if asset.classically_broken:
            flags.append("classically broken")
        if asset.in_test_code_only:
            flags.append("test code only")
        rows.append(
            [
                rank,
                _asset_label(asset),
                asset.tier.value,
                asset.threat.value,
                asset.usage.value,
                ", ".join(flags),
                _evidence(asset.occurrences),
                _recommendation(asset),
            ]
        )
    lines += _table(["Rank", "Asset", "Tier", "Threat", "Usage", "Flags", "Evidence", "Recommendation"], rows)
    if valid_total > len(ranked):
        lines += ["", f"Showing {len(ranked)} of {valid_total} ranked assets, in the engine's order."]
    if unresolved:
        lines += ["", f"{len(unresolved)} ranked id(s) are not in the asset list; see Report diagnostics."]
    return lines


def _unique_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for f in sorted(findings, key=lambda f: (f.id, f.raw_name, _location_key(f.location))):
        unique.setdefault(f.id, f)
    return list(unique.values())


def _warnings_section(findings: list[Finding]) -> list[str]:
    lines = [
        "## Warnings",
        "",
        "Hygiene-only findings. They are shown for every source and are excluded "
        "from the score, the readiness and the tier counts.",
        "",
    ]
    groups: dict[tuple, list[Finding]] = {}
    for f in _unique_findings(findings):
        if f.extra.get("hygiene_only") is not True:
            continue
        raw_flags = f.extra.get("hygiene_flags") or []
        flags = tuple(sorted(str(x) for x in raw_flags)) if isinstance(raw_flags, list) else ()
        groups.setdefault((f.raw_name, flags, f.location.source_type.value), []).append(f)
    if not groups:
        lines.append("No warnings.")
        return lines
    rows = []
    for (raw_name, flags, source), members in sorted(groups.items()):
        in_test = sum(1 for m in members if m.in_test_code)
        test = "yes" if in_test == len(members) else "partly" if in_test else "no"
        rows.append(
            [
                raw_name,
                ", ".join(flags),
                source,
                len(members),
                test,
                _evidence([m.location for m in members]),
            ]
        )
    lines += _table(["Warning", "Flags", "Source", "Findings", "Test code", "Evidence"], rows)
    return lines


def _libraries_section(findings: list[Finding]) -> list[str]:
    lines = ["## Library inventory", ""]
    libs = [f for f in _unique_findings(findings) if f.kind_hint is KindHint.LIBRARY]
    if not libs:
        lines.append("No library findings.")
        return lines
    libs.sort(
        key=lambda f: (f.library or f.raw_name, f.raw_name, f.language or "", _location_key(f.location))
    )
    rows = [
        [
            f.library or f.raw_name,
            f.raw_name,
            f.language,
            _location_text(f.location),
            "yes" if f.in_test_code else "no",
        ]
        for f in libs
    ]
    lines += _table(["Library", "Declared", "Language", "Location", "Test code"], rows)
    return lines


def _sessions_section(sessions: list[TLSSession]) -> list[str]:
    lines = ["## TLS and SSH sessions", ""]
    if not sessions:
        lines.append("No TLS or SSH sessions in this result.")
        return lines
    counts = Counter((s.transport, s.pq_status, s.verdict_tier.value) for s in sessions)
    count_rows = [
        [transport, pq, tier, n]
        for (transport, pq, tier), n in sorted(
            counts.items(), key=lambda kv: (kv[0][0], kv[0][1], _tier_index(kv[0][2]))
        )
    ]
    lines += _table(["Transport", "PQ status", "Verdict", "Sessions"], count_rows)
    ordered = sorted(sessions, key=lambda s: (_tier_index(s.verdict_tier.value), s.flow, s.session_id))
    shown = ordered[:SESSIONS_SHOWN]
    rows = [
        [
            s.verdict_tier.value,
            s.transport,
            s.service,
            s.flow,
            s.version,
            s.negotiated_group,
            s.negotiated_cipher_suite,
            s.pq_status,
        ]
        for s in shown
    ]
    lines += [""]
    lines += _table(
        ["Verdict", "Transport", "Service", "Flow", "Version", "Negotiated group", "Negotiated suite", "PQ"],
        rows,
    )
    if len(ordered) > len(shown):
        lines += [
            "",
            f"Showing {len(shown)} of {len(ordered)} sessions, ordered by verdict, flow and session id.",
        ]
    return lines


def _roadmap_section(result: ScanResult, assets: dict[str, CryptoAsset]) -> list[str]:
    if result.roadmap is None:
        return []
    lines = ["## Roadmap", ""]
    lines.append("Phases are project planning targets, not regulatory deadlines.")
    if not result.roadmap:
        return lines + ["", "No roadmap items."]
    items = sorted(
        result.roadmap,
        key=lambda i: (i.phase, i.action, sorted(i.asset_ids), i.occurrence_count),
    )
    current: int | None = None
    for item in items:
        if item.phase != current:
            current = item.phase
            lines += ["", f"### Phase {item.phase}: {PHASE_LABELS[item.phase]}", ""]
        ids = sorted(set(item.asset_ids), key=lambda i: (_asset_label(assets[i]) if i in assets else i, i))
        names = [_asset_label(assets[i]) if i in assets else f"{i} (not in assets)" for i in ids]
        if len(names) > ROADMAP_ASSETS_SHOWN:
            names = names[:ROADMAP_ASSETS_SHOWN] + [f"+{len(ids) - ROADMAP_ASSETS_SHOWN} more"]
        detail = f"{item.occurrence_count} occurrence(s); assets: " + (", ".join(names) or "none")
        lines.append(f"- {_cell(item.action)}: {_cell(detail)}")
    return lines


def _errors_section(result: ScanResult) -> list[str]:
    lines = ["## Errors and coverage", ""]
    if result.errors:
        errors = sorted(result.errors, key=lambda e: (e.detector, e.path or "", e.message))
        lines.append(f"{len(errors)} scan error(s). Coverage is incomplete for the paths below.")
        lines.append("")
        lines += _table(
            ["Detector", "Path", "Message"],
            [[e.detector, e.path, e.message] for e in errors[:ERRORS_SHOWN]],
        )
        if len(errors) > ERRORS_SHOWN:
            lines += ["", f"Showing {ERRORS_SHOWN} of {len(errors)} errors, ordered by detector and path."]
    else:
        lines.append("No scan errors were reported.")
    lines += [
        "",
        "Coverage is limited to what the registered scanners handled. An input a scanner does not "
        "support appears as an error; an empty error list is not a statement that every file type "
        "was scanned.",
    ]
    return lines


def _diagnostics_section(unresolved_risks: list[str], unresolved_roadmap: list[str]) -> list[str]:
    lines = ["## Report diagnostics", ""]
    if not unresolved_risks and not unresolved_roadmap:
        return lines + ["None."]
    if unresolved_risks:
        lines.append(
            "Ranked ids (summary.top_risks) with no matching asset, listed in ranking order: "
            + ", ".join(_cell(i) for i in unresolved_risks)
        )
    if unresolved_roadmap:
        lines.append(
            "Roadmap asset ids with no matching asset: " + ", ".join(_cell(i) for i in unresolved_roadmap)
        )
    return lines


# ---------------------------------------------------------------- public API


def render_markdown_summary(result: ScanResult) -> str:
    """Render the executive summary: deterministic for the same result, whatever the input order."""
    assets: dict[str, CryptoAsset] = {}
    for asset in sorted(result.assets, key=lambda a: (a.asset_id, a.canonical_name, a.tier.value)):
        assets.setdefault(asset.asset_id, asset)

    valid: list[CryptoAsset] = []
    unresolved_risks: list[str] = []
    seen: set[str] = set()
    for asset_id in result.summary.top_risks:
        if asset_id in seen:
            continue
        seen.add(asset_id)
        if asset_id in assets:
            valid.append(assets[asset_id])
        else:
            unresolved_risks.append(asset_id)

    unresolved_roadmap = sorted(
        {i for item in result.roadmap or [] for i in item.asset_ids if i not in assets}
    )

    sections = [
        _header(result),
        _score_section(result),
        _counts_section(result),
        _top_risks_section(valid[:TOP_RISKS_LIMIT], len(valid), unresolved_risks),
        _warnings_section(result.findings),
        _libraries_section(result.findings),
        _sessions_section(result.sessions),
        _roadmap_section(result, assets),
        _errors_section(result),
        _diagnostics_section(unresolved_risks, unresolved_roadmap),
    ]
    return "\n\n".join("\n".join(section) for section in sections if section) + "\n"


def write_markdown_summary(result: ScanResult, path: str | Path) -> None:
    """Write the summary as UTF-8 with LF line endings, creating parent directories."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_markdown_summary(result), encoding="utf-8", newline="\n")
