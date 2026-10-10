"""Typed session views from observed network metadata and negotiated classified atoms."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Literal

from quantumtrace.engine.classify import ClassifiedNode, summarize_verdict
from quantumtrace.engine.registries import TLSRegistry
from quantumtrace.models import Finding, KindHint, ScanError, SourceType, Tier, TLSSession, Usage

_NETWORK = {SourceType.PCAP, SourceType.LIVE, SourceType.SSH}
_LIST_KINDS = {
    "offered_groups": KindHint.GROUP,
    "offered_cipher_suites": KindHint.CIPHER_SUITE,
    "offered_sig_schemes": KindHint.SIGNATURE_SCHEME,
}
_SCALAR_KINDS = {"negotiated_group": KindHint.GROUP, "negotiated_cipher_suite": KindHint.CIPHER_SUITE}


def build_sessions(
    findings: list[Finding], roots: list[ClassifiedNode]
) -> tuple[list[TLSSession], list[ScanError]]:
    """Do not infer a selected component from client offers or from nearby sessions."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if (
            finding.session_id
            and finding.location.source_type in _NETWORK
            and finding.kind_hint != KindHint.PLAINTEXT
        ):
            grouped[finding.session_id].append(finding)
    records: dict[str, list[ClassifiedNode]] = defaultdict(list)
    for root in roots:
        for row in root.walk():
            raw = row.node.normalized.finding
            if (
                raw.session_id
                and raw.location.source_type in _NETWORK
                and raw.negotiated is True
                and row.scoreable
            ):
                records[raw.session_id].append(row)
    tls = TLSRegistry()
    sessions = []
    errors = []
    for sid, raw_rows in sorted(grouped.items()):
        rows = sorted(raw_rows, key=lambda raw: (raw.location.frame or 0, raw.id, raw.raw_name))
        conflict = False

        def error(field: str) -> None:
            nonlocal conflict
            conflict = True
            errors.append(
                ScanError(
                    detector="engine.sessions", path=sid, message=f"conflicting or invalid {field} evidence"
                )
            )

        def name(value: str, kind: KindHint) -> str:
            if re.fullmatch(r"0x[0-9a-fA-F]{1,4}", value):
                code = f"0x{int(value, 16):04X}"
                resolved = tls.resolve(kind, code)
                return resolved.iana_name if resolved else code
            if kind == KindHint.CIPHER_SUITE:
                resolved = tls.resolve_name(kind, value)
                if resolved:
                    return resolved.iana_name
            return value

        metadata = [raw.extra["session"] for raw in rows if isinstance(raw.extra.get("session"), dict)]
        for raw in rows:
            if raw.extra.get("session") is not None and not isinstance(raw.extra["session"], dict):
                error("session metadata")

        selected_metadata = [
            raw.extra["session"]
            for raw in rows
            if raw.negotiated is True and isinstance(raw.extra.get("session"), dict)
        ]

        def scalar(field: str, observed: list[str] | None = None) -> str | None:
            values = list(observed or [])
            evidence = (
                selected_metadata
                if field in {"negotiated_group", "negotiated_cipher_suite", "cert_key", "cert_sig_alg"}
                else metadata
            )
            for item in evidence:
                value = item.get(field) if field != "source" else None
                if value is None:
                    continue
                if not isinstance(value, str):
                    error(field)
                    continue
                values.append(value)
            if field in _SCALAR_KINDS:
                values = [name(value, _SCALAR_KINDS[field]) for value in values]
            distinct = sorted(set(values))
            if len(distinct) > 1:
                error(field)
                return None
            return distinct[0] if distinct else None

        source = scalar(
            "source",
            [value for raw in rows if (value := raw.location.file or raw.location.target) is not None],
        )
        flow = scalar("flow", [raw.location.flow for raw in rows if raw.location.flow])
        sni = scalar("sni", [raw.location.sni for raw in rows if raw.location.sni])
        transport_value = scalar(
            "transport", ["ssh" for raw in rows if raw.location.source_type == SourceType.SSH]
        )
        transport: Literal["tls", "ssh"] = "ssh" if transport_value == "ssh" else "tls"
        if transport_value not in {None, "tls", "ssh"}:
            error("transport")
        version_rows = [raw for raw in rows if raw.kind_hint == KindHint.PROTOCOL_VERSION]
        # An observed textual metadata version can accompany an unresolved numeric raw label.
        versions = [raw.raw_name for raw in version_rows if not raw.raw_name.lower().startswith("0x")]
        if not versions and not any(item.get("version") is not None for item in metadata):
            versions = [name(raw.raw_name, KindHint.PROTOCOL_VERSION) for raw in version_rows]
        version = scalar("version", versions or [raw.protocol for raw in rows if raw.protocol])
        service = scalar("service")

        def offered(field: str, kind: KindHint) -> list[str]:
            lists = []
            for item in metadata:
                value = item.get(field)
                if value is None:
                    continue
                if not isinstance(value, list) or any(not isinstance(entry, str) for entry in value):
                    error(field)
                    continue
                lists.append(list(dict.fromkeys(name(entry, kind) for entry in value)))
            distinct = {tuple(value) for value in lists}
            if len(distinct) > 1:
                error(field)
                return []
            if lists:
                return lists[0]
            # Metadata absent: preserve every offered row; no claim of unobserved client list order.
            usage = {
                KindHint.GROUP: Usage.KEY_EXCHANGE,
                KindHint.CIPHER_SUITE: Usage.ENCRYPTION,
                KindHint.SIGNATURE_SCHEME: Usage.SIGNATURE,
            }[kind]
            return list(
                dict.fromkeys(
                    name(raw.raw_name, kind)
                    for raw in rows
                    if raw.negotiated is False
                    and (raw.kind_hint == kind or (transport == "ssh" and raw.usage == usage))
                )
            )

        offered_lists = {field: offered(field, kind) for field, kind in _LIST_KINDS.items()}
        selected = [raw for raw in rows if raw.negotiated is True]
        group = scalar(
            "negotiated_group",
            [
                raw.raw_name
                for raw in selected
                if raw.kind_hint == KindHint.GROUP or (transport == "ssh" and raw.usage == Usage.KEY_EXCHANGE)
            ],
        )
        cipher = scalar(
            "negotiated_cipher_suite",
            [
                raw.raw_name
                for raw in selected
                if raw.kind_hint == KindHint.CIPHER_SUITE
                or (
                    transport == "ssh"
                    and raw.usage == Usage.ENCRYPTION
                    and raw.extra.get("direction") != "server_to_client"
                )
            ],
        )
        cert = scalar(
            "cert_key",
            [
                raw.raw_name
                for raw in selected
                if raw.kind_hint == KindHint.CERTIFICATE
                or (transport == "ssh" and raw.usage in {Usage.AUTHENTICATION, Usage.SIGNATURE})
            ],
        )
        cert_sig = scalar(
            "cert_sig_alg",
            [
                value
                for raw in selected
                if raw.kind_hint == KindHint.CERTIFICATE
                and isinstance(value := raw.extra.get("signature_algorithm"), str)
            ],
        )
        states = {
            raw.extra["certificate_state"]
            for raw in rows
            if isinstance(raw.extra.get("certificate_state"), str)
        }
        if len(states) > 1 or not states <= {"observed", "encrypted", "absent"}:
            error("certificate_state")
        observability = {
            raw.extra["authentication_observable"]
            for raw in rows
            if isinstance(raw.extra.get("authentication_observable"), bool)
        }
        if len(observability) > 1:
            error("authentication_observable")
        for raw in rows:
            if raw.extra.get("authentication_observable") is not None and not isinstance(
                raw.extra["authentication_observable"], bool
            ):
                error("authentication_observable")
            if raw.extra.get("certificate_state") is not None and not isinstance(
                raw.extra["certificate_state"], str
            ):
                error("certificate_state")
        observed = bool(selected and any(raw.kind_hint == KindHint.CERTIFICATE for raw in selected))
        # An observed but undecodable Certificate message has no CERTIFICATE finding and stays
        # unauthenticated (M2 Q2); only a decoded certificate contradicting false is a conflict.
        if observed and observability == {False}:
            error("certificate authentication")
        auth = observed or observability == {True}
        if states & {"encrypted", "absent"}:
            if auth:
                error("certificate authentication")
            auth = False
        if not auth:
            cert = cert_sig = None
        banners = []
        for item in metadata:
            value = item.get("peer_banners")
            if value is not None:
                if isinstance(value, list) and all(isinstance(entry, str) for entry in value):
                    banners.append(value)
                else:
                    error("peer_banners")
        if len({tuple(value) for value in banners}) > 1:
            error("peer_banners")
            banners = []
        mechanisms = records[sid]
        verdict = summarize_verdict(
            mechanisms, require_authentication=True, authentication_observable=auth
        ).tier
        kex = [row for row in mechanisms if row.node.normalized.identity.usage == Usage.KEY_EXCHANGE]
        encryption = [row for row in mechanisms if row.node.normalized.identity.usage == Usage.ENCRYPTION]
        if (not kex or not encryption) and verdict == Tier.SAFE:
            verdict = Tier.UNKNOWN
        pq: Literal["pq_hybrid", "pq_pure", "classical", "unknown"] = "unknown"
        if kex and all(row.tier != Tier.UNKNOWN for row in kex):
            if all(row.node.kind == "hybrid" and row.tier == Tier.SAFE for row in kex):
                pq = "pq_hybrid"
            elif all(row.primitive == "kem" and row.tier == Tier.SAFE for row in kex):
                pq = "pq_pure"
            elif all(row.tier == Tier.CRITICAL for row in kex):
                pq = "classical"
        if conflict:
            if verdict not in {Tier.CRITICAL, Tier.MEDIUM}:
                verdict = Tier.UNKNOWN
            pq = "unknown"
        sessions.append(
            TLSSession(
                session_id=sid,
                flow=flow or "",
                sni=sni,
                version=version,
                **offered_lists,
                negotiated_group=group,
                negotiated_cipher_suite=cipher,
                cert_key=cert,
                cert_sig_alg=cert_sig,
                pq_status=pq,
                verdict_tier=verdict,
                source=source or "",
                transport=transport,
                service=service,
                peer_banners=banners[0] if banners else [],
            )
        )
    return sessions, errors
