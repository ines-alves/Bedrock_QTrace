"""CycloneDX 1.6 CBOM writer and strict offline validator for a ScanResult."""

from __future__ import annotations

import json
import uuid
from collections import Counter
from typing import Any

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from quantumtrace.engine.registries import TLSRegistry
from quantumtrace.models import CryptoAsset, Finding, KindHint, Location, ScanResult, TLSSession

SPEC_VERSION = "1.6"
_PURL_TYPES = {"python": "pypi", "go": "golang"}
_REF_KEYS = {"ref", "algorithmRef", "signatureAlgorithmRef", "subjectPublicKeyRef"}
_REF_LISTS = {"dependsOn", "algorithms"}
_VALIDATOR = JsonStrictValidator(SchemaVersion.V1_6)


def _properties(**items: object) -> list[dict[str, str]]:
    """Namespaced name/value properties; None values are skipped, booleans are lowercase."""
    return [
        {
            "name": f"quantumtrace:{key}",
            "value": str(value).lower() if isinstance(value, bool) else str(value),
        }
        for key, value in items.items()
        if value is not None
    ]


def _present(**items: Any) -> dict[str, Any]:
    return {key: value for key, value in items.items() if value is not None}


def _occurrences(locations: list[Location], resolved: dict[tuple[str | None, int | None], int]) -> list[dict]:
    """Evidence occurrences; the schema requires a location string, so file, flow or resource id."""
    rows = []
    for loc in locations:
        note = resolved.get((loc.file, loc.line))
        context = [
            part for part in (loc.snippet, None if note is None else f"resolved_from_line={note}") if part
        ]
        rows.append(
            _present(
                location=loc.file or loc.flow or loc.resource_id,
                line=loc.line,
                additionalContext="; ".join(context) or None,
            )
        )
    return rows


def _session(
    asset: CryptoAsset, findings: dict[str, Finding], sessions: dict[str, TLSSession]
) -> TLSSession | None:
    for finding_id in asset.finding_ids:
        session_id = findings[finding_id].session_id
        if session_id is not None:
            return sessions[session_id]
    return None


def _protocol(asset: CryptoAsset, session: TLSSession | None, suite_codes: dict[str, str]) -> dict[str, Any]:
    if session is None:
        return {"type": "tls" if asset.family == "TLS" else "unknown"}
    props = _present(type=session.transport, version=session.version)
    if session.transport == "tls" and session.negotiated_cipher_suite is not None:
        code = suite_codes.get(session.negotiated_cipher_suite)
        suite = _present(
            name=session.negotiated_cipher_suite,
            algorithms=list(asset.components),
            identifiers=None if code is None else [f"0x{code[2:4]}", f"0x{code[4:6]}"],
        )
        props["cipherSuites"] = [suite]
    return props


def _crypto_properties(
    asset: CryptoAsset,
    extra: dict[str, Any],
    session: TLSSession | None,
    suite_codes: dict[str, str],
) -> dict[str, Any]:
    props: dict[str, Any] = {"assetType": asset.asset_type}
    if asset.asset_type == "algorithm":
        size = None if asset.key_size is None else str(asset.key_size)
        props["algorithmProperties"] = _present(
            primitive=asset.primitive,
            mode=asset.mode,
            curve=asset.curve,
            parameterSetIdentifier=asset.parameter_set or size,
            classicalSecurityLevel=asset.classical_security_bits,
            nistQuantumSecurityLevel=asset.nist_quantum_level,
        )
    elif asset.asset_type == "certificate":
        props["certificateProperties"] = _present(
            subjectName=extra.get("domain"),
            notValidBefore=extra.get("not_before"),
            notValidAfter=extra.get("not_after"),
        )
    elif asset.asset_type == "protocol":
        props["protocolProperties"] = _protocol(asset, session, suite_codes)
    return _present(**props, oid=asset.oid)


def _asset_component(
    asset: CryptoAsset,
    findings: dict[str, Finding],
    sessions: dict[str, TLSSession],
    suite_codes: dict[str, str],
) -> dict[str, Any]:
    extra = {key: value for fid in asset.finding_ids for key, value in findings[fid].extra.items()}
    resolved = {
        (findings[fid].location.file, findings[fid].location.line): findings[fid].extra["resolved_from_line"]
        for fid in asset.finding_ids
        if "resolved_from_line" in findings[fid].extra
    }
    session = _session(asset, findings, sessions)
    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.asset_id,
        "name": asset.canonical_name,
        "description": asset.rationale,
        "cryptoProperties": _crypto_properties(asset, extra, session, suite_codes),
        "evidence": {"occurrences": _occurrences(asset.occurrences, resolved)},
        "properties": _properties(
            tier=asset.tier.value,
            threat=asset.threat.value,
            hndlExposed=asset.hndl_exposed,
            classicallyBroken=asset.classically_broken,
            negotiated=asset.negotiated,
            forwardSecrecy=asset.forward_secrecy,
            deprecatedPqcDraft=True if asset.deprecated_pqc_draft else None,
            pqcStandard=asset.pqc_standard,
            testCodeOnly=True if asset.in_test_code_only else None,
            keySize=None if asset.asset_type == "algorithm" else asset.key_size,
            curve=None if asset.asset_type == "algorithm" else asset.curve,
            signatureAlgorithm=extra.get("signature_algorithm"),
        ),
    }


def _key_material(finding: Finding, owner: dict[str, str]) -> dict[str, Any]:
    """One related-crypto-material component per KMS key; never scored, tier lives on the algorithm."""
    extra = finding.extra
    material = _present(
        type="key",
        id=finding.location.resource_id,
        state="active" if extra.get("state") == "Enabled" else None,
        algorithmRef=owner.get(finding.id),
        expirationDate=extra.get("valid_to"),
        size=finding.key_size,
    )
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"material-{finding.id}",
        "name": extra.get("alias") or finding.location.resource_id,
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": material,
        },
        "evidence": {"occurrences": _occurrences([finding.location], {})},
        "properties": _properties(
            keyState=extra.get("state"),
            rotationStatus=extra.get("rotation_status"),
            keyUsage=extra.get("key_usage"),
            origin=extra.get("origin"),
        ),
    }


def _library(finding: Finding) -> dict[str, Any]:
    name, _, version = finding.raw_name.partition("==")
    purl_type = _PURL_TYPES.get(finding.language or "")
    return _present(
        type="library",
        **{"bom-ref": f"library-{finding.id}"},
        name=name,
        version=version or None,
        purl=None if purl_type is None else f"pkg:{purl_type}/{name}" + (f"@{version}" if version else ""),
        evidence={"occurrences": _occurrences([finding.location], {})},
    )


def _is_wrapper(asset: CryptoAsset, findings: dict[str, Finding]) -> bool:
    """An asset made only of hygiene warnings or library declarations: not a cryptographic primitive (M3M4-05)."""
    return all(
        findings[fid].extra.get("hygiene_only") or findings[fid].kind_hint == KindHint.LIBRARY
        for fid in asset.finding_ids
    )


def build_cbom(result: ScanResult) -> dict[str, Any]:
    """Build a CycloneDX 1.6 CBOM dict from a classified ScanResult, deterministically."""
    findings = {finding.id: finding for finding in result.findings}
    sessions = {session.session_id: session for session in result.sessions}
    suite_codes = {row["iana"]: code for code, row in TLSRegistry().data["cipher_suites"].items()}
    owner = {fid: asset.asset_id for asset in result.assets for fid in asset.finding_ids}
    assets = [asset for asset in result.assets if not _is_wrapper(asset, findings)]
    components = [_asset_component(asset, findings, sessions, suite_codes) for asset in assets]
    components += [
        _key_material(finding, owner)
        for finding in result.findings
        if finding.kind_hint == KindHint.KEY and finding.detector == "cloud.kms"
    ]
    components += [_library(finding) for finding in result.findings if finding.kind_hint == KindHint.LIBRARY]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_OID, result.scan_id)}",
        "version": 1,
        "metadata": {
            "timestamp": result.finished_at,
            "tools": {
                "components": [
                    {"type": "application", "name": "QuantumTrace", "version": result.tool_version}
                ]
            },
        },
        "components": components,
        "dependencies": [
            {"ref": asset.asset_id, "dependsOn": list(asset.components)}
            for asset in assets
            if asset.components
        ],
    }


def _collect_refs(node: Any, defined: list[str], used: list[str]) -> None:
    if isinstance(node, list):
        for item in node:
            _collect_refs(item, defined, used)
    elif isinstance(node, dict):
        for key, value in node.items():
            if key == "bom-ref":
                defined.append(value)
            elif key in _REF_KEYS:
                used.append(value)
            elif key in _REF_LISTS:
                used.extend(value)
            else:
                _collect_refs(value, defined, used)


def validate_cbom(cbom: dict[str, Any]) -> list[str]:
    """Strict offline validation: the bundled 1.6 schema plus bom-ref uniqueness and reference checks.

    The schema enforces neither unique bom-ref values nor that references resolve.
    """
    errors = [
        f"{'/'.join(str(part) for part in error.data.absolute_path) or '<root>'}: {error.data.message[:200]}"
        for error in _VALIDATOR.validate_str(json.dumps(cbom), all_errors=True) or []
    ]
    defined: list[str] = []
    used: list[str] = []
    _collect_refs(cbom, defined, used)
    errors += [f"duplicate bom-ref: {ref}" for ref, count in sorted(Counter(defined).items()) if count > 1]
    errors += [f"dangling reference: {ref}" for ref in sorted(set(used) - set(defined))]
    return errors
