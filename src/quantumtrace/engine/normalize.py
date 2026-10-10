"""Normalize evidence without assigning security policy or decomposing composites."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Protocol

from quantumtrace.kb.loader import Algorithm, KnowledgeBase, alias_key
from quantumtrace.models import Finding, KindHint, Usage

AssetType = Literal["algorithm", "certificate", "protocol", "related-crypto-material"]
MatchMethod = Literal["alias", "pattern", "unknown"]
Value = str | int
_TLS_KINDS = frozenset(
    {KindHint.CIPHER_SUITE, KindHint.GROUP, KindHint.SIGNATURE_SCHEME, KindHint.PROTOCOL_VERSION}
)
_MODES = frozenset({"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"})


@dataclass(frozen=True)
class RegistryResolution:
    """Owner-validated row; verify-only rows must set verified=False.

    The adapter, not normalization, validates the owner's file schema and sources.
    This interface carries no security verdict or speculative numeric table.
    """

    kind: KindHint
    codepoint: str
    iana_name: str
    verified: bool
    source: str


class RegistryResolver(Protocol):
    def resolve(self, kind: KindHint, codepoint: str) -> RegistryResolution | None:
        """Resolve one normalized hex value in exactly the requested namespace."""
        ...


@dataclass(frozen=True)
class ParameterEvidence:
    field: str
    value: Value
    source: str


@dataclass(frozen=True)
class Conflict:
    field: str
    values: tuple[Value, ...]
    reason: str


@dataclass(frozen=True)
class Parameters:
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    parameter_set: str | None = None
    underlying_hash: str | None = None
    underlying_cipher: str | None = None
    variant: str | None = None
    output_size: int | None = None


@dataclass(frozen=True)
class CanonicalIdentity:
    algorithm_id: str | None
    usage: Usage
    asset_type: AssetType
    parameters: Parameters
    # Unknown spelling and contradictions must not collapse into known evidence.
    unresolved_name: str | None = None
    unresolved_namespace: KindHint | None = None
    conflicts: tuple[Conflict, ...] = ()


@dataclass(frozen=True)
class NormalizedFinding:
    """Private engine record; Finding remains the original, unmodified evidence.

    All normalized data is frozen. The shared Finding itself is intentionally the
    original model, so downstream callers must treat it as read-only.
    """

    finding: Finding
    identity: CanonicalIdentity
    resolved_name: str
    match_method: MatchMethod
    provenance: tuple[ParameterEvidence, ...]
    conflicts: tuple[Conflict, ...]
    unknown_reasons: tuple[str, ...]
    legacy_name: bool
    notes: tuple[str, ...]

    @property
    def is_resolved(self) -> bool:
        return self.identity.algorithm_id is not None and not self.conflicts and not self.unknown_reasons


def _hex(value: object) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]{1,4}", value.strip()):
        return None
    return f"0x{int(value.strip(), 16):04X}"


def _curve(value: str, kb: KnowledgeBase) -> str:
    key = alias_key(value)
    for entry in kb.algorithms.values():
        for raw, canonical in entry.curve_aliases.items():
            if alias_key(raw) == key:
                return canonical
    # Preserve named curves; no guessed security bits or TLS codepoints.
    return key


def _padding(value: str) -> str:
    key = alias_key(value)
    if re.fullmatch(r"oaepwithsha(?:1|224|256|384|512)andmgf1padding", key):
        return "oaep"
    return {
        "nopadding": "none",
        "pkcs5padding": "pkcs5",
        "pkcs7padding": "pkcs7",
        "pkcs1padding": "pkcs1v15",
        "oaeppadding": "oaep",
    }.get(key, key)


def _lookup(name: str, kb: KnowledgeBase) -> tuple[Algorithm | None, MatchMethod, dict[str, str], bool]:
    key = alias_key(name)
    exact = kb.by_alias(name)
    matches = [
        (kb.get(rule.algorithm_id), m.groupdict())
        for rule in kb.patterns
        if (m := rule.expression.fullmatch(key))
    ]
    if exact:
        # Exact identity takes precedence, but its pattern may supply parameters.
        captures = [groups for entry, groups in matches if entry.id == exact.id]
        groups, ambiguous = _captures(captures)
        return exact, "alias", groups, ambiguous
    identifiers = {entry.id for entry, _ in matches}
    if len(identifiers) == 1:
        entry = matches[0][0]
        groups, ambiguous = _captures([groups for _, groups in matches])
        return entry, "pattern", groups, ambiguous
    return None, "unknown", {}, len(identifiers) > 1


def _captures(matches: list[dict[str, str]]) -> tuple[dict[str, str], bool]:
    groups = [{k: v for k, v in match.items() if v} for match in matches]
    if len({tuple(sorted(match.items())) for match in groups}) > 1:
        return {}, True
    return (groups[0] if groups else {}), False


def normalize(
    finding: Finding, kb: KnowledgeBase, *, registry: RegistryResolver | None = None
) -> NormalizedFinding:
    """Normalize one (previously decomposed) Finding using explicit lookup data.

    Scanner parameters precede name inference. Conflicts leave the effective
    parameter unset and are part of identity, preventing downstream false SAFE
    decisions. Usage, exposure, confidence and raw source evidence are never guessed.
    """
    evidence: list[ParameterEvidence] = []
    conflicts: list[Conflict] = []
    reasons: list[str] = []
    notes: list[str] = []
    inferred: dict[str, Value] = {}
    name = finding.raw_name.strip()
    raw_code = _hex(name)
    extra_code = finding.extra.get("codepoint")
    code = raw_code or _hex(extra_code)
    if extra_code is not None and _hex(extra_code) is None:
        conflicts.append(Conflict("codepoint", (str(extra_code),), "malformed hex codepoint"))
    if raw_code and extra_code is not None and _hex(extra_code) != raw_code:
        conflicts.append(Conflict("codepoint", (raw_code, str(extra_code)), "raw and metadata disagree"))
    numeric = raw_code is not None or name.lower().startswith("0x") or name.isdecimal()
    if code is not None:
        if finding.kind_hint not in _TLS_KINDS:
            reasons.append("codepoint has no supported TLS namespace")
        elif registry is None:
            reasons.append("verified TLS registry unavailable")
        else:
            row = registry.resolve(finding.kind_hint, code)
            if row is None or row.verified is not True or not row.source.strip():
                reasons.append("codepoint absent or unverified in namespace")
            elif row.kind != finding.kind_hint or _hex(row.codepoint) != code or not row.iana_name.strip():
                conflicts.append(
                    Conflict("registry", (code, row.codepoint), "resolver returned mismatched row")
                )
            else:
                name = row.iana_name.strip()
                evidence.append(ParameterEvidence("name", name, f"registry:{row.source}"))
                supplied_name = finding.extra.get("iana_name")
                for label, observed in (
                    ("raw_name", finding.raw_name if not numeric else None),
                    ("iana_name", supplied_name),
                ):
                    if observed is not None:
                        if not isinstance(observed, str) or not _equivalent(observed, name, kb, finding):
                            conflicts.append(
                                Conflict("name", (str(observed), name), f"{label} disagrees with registry")
                            )
    elif numeric:
        reasons.append("numeric name is not a valid namespace-qualified hex codepoint")

    # Unsupported numeric evidence cannot be laundered by an unverified iana_name.
    lookup_name = name if not numeric or (code and name != finding.raw_name.strip()) else ""
    # SSH suffixes express transport/MAC details, not a different AES key size.
    if (
        finding.protocol
        and finding.protocol.casefold() == "ssh"
        or finding.location.source_type.value == "ssh"
    ):
        if re.fullmatch(r"aes(?:128|192|256)-(?:gcm|cbc|ctr)@openssh\.com", lookup_name, re.I):
            lookup_name = lookup_name.split("@")[0]
        if re.fullmatch(r"hmac-sha2-(?:256|512)(?:-etm@openssh\.com)?", lookup_name, re.I):
            lookup_name = re.sub(r"sha2-", "sha", lookup_name, flags=re.I).split("-etm")[0]
    entry, method, captures, ambiguous = _lookup(lookup_name, kb)
    if ambiguous:
        reasons.append("ambiguous KB pattern matches")
    if entry is None:
        reasons.append("unrecognized algorithm name")

    if entry:
        curve_name = _curve(name, kb)
        curve_alias = curve_name in {"secp256r1", "secp384r1", "secp521r1", "secp256k1"}
        if entry.id in {"ECDH", "ECDSA"}:
            if curve_alias:
                inferred["curve"] = curve_name
                entry = kb.get(
                    "ECDSA" if finding.usage in {Usage.SIGNATURE, Usage.AUTHENTICATION} else "ECDH"
                )
            elif alias_key(name) in {"ec", "ecc"}:
                if finding.usage == Usage.KEY_EXCHANGE:
                    entry = kb.get("ECDH")
                elif finding.usage == Usage.UNKNOWN:
                    reasons.append("generic EC name has unknown usage")
            cloud_curve = re.fullmatch(r"ecc(?:nistp|secgp)(256|384|521)(k1)?", alias_key(name))
            if cloud_curve:
                inferred["curve"] = f"secp{cloud_curve[1]}{'k1' if cloud_curve[2] else 'r1'}"
            if alias_key(name).startswith("ecprime") or alias_key(name).startswith("ecsecp"):
                inferred["curve"] = _curve(alias_key(name)[2:], kb)
            if (
                cloud_curve or alias_key(name).startswith(("ecprime", "ecsecp"))
            ) and finding.usage == Usage.KEY_EXCHANGE:
                entry = kb.get("ECDH")
        if captures.get("size") and entry.id != "SLH-DSA":
            field = "output_size" if entry.id in {"BLAKE2", "BLAKE3"} else "key_size"
            inferred[field] = int(captures["size"])
        if captures.get("curve"):
            inferred["curve"] = _curve(captures["curve"], kb)
        if captures.get("mode"):
            inferred["mode"] = captures["mode"].lower()
        param = captures.get("param")
        if param:
            if entry.id in {"HMAC", "HKDF", "PBKDF2"}:
                hash_entry = kb.by_alias(param)
                if hash_entry:
                    inferred["underlying_hash"] = hash_entry.id
                    if entry.id == "HMAC":
                        concrete = kb.by_alias(f"HMAC-{param}")
                        if concrete:
                            entry = concrete
            else:
                inferred["parameter_set"] = entry.param_map.get(param, param)
        if entry.id == "SLH-DSA" and captures.get("size"):
            if param:
                inferred["parameter_set"] = f"{param.upper()}-{captures['size']}{captures['variant']}"
            else:
                reasons.append("SLH-DSA hash family not observed")
        if entry.id in {"Argon2", "BLAKE2"} and alias_key(name) != alias_key(entry.id):
            inferred["variant"] = (
                re.sub(r"\d+$", "", alias_key(name)) if entry.id == "BLAKE2" else alias_key(name)
            )
        if entry.id in {"CMAC", "GMAC"} and "aes" in alias_key(name):
            inferred["underlying_cipher"] = "AES"
        if entry.id.startswith("HMAC-"):
            hash_name = entry.id.removeprefix("HMAC-")
            hash_entry = kb.by_alias(hash_name)
            if hash_entry:
                inferred["underlying_hash"] = hash_entry.id
        # Explicit Java transformation provides mode/padding without provider defaults.
        transform = name.split("/")
        if entry.id == "AES" and len(transform) == 3:
            inferred["mode"] = transform[1].strip().casefold()
            inferred["padding"] = _padding(transform[2])
        if entry.id == "PBKDF2" and "sha256" in alias_key(name):
            inferred["underlying_hash"] = "SHA-256"
        if entry.id == "RSA":
            if finding.padding:
                oaep = re.fullmatch(
                    r"oaepwith(?P<hash>sha(?:1|224|256|384|512))andmgf1padding", alias_key(finding.padding)
                )
                if oaep:
                    digest = kb.by_alias(oaep["hash"])
                    if digest:
                        inferred["underlying_hash"] = digest.id
            for suffix, padding in (("pss", "pss"), ("oaep", "oaep"), ("pkcs1v15", "pkcs1v15")):
                if alias_key(name).endswith(suffix):
                    inferred["padding"] = padding
        if entry.id == "3DES" and alias_key(name) == "3descbc":
            inferred["mode"] = "cbc"

    if entry:
        primitives = set(entry.primitive_by_usage.values())
        allowed = {
            KindHint.GROUP: {"key-agree", "kem", "combiner"},
            KindHint.SIGNATURE_SCHEME: {"signature"},
        }.get(finding.kind_hint)
        if allowed is not None and not primitives.intersection(allowed):
            conflicts.append(
                Conflict(
                    "kind_hint",
                    (finding.kind_hint.value, entry.id),
                    "kind conflicts with algorithm primitive",
                )
            )
        if (
            entry.id == "ECDH"
            and finding.usage in {Usage.SIGNATURE, Usage.AUTHENTICATION}
            or entry.id == "ECDSA"
            and finding.usage == Usage.KEY_EXCHANGE
        ):
            conflicts.append(
                Conflict("usage", (finding.usage.value, entry.id), "usage conflicts with explicit algorithm")
            )

    effective: dict[str, Value | None] = {}
    for field in Parameters.__dataclass_fields__:
        raw = getattr(finding, field, None)
        scanner: Value | None = raw
        if raw is not None:
            if field == "curve":
                scanner = _curve(raw, kb)
            elif field == "mode":
                scanner = raw.strip().casefold()
            elif field == "padding":
                scanner = _padding(raw)
            source = "scanner"
            if field in {"key_size", "mode"}:
                detail = finding.extra.get(f"{field}_source")
                if isinstance(detail, str):
                    source += f":{detail}"
            assert scanner is not None
            evidence.append(ParameterEvidence(field, scanner, source))
        named = inferred.get(field)
        if named is not None:
            evidence.append(ParameterEvidence(field, named, "name"))
        value = scanner if scanner is not None else named
        if scanner is not None and named is not None and scanner != named:
            conflicts.append(Conflict(field, (scanner, named), "scanner and name disagree"))
            value = None
        if field == "key_size" and value is not None and (type(value) is not int or value <= 0):
            conflicts.append(Conflict(field, (value,), "key size must be positive bits"))
            value = None
        if field == "mode" and value is not None and value not in _MODES:
            conflicts.append(Conflict(field, (value,), "mode outside canonical schema"))
            value = None
        if field == "parameter_set" and value is not None and entry and value not in entry.parameter_sets:
            conflicts.append(Conflict(field, (value,), "undeclared parameter set"))
            value = None
        marker = finding.extra.get(f"{field}_source")
        if (
            scanner is not None
            and isinstance(marker, str)
            and (
                field == "key_size"
                and marker in {"ambiguous", "unresolved"}
                or field == "mode"
                and marker in {"jca_default", "provider_assumed"}
            )
        ):
            conflicts.append(Conflict(field, (scanner,), "scanner provenance does not establish parameter"))
            value = None
        effective[field] = value

    legacy = bool(
        entry
        and (
            entry.deprecated_pqc_draft
            or any(
                alias_key(observed).startswith(alias_key(a))
                for observed in (finding.raw_name, name)
                for a in entry.deprecated_aliases
            )
        )
    )
    if legacy:
        notes.append("legacy/pre-standard spelling is not evidence of final-standard compliance")
    if entry:
        notes.extend(
            note
            for alias, note in entry.note_if_alias.items()
            if any(alias_key(observed).startswith(alias_key(alias)) for observed in (finding.raw_name, name))
        )
    params = Parameters(**effective)  # type: ignore[arg-type]
    conflict_tuple = tuple(conflicts)
    asset_type: AssetType = "algorithm"
    if finding.kind_hint == KindHint.CERTIFICATE:
        asset_type = "certificate"
    elif finding.kind_hint in {
        KindHint.CIPHER_SUITE,
        KindHint.PROTOCOL_VERSION,
        KindHint.POLICY,
        KindHint.PLAINTEXT,
    }:
        asset_type = "protocol"
    identity = CanonicalIdentity(
        entry.id if entry else None,
        finding.usage,
        asset_type,
        params,
        (raw_code or alias_key(finding.raw_name)) if entry is None or conflicts or reasons else None,
        finding.kind_hint if entry is None or conflicts or reasons else None,
        conflict_tuple,
    )
    return NormalizedFinding(
        finding, identity, name, method, tuple(evidence), conflict_tuple, tuple(reasons), legacy, tuple(notes)
    )


def _equivalent(left: str, right: str, kb: KnowledgeBase, finding: Finding) -> bool:
    if alias_key(left) == alias_key(right):
        return True
    # Compare complete normalized identities, so distinct curves/modes/parameter
    # sets cannot agree merely because they share a family. No registry recursion.
    a = normalize(finding.model_copy(update={"raw_name": left, "extra": {}}), kb)
    b = normalize(finding.model_copy(update={"raw_name": right, "extra": {}}), kb)
    return a.is_resolved and b.is_resolved and a.identity == b.identity
