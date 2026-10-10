"""Build evidence trees before classification, without inventing owner registries."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Literal, Protocol

from quantumtrace.engine.normalize import (
    Conflict,
    NormalizedFinding,
    ParameterEvidence,
    RegistryResolution,
    RegistryResolver,
    normalize,
)
from quantumtrace.kb.loader import KnowledgeBase, alias_key
from quantumtrace.models import Finding, KindHint, SourceType, Usage


@dataclass(frozen=True)
class ComponentSpec:
    """Internal recipe; optional owner adapters return validated observed recipes."""

    name: str
    usage: Usage
    role: str
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    parameter_set: str | None = None
    underlying_hash: str | None = None
    variant: str | None = None
    kind: KindHint = KindHint.ALGORITHM
    inherit_parameters: bool = False
    source: str = "decomposition"


@dataclass(frozen=True)
class CloudResolution:
    """No policy: an owner-validated mapping conditional on the original Finding."""

    raw_name: str
    source_type: SourceType
    components: tuple[ComponentSpec, ...]
    verified: bool
    source: str


class CloudResolver(Protocol):
    def resolve(self, finding: Finding) -> CloudResolution | None: ...


class NamedTLSResolver(Protocol):
    def resolve_name(self, kind: KindHint, raw_name: str) -> RegistryResolution | None: ...


@dataclass(frozen=True)
class EvidenceNode:
    """Derived containers summarize; hybrid children are trace-only, never scored."""

    node_id: str
    parent_id: str | None
    role: str
    kind: Literal["atom", "container", "hybrid"]
    normalized: NormalizedFinding
    scoreable: bool
    children: tuple[EvidenceNode, ...] = ()
    forward_secrecy: bool | None = None
    notes: tuple[str, ...] = ()

    def walk(self) -> tuple[EvidenceNode, ...]:
        return (self, *(node for child in self.children for node in child.walk()))


@dataclass(frozen=True)
class Decomposition:
    finding: Finding
    root: EvidenceNode | None
    dropped_reason: str | None = None
    issues: tuple[str, ...] = ()
    resource_id: str | None = None
    certificate_arns: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Recipe:
    components: tuple[ComponentSpec, ...]
    forward_secrecy: bool | None = None
    notes: tuple[str, ...] = ()


def _code(value: object) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]{1,4}", value.strip()):
        return None
    return f"0x{int(value.strip(), 16):04X}"


def _drop(finding: Finding) -> str | None:
    if finding.kind_hint not in {
        KindHint.CIPHER_SUITE,
        KindHint.GROUP,
        KindHint.SIGNATURE_SCHEME,
        KindHint.PROTOCOL_VERSION,
    }:
        return None
    raw = _code(finding.raw_name)
    extra = _code(finding.extra.get("codepoint"))
    # Conflicting raw and metadata codes must not discard real crypto evidence.
    if raw and extra and raw != extra:
        return None
    if finding.extra.get("codepoint") is not None and extra is None:
        return None
    # Metadata alone cannot discard a contradictory named crypto observation.
    code = raw
    if code:
        value = int(code, 16)
        if value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF:
            return "TLS GREASE value"
        if finding.kind_hint == KindHint.CIPHER_SUITE and value in {0x00FF, 0x5600}:
            return "TLS signaling cipher suite"
    if finding.kind_hint == KindHint.CIPHER_SUITE and finding.raw_name.strip().upper() in {
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        "TLS_FALLBACK_SCSV",
    }:
        return "TLS signaling cipher suite"
    return None


def _nodes(children: list[EvidenceNode] | tuple[EvidenceNode, ...]) -> tuple[EvidenceNode, ...]:
    unique: dict[str, EvidenceNode] = {}
    for node in sorted(children, key=lambda item: (item.node_id, item.normalized.resolved_name)):
        previous = unique.get(node.node_id)
        if previous:
            provenance = tuple(
                sorted(
                    set((*previous.normalized.provenance, *node.normalized.provenance)),
                    key=lambda item: (item.field, str(item.value), item.source),
                )
            )
            unique[node.node_id] = replace(
                previous,
                normalized=replace(
                    previous.normalized,
                    provenance=provenance,
                    legacy_name=previous.normalized.legacy_name or node.normalized.legacy_name,
                    notes=tuple(sorted(set((*previous.normalized.notes, *node.normalized.notes)))),
                ),
            )
        else:
            unique[node.node_id] = node
    return tuple(unique.values())


def _identifier(finding: Finding, parent: str | None, role: str, normalized: NormalizedFinding) -> str:
    payload = json.dumps(
        [finding.id, parent, role, asdict(normalized.identity)], sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def _atom(finding: Finding, spec: ComponentSpec, kb: KnowledgeBase, parent: str | None) -> EvidenceNode:
    # Project only parameters belonging to this component, then restore the raw
    # Finding reference. Registry metadata belongs to the parent, not the atom.
    scope = (
        spec.inherit_parameters
        or (
            finding.kind_hint == KindHint.KEY
            and spec.role in {"key", "signature", "encryption", "key_exchange", "mac"}
        )
        or (finding.kind_hint == KindHint.CERTIFICATE and spec.role == "certificate_key")
    )
    inherited = {
        field: getattr(finding, field) if scope else None
        for field in ("key_size", "curve", "mode", "padding")
    }
    extra = {key: value for key, value in finding.extra.items() if key not in {"codepoint", "iana_name"}}
    view = finding.model_copy(
        update={
            "raw_name": spec.name,
            "kind_hint": spec.kind,
            "usage": spec.usage,
            "extra": extra,
            **inherited,
        }
    )
    normalized = normalize(view, kb)
    # Normalize recipe spellings separately before comparing observed parameters.
    recipe_view = view.model_copy(update={field: getattr(spec, field) for field in inherited})
    recipe = normalize(recipe_view, kb)
    params = normalized.identity.parameters
    provenance = list(normalized.provenance)
    conflicts = list(normalized.conflicts)
    for field in ("key_size", "curve", "mode", "padding", "parameter_set", "underlying_hash", "variant"):
        provided = getattr(spec, field)
        if provided is None:
            continue
        value = getattr(recipe.identity.parameters, field) if field in inherited else provided
        if field == "underlying_hash":
            value = _hash_name(str(value), kb) or value
        provenance.append(
            ParameterEvidence(field, value if value is not None else str(provided), spec.source)
        )
        prior = getattr(params, field)
        if any(conflict.field == field for conflict in recipe.conflicts):
            conflicts.extend(conflict for conflict in recipe.conflicts if conflict.field == field)
            params = replace(params, **{field: None})
        elif any(conflict.field == field for conflict in conflicts):
            continue
        elif field == "parameter_set" and (
            normalized.identity.algorithm_id is None
            or value not in kb.get(normalized.identity.algorithm_id).parameter_sets
        ):
            conflicts.append(Conflict(field, (str(value),), "undeclared recipe parameter set"))
            params = replace(params, **{field: None})
        elif field == "underlying_hash" and (_hash_name(str(value), kb) is None):
            conflicts.append(Conflict(field, (str(value),), "unknown recipe digest"))
            params = replace(params, **{field: None})
        elif prior is not None and prior != value:
            conflicts.append(Conflict(field, (prior, value), "scanner/name and recipe disagree"))
            params = replace(params, **{field: None})
        else:
            params = replace(params, **{field: value})
    identity = replace(normalized.identity, parameters=params, conflicts=tuple(conflicts))
    normalized = replace(
        normalized,
        finding=finding,
        identity=identity,
        provenance=tuple(provenance),
        conflicts=tuple(conflicts),
    )
    node_id = _identifier(finding, parent, spec.role, normalized)
    return EvidenceNode(node_id, parent, spec.role, "atom", normalized, _eligible(finding, normalized, kb))


def _eligible(finding: Finding, normalized: NormalizedFinding, kb: KnowledgeBase) -> bool:
    if (
        finding.kind_hint in {KindHint.PLAINTEXT, KindHint.LIBRARY, KindHint.PROTOCOL_VERSION}
        or finding.extra.get("hygiene_only") is True
    ):
        return False
    identifier = normalized.identity.algorithm_id
    return identifier is None or not kb.get(identifier).scoring_excluded


def _hash_name(raw: str, kb: KnowledgeBase) -> str | None:
    entry = kb.by_alias("SHA-1" if raw.casefold() == "sha" else raw)
    return entry.id if entry and "hash" in entry.primitive_by_usage.values() else None


def _signature(name: str, kb: KnowledgeBase) -> _Recipe | None:
    key = alias_key(name)
    match = re.fullmatch(
        r"(?P<hash>md5|sha1|sha224|sha256|sha384|sha512|sha512256|sha512224|sha3256|sha3384|sha3512)with(?P<alg>rsa|ecdsa|dsa)(?P<pss>pss|encryption)?",
        key,
    )
    if not match:
        match = re.fullmatch(r"(?P<alg>ecdsa|rsa|dsa)with(?P<hash>sha1|sha256|sha384|sha512)", key)
    if not match:
        match = re.fullmatch(r"rsassa(?P<pss>pss|pkcs1v15)(?P<hash>sha256|sha384|sha512)", key)
        if match:
            algorithm = "RSA"
        else:
            return None
    else:
        algorithm = match["alg"].upper()
        # X.509 sha256WithRSAEncryption-style names (RFC 8017) denote RSA PKCS#1 v1.5 only.
        if match.groupdict().get("pss") == "encryption" and algorithm != "RSA":
            return None
    digest = _hash_name(match["hash"], kb)
    if digest is None:
        return None
    pss = match.groupdict().get("pss")
    padding = "pss" if pss == "pss" else "pkcs1v15" if algorithm == "RSA" else None
    return _Recipe(
        (
            ComponentSpec(algorithm, Usage.SIGNATURE, "signature", padding=padding, inherit_parameters=True),
            ComponentSpec(digest, Usage.SIGNATURE, "signature_hash"),
        )
    )


def _tls_signature(name: str, kb: KnowledgeBase) -> _Recipe | None:
    # Named syntax only; numeric assignments remain the registry owner's domain.
    match = re.fullmatch(r"rsa_(pkcs1|pss_rsae|pss_pss)_(sha1|sha256|sha384|sha512)", name, re.I)
    if match:
        padding = "pkcs1v15" if match[1].lower() == "pkcs1" else "pss"
        return _Recipe(
            (
                ComponentSpec("RSA", Usage.SIGNATURE, "signature", padding=padding, inherit_parameters=True),
                ComponentSpec(_hash_name(match[2], kb) or match[2], Usage.SIGNATURE, "signature_hash"),
            )
        )
    match = re.fullmatch(
        r"ecdsa_(?:(secp256r1|secp384r1|secp521r1)_)?(sha1|sha256|sha384|sha512)", name, re.I
    )
    if match:
        return _Recipe(
            (
                ComponentSpec(
                    "ECDSA",
                    Usage.SIGNATURE,
                    "signature",
                    curve=match[1].lower() if match[1] else None,
                    inherit_parameters=True,
                ),
                ComponentSpec(_hash_name(match[2], kb) or match[2], Usage.SIGNATURE, "signature_hash"),
            )
        )
    return None


def _transform(name: str, kb: KnowledgeBase) -> _Recipe | None:
    match = re.fullmatch(r"\s*([A-Za-z0-9_-]+)\s*/\s*([A-Za-z0-9_-]+)\s*/\s*([^/]+?)\s*", name)
    if not match:
        return None
    algorithm = kb.by_alias(match[1])
    if algorithm is None or algorithm.id not in {"AES", "Camellia", "DES", "3DES", "RSA", "Blowfish", "RC2"}:
        return None
    padding = match[3]
    if not re.fullmatch(
        r"NoPadding|PKCS[157]Padding|OAEPPadding|OAEPWithSHA-?(?:1|224|256|384|512)AndMGF1Padding",
        padding,
        re.I,
    ):
        return None
    components = [
        ComponentSpec(
            algorithm.id,
            Usage.ENCRYPTION,
            "encryption",
            mode=match[2],
            padding=padding,
            inherit_parameters=True,
        )
    ]
    notes: tuple[str, ...] = ()
    oaep = re.fullmatch(r"OAEPWith(SHA-?(?:1|224|256|384|512))AndMGF1Padding", padding, re.I)
    if algorithm.id == "RSA" and oaep:
        components[0] = replace(components[0], padding="oaep", underlying_hash=_hash_name(oaep[1], kb))
        components.append(ComponentSpec(_hash_name(oaep[1], kb) or oaep[1], Usage.KDF, "padding_hash"))
        notes = ("OAEP digest observed; MGF1 digest is not established by this transformation name",)
    if algorithm.id == "RSA":
        notes += ("RSA ECB transformation token is not a block-cipher ECB construction",)
    return _Recipe(tuple(components), notes=notes)


def _cipher(name: str, kb: KnowledgeBase) -> ComponentSpec | None:
    match = re.fullmatch(r"(AES|CAMELLIA)_(128|192|256)_(GCM|CBC|CCM|CCM_8)", name)
    if match:
        return ComponentSpec(
            match[1].title() if match[1] == "CAMELLIA" else "AES",
            Usage.ENCRYPTION,
            "encryption",
            key_size=int(match[2]),
            mode="ccm" if match[3] == "CCM_8" else match[3].lower(),
            variant="ccm-8" if match[3] == "CCM_8" else None,
            inherit_parameters=True,
        )
    if name == "CHACHA20_POLY1305":
        return ComponentSpec("ChaCha20-Poly1305", Usage.ENCRYPTION, "encryption", inherit_parameters=True)
    if name == "3DES_EDE_CBC":
        return ComponentSpec("3DES", Usage.ENCRYPTION, "encryption", mode="cbc", inherit_parameters=True)
    if name == "DES_CBC":
        return ComponentSpec("DES", Usage.ENCRYPTION, "encryption", mode="cbc", inherit_parameters=True)
    if name == "RC4_128":
        return ComponentSpec("RC4", Usage.ENCRYPTION, "encryption", key_size=128, inherit_parameters=True)
    return None


def _tls_suite(name: str, kb: KnowledgeBase) -> _Recipe | None:
    match = re.fullmatch(r"TLS_(?:(.+)_WITH_)?(.+)_(SHA|SHA256|SHA384|SHA512)", name.upper())
    if not match:
        return None
    prefix, cipher_name, digest = match.groups()
    cipher = _cipher(cipher_name, kb)
    if cipher is None:
        return None
    digest = _hash_name(digest, kb) or digest
    aead = cipher.mode in {"gcm", "ccm"} or cipher.name == "ChaCha20-Poly1305"
    if prefix is None:
        if not aead or digest not in {"SHA-256", "SHA-384"}:
            return None
        return _Recipe(
            (cipher, ComponentSpec(f"HKDF-{digest}", Usage.KDF, "kdf")),
            notes=("TLS 1.3 suite does not establish key exchange or certificate authentication",),
        )
    roles = {
        "RSA": ("RSA", "RSA", False),
        "DHE_RSA": ("DH", "RSA", True),
        "DHE_DSS": ("DH", "DSA", True),
        "DH_RSA": ("DH", "RSA", False),
        "DH_DSS": ("DH", "DSA", False),
        "ECDHE_RSA": ("ECDH", "RSA", True),
        "ECDHE_ECDSA": ("ECDH", "ECDSA", True),
        "ECDH_RSA": ("ECDH", "RSA", False),
        "ECDH_ECDSA": ("ECDH", "ECDSA", False),
        "PSK": ("PSK", "PSK", None),
        "DHE_PSK": ("DHE-PSK", "PSK", None),
        "ECDHE_PSK": ("ECDHE-PSK", "PSK", None),
        "RSA_PSK": ("RSA-PSK", "PSK", None),
        "DH_ANON": ("DH", "anonymous-authentication", None),
        "ECDH_ANON": ("ECDH", "anonymous-authentication", None),
    }
    if prefix not in roles:
        return None
    kex, auth, fs = roles[prefix]
    notes = (
        ("PSK/anonymous authentication parameters are not established by the suite",)
        if auth in {"PSK", "anonymous-authentication"}
        else ()
    )
    components = (
        ComponentSpec(kex, Usage.KEY_EXCHANGE, "key_exchange"),
        ComponentSpec(auth, Usage.AUTHENTICATION, "authentication"),
        cipher,
    )
    # AEAD suffix identifies the PRF hash, not a record-layer HMAC.
    tail = (
        ComponentSpec(digest, Usage.KDF, "prf") if aead else ComponentSpec(f"HMAC-{digest}", Usage.MAC, "mac")
    )
    return _Recipe((*components, tail), fs, notes)


def _jose(finding: Finding, name: str) -> _Recipe | None:
    name = name.upper()
    match = re.fullmatch(r"(RS|PS|ES|HS)(256|384|512)", name)
    if match:
        family, size = match.groups()
        digest = f"SHA-{size}"
        if family == "HS":
            return _Recipe((ComponentSpec(f"HMAC-{digest}", Usage.MAC, "mac", inherit_parameters=True),))
        algorithm = "ECDSA" if family == "ES" else "RSA"
        curve = {"256": "secp256r1", "384": "secp384r1", "512": "secp521r1"}[size] if family == "ES" else None
        return _Recipe(
            (
                ComponentSpec(
                    algorithm,
                    Usage.SIGNATURE,
                    "signature",
                    curve=curve,
                    padding="pss" if family == "PS" else "pkcs1v15" if family == "RS" else None,
                    inherit_parameters=True,
                ),
                ComponentSpec(digest, Usage.SIGNATURE, "signature_hash"),
            )
        )
    match = re.fullmatch(r"A(128|192|256)GCM", name)
    if match:
        return _Recipe(
            (
                ComponentSpec(
                    "AES",
                    Usage.ENCRYPTION,
                    "encryption",
                    key_size=int(match[1]),
                    mode="gcm",
                    inherit_parameters=True,
                ),
            )
        )
    if name in {"RSA-OAEP", "RSA-OAEP-256"}:
        return _Recipe(
            (
                ComponentSpec(
                    "RSA",
                    Usage.ENCRYPTION,
                    "encryption",
                    padding="oaep",
                    underlying_hash="SHA-256" if name.endswith("256") else "SHA-1",
                    inherit_parameters=True,
                ),
                ComponentSpec("SHA-256" if name.endswith("256") else "SHA-1", Usage.KDF, "padding_hash"),
            )
        )
    if name == "ECDH-ES":
        return _Recipe((ComponentSpec("ECDH", Usage.KEY_EXCHANGE, "key_exchange", inherit_parameters=True),))
    if name == "EDDSA":
        curve = finding.curve.casefold() if finding.curve else None
        algorithm = {"ed25519": "Ed25519", "ed448": "Ed448"}.get(curve or "", "ambiguous-jose-eddsa")
        return _Recipe(
            (ComponentSpec(algorithm, Usage.SIGNATURE, "signature", inherit_parameters=True),),
            notes=("JOSE EdDSA alone does not distinguish Ed25519 from Ed448",),
        )
    return None


def _ssh(finding: Finding, name: str, kb: KnowledgeBase) -> _Recipe | None:
    entry = kb.by_alias(name)
    # ssh-rsa as KEY is a public-key blob type; it proves no SHA-1 signature.
    if alias_key(name) == "sshrsa" and finding.kind_hint == KindHint.KEY:
        return _Recipe((ComponentSpec("RSA", finding.usage, "key", inherit_parameters=True),))
    if entry and entry.components and entry.family != "Hybrid-KEM":
        return _Recipe(
            tuple(
                ComponentSpec(
                    c.algorithm_id,
                    c.usage,
                    "signature"
                    if c.usage == Usage.SIGNATURE and c.algorithm_id in {"RSA", "DSA", "ECDSA"}
                    else "signature_hash"
                    if c.usage == Usage.SIGNATURE
                    else "key_exchange"
                    if c.usage == Usage.KEY_EXCHANGE
                    else "kex_hash",
                    key_size=c.key_size,
                    curve=c.curve,
                    parameter_set=c.parameter_set,
                    inherit_parameters=c.algorithm_id in {"RSA", "DH"},
                    source=f"kb:{entry.id}",
                )
                for c in entry.components
            )
        )
    match = re.fullmatch(r"ecdh-sha2-nistp(256|384|521)", name, re.I)
    if match:
        size = match[1]
        return _Recipe(
            (
                ComponentSpec(
                    "ECDH", Usage.KEY_EXCHANGE, "key_exchange", curve=f"secp{size}r1", inherit_parameters=True
                ),
                ComponentSpec("SHA-512" if size == "521" else f"SHA-{size}", Usage.HASH, "kex_hash"),
            )
        )
    if name.casefold() in {"curve25519-sha256", "curve25519-sha256@libssh.org"}:
        return _Recipe(
            (
                ComponentSpec("X25519", Usage.KEY_EXCHANGE, "key_exchange", inherit_parameters=True),
                ComponentSpec("SHA-256", Usage.HASH, "kex_hash"),
            )
        )
    return None


def _recipe(finding: Finding, name: str, kb: KnowledgeBase) -> _Recipe | None:
    if finding.kind_hint == KindHint.CIPHER_SUITE or name.upper().startswith("TLS_"):
        return _tls_suite(name, kb)
    if finding.kind_hint == KindHint.SIGNATURE_SCHEME:
        result = _tls_signature(name, kb)
        if result:
            return result
    return _signature(name, kb) or _transform(name, kb) or _jose(finding, name) or _ssh(finding, name, kb)


def _hybrid(node: EvidenceNode, finding: Finding, kb: KnowledgeBase) -> EvidenceNode:
    identifier = node.normalized.identity.algorithm_id
    entry = kb.get(identifier) if identifier else None
    if entry is None or entry.family != "Hybrid-KEM" or not entry.components:
        return node
    children = []
    for component in entry.components:
        spec = ComponentSpec(
            component.algorithm_id,
            Usage.KEY_EXCHANGE,
            "hybrid_component",
            key_size=component.key_size,
            curve=component.curve,
            parameter_set=component.parameter_set,
            source=f"kb:{entry.id}",
        )
        child = _atom(finding, spec, kb, node.node_id)
        children.append(replace(child, scoreable=False))
    if entry.id.endswith(("-sha256", "-sha512")):
        digest = "SHA-256" if entry.id.endswith("sha256") else "SHA-512"
        child = _atom(
            finding,
            ComponentSpec(digest, Usage.HASH, "combiner_hash", source=f"kb:{entry.id}"),
            kb,
            node.node_id,
        )
        children.append(replace(child, scoreable=False))
    return replace(
        node,
        kind="hybrid",
        children=_nodes(children),
        notes=(
            *node.notes,
            "hybrid combiner is atomic; component traces never override its verdict or score",
        ),
    )


def decompose(
    finding: Finding,
    kb: KnowledgeBase,
    *,
    registry: RegistryResolver | None = None,
    named_registry: NamedTLSResolver | None = None,
    cloud_registry: CloudResolver | None = None,
) -> Decomposition:
    """Decompose one observation; callers retain original raw Findings in reports."""
    dropped = _drop(finding)
    arns = finding.extra.get("certificate_arns")
    links = tuple(sorted(set(arn for arn in arns if isinstance(arn, str)))) if isinstance(arns, list) else ()
    if dropped:
        return Decomposition(
            finding, None, dropped, resource_id=finding.location.resource_id, certificate_arns=links
        )
    base = normalize(finding, kb, registry=registry)
    name = base.resolved_name
    issues: list[str] = []
    recipe: _Recipe | None = None
    cloud = finding.location.source_type in {SourceType.KMS, SourceType.LOADBALANCER, SourceType.ACM}
    if cloud and cloud_registry is not None:
        row = cloud_registry.resolve(finding)
        if row is not None:
            if (
                row.verified is not True
                or not row.source.strip()
                or row.raw_name != finding.raw_name
                or row.source_type != finding.location.source_type
                or not row.components
            ):
                issues.append("cloud mapping absent, unverified or inconsistent with observation")
            else:
                recipe = _Recipe(
                    tuple(replace(spec, source=f"cloud:{row.source}") for spec in row.components)
                )
    cloud_recipe = recipe is not None
    if (
        finding.kind_hint == KindHint.CIPHER_SUITE
        and not finding.raw_name.strip().upper().startswith("TLS_")
        and _code(finding.raw_name) is None
    ):
        named_row = (
            named_registry.resolve_name(finding.kind_hint, finding.raw_name) if named_registry else None
        )
        if (
            named_row
            and named_row.verified is True
            and named_row.source.strip()
            and named_row.kind == finding.kind_hint
            and _code(named_row.codepoint)
            and named_row.iana_name.upper().startswith("TLS_")
        ):
            if finding.extra.get("codepoint") is not None and _code(finding.extra["codepoint"]) != _code(
                named_row.codepoint
            ):
                issues.append("OpenSSL registry codepoint conflicts with observed metadata")
            elif finding.extra.get("iana_name") is not None and alias_key(
                str(finding.extra["iana_name"])
            ) != alias_key(named_row.iana_name):
                issues.append("OpenSSL registry IANA name conflicts with observed metadata")
            else:
                name = named_row.iana_name.strip()
                view = finding.model_copy(
                    update={
                        "raw_name": name,
                        "extra": {
                            key: value
                            for key, value in finding.extra.items()
                            if key not in {"codepoint", "iana_name"}
                        },
                    }
                )
                base = replace(normalize(view, kb), finding=finding)
                base = replace(
                    base,
                    provenance=(
                        *base.provenance,
                        ParameterEvidence("name", name, f"registry:{named_row.source}"),
                    ),
                )
        else:
            issues.append("verified OpenSSL name registry unavailable or unverified")
    blocked = base.conflicts or any(
        reason != "unrecognized algorithm name" for reason in base.unknown_reasons
    )
    if blocked or issues:
        normalized = replace(base, unknown_reasons=(*base.unknown_reasons, *issues))
        node = EvidenceNode(
            _identifier(finding, None, "unknown", normalized),
            None,
            "unknown",
            "atom",
            normalized,
            _eligible(finding, normalized, kb),
        )
        return Decomposition(
            finding,
            node,
            issues=tuple(issues),
            resource_id=finding.location.resource_id,
            certificate_arns=links,
        )
    recipe = recipe or _recipe(finding, name, kb)
    if name.upper() == "EDDSA":
        if finding.curve and finding.curve.casefold() in {"ed25519", "ed448"}:
            base = replace(
                normalize(finding.model_copy(update={"raw_name": finding.curve, "extra": {}}), kb),
                finding=finding,
            )
        else:
            base = replace(
                base,
                identity=replace(
                    base.identity,
                    algorithm_id=None,
                    unresolved_name="eddsa",
                    unresolved_namespace=finding.kind_hint,
                ),
                unknown_reasons=("EdDSA variant not observed",),
            )
    # Metadata describes observed certificate key/signature; never borrow subject
    # size/curve for its issuer's signature. Matching resource joins happen later.
    if finding.kind_hint == KindHint.CERTIFICATE and not cloud_recipe:
        key_name = finding.extra.get("key_algorithm", name)
        if not isinstance(key_name, str):
            key_name = "unobserved-certificate-key"
        raw_key = normalize(finding.model_copy(update={"raw_name": name, "extra": {}}), kb)
        metadata_key = normalize(finding.model_copy(update={"raw_name": key_name, "extra": {}}), kb)
        if (
            "key_algorithm" in finding.extra
            and raw_key.identity.algorithm_id is not None
            and (metadata_key.identity != raw_key.identity or metadata_key.conflicts)
        ):
            conflict = Conflict(
                "key_algorithm", (name, key_name), "certificate key metadata conflicts with raw observation"
            )
            normalized = replace(
                base,
                conflicts=(*base.conflicts, conflict),
                identity=replace(base.identity, conflicts=(*base.identity.conflicts, conflict)),
            )
            node = EvidenceNode(
                _identifier(finding, None, "unknown", normalized),
                None,
                "unknown",
                "atom",
                normalized,
                _eligible(finding, normalized, kb),
            )
            return Decomposition(
                finding,
                node,
                issues=(conflict.reason,),
                resource_id=finding.location.resource_id,
                certificate_arns=links,
            )
        key_spec = ComponentSpec(key_name, Usage.AUTHENTICATION, "certificate_key", inherit_parameters=True)
        specs = [key_spec]
        signature_name = finding.extra.get("signature_algorithm")
        if isinstance(signature_name, str):
            sig = _signature(signature_name, kb) or _tls_signature(signature_name, kb)
            if sig:
                specs.extend(replace(spec, inherit_parameters=False) for spec in sig.components)
            else:
                specs.append(ComponentSpec(signature_name, Usage.SIGNATURE, "signature"))
        recipe = _Recipe(tuple(specs))
    if (
        finding.kind_hint == KindHint.KEY
        and not cloud_recipe
        and isinstance(finding.extra.get("signature_algorithm"), str)
    ):
        signature_name = finding.extra["signature_algorithm"]
        signature = _signature(signature_name, kb) or _tls_signature(signature_name, kb)
        key_id = base.identity.algorithm_id
        if signature and key_id:
            primary = signature.components[0]
            sig_id = normalize(
                finding.model_copy(update={"raw_name": primary.name, "extra": {}}), kb
            ).identity.algorithm_id
            if sig_id != key_id:
                conflict = Conflict(
                    "signature_algorithm",
                    (name, signature_name),
                    "key and supplied signature algorithm disagree",
                )
                base = replace(
                    base,
                    conflicts=(*base.conflicts, conflict),
                    identity=replace(base.identity, conflicts=(*base.identity.conflicts, conflict)),
                )
                issues.append(conflict.reason)
                recipe = None
            else:
                primary = replace(
                    primary,
                    key_size=base.identity.parameters.key_size,
                    curve=base.identity.parameters.curve,
                    source="observed:key_name/signature_algorithm",
                )
                recipe = replace(signature, components=(primary, *signature.components[1:]))
        elif key_id:
            recipe = _Recipe(
                (
                    ComponentSpec(name, finding.usage, "key", inherit_parameters=True),
                    ComponentSpec(signature_name, Usage.SIGNATURE, "signature"),
                )
            )
    if recipe and finding.kind_hint not in {KindHint.CIPHER_SUITE, KindHint.POLICY, KindHint.CERTIFICATE}:
        primary_role = next((spec for spec in recipe.components if spec.inherit_parameters), None)
        if primary_role and finding.usage != Usage.UNKNOWN and finding.usage != primary_role.usage:
            conflict = Conflict(
                "usage",
                (finding.usage.value, primary_role.usage.value),
                "observed usage conflicts with encoded composite role",
            )
            base = replace(
                base,
                conflicts=(*base.conflicts, conflict),
                identity=replace(base.identity, conflicts=(*base.identity.conflicts, conflict)),
            )
            issues.append(conflict.reason)
            recipe = None
    root_id = _identifier(finding, None, "observation", base)
    if recipe:
        children = []
        for spec in recipe.components:
            child = _atom(finding, spec, kb, root_id)
            if spec.role == "key_exchange":
                child = replace(child, forward_secrecy=recipe.forward_secrecy)
            if spec.kind == KindHint.CIPHER_SUITE:
                nested = _tls_suite(spec.name, kb)
                if nested:
                    nested_children = tuple(
                        replace(
                            _atom(finding, replace(atom, inherit_parameters=False), kb, child.node_id),
                            forward_secrecy=nested.forward_secrecy if atom.role == "key_exchange" else None,
                        )
                        for atom in nested.components
                    )
                    child = replace(
                        child,
                        kind="container",
                        scoreable=False,
                        children=_nodes(nested_children),
                        forward_secrecy=nested.forward_secrecy,
                        notes=nested.notes,
                    )
            child = _hybrid(child, finding, kb)
            children.append(child)
        root = EvidenceNode(
            root_id,
            None,
            "observation",
            "container",
            base,
            False,
            _nodes(children),
            recipe.forward_secrecy,
            recipe.notes,
        )
    else:
        root = EvidenceNode(
            root_id,
            None,
            "observation",
            "atom",
            base,
            _eligible(finding, base, kb),
        )
        root = _hybrid(root, finding, kb)
        if cloud and (
            finding.kind_hint == KindHint.POLICY or base.identity.algorithm_id == "KMS-SYMMETRIC-DEFAULT"
        ):
            issues.append("verified cloud registry coverage unavailable")
            root = replace(
                root,
                normalized=replace(
                    root.normalized, unknown_reasons=(*root.normalized.unknown_reasons, *issues)
                ),
            )
    return Decomposition(
        finding, root, issues=tuple(issues), resource_id=finding.location.resource_id, certificate_arns=links
    )
