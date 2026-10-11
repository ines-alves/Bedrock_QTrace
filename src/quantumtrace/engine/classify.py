"""Central KB policy interpretation; no aggregation, scoring, clock or scanner mutations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable, cast

from quantumtrace.engine.decompose import EvidenceNode
from quantumtrace.engine.normalize import Parameters
from quantumtrace.kb.loader import Algorithm, KnowledgeBase, Mode, Replacement, alias_key
from quantumtrace.models import CryptoAsset, KindHint, Recommendation, SourceType, Threat, Tier, Usage

_PRECEDENCE = {Tier.SAFE: 0, Tier.UNKNOWN: 1, Tier.MEDIUM: 2, Tier.CRITICAL: 3}
_TRANSIT = frozenset({SourceType.PCAP, SourceType.LIVE, SourceType.SSH, SourceType.LOADBALANCER})


@dataclass(frozen=True)
class Advice:
    action: str
    target_algorithm: str | None = None
    standard: str | None = None
    priority: int = 2

    def to_recommendation(self) -> Recommendation:
        return Recommendation(**vars(self))


@dataclass(frozen=True)
class VerdictSummary:
    tier: Tier
    hndl_exposed: bool
    rationale: str


def summarize_verdict(
    components: Iterable[ClassifiedNode],
    *,
    require_authentication: bool = False,
    authentication_observable: bool | None = None,
) -> VerdictSummary:
    """Combine already-classified mechanisms; never pass hybrid trace halves as mechanisms.

    Session assembly supplies observability explicitly. A missing authentication
    mechanism remains UNKNOWN even when observability was asserted True.
    """
    rows = tuple(components)
    tiers = [row.tier for row in rows]
    notes = ["Composite precedence: CRITICAL > MEDIUM > UNKNOWN > SAFE."]
    if require_authentication and (
        authentication_observable is not True
        or not any(
            row.node.normalized.identity.usage in {Usage.AUTHENTICATION, Usage.SIGNATURE} for row in rows
        )
    ):
        tiers.append(Tier.UNKNOWN)
        notes.append("Authentication is UNKNOWN; no certificate key is inferred.")
    tier = max(tiers or [Tier.UNKNOWN], key=_PRECEDENCE.__getitem__)
    protected = any(row.node.kind == "hybrid" and row.tier == Tier.SAFE for row in rows)
    if protected:
        notes.append("Confidentiality PQ-protected by the atomic hybrid; authentication is separate.")
    return VerdictSummary(tier, any(row.hndl_exposed for row in rows), " ".join(notes))


@dataclass(frozen=True)
class ClassifiedNode:
    """Private policy record retaining all evidence for later aggregation/scoring."""

    node: EvidenceNode
    tier: Tier
    threat: Threat
    family: str
    primitive: str
    rationale: str
    recommendations: tuple[Advice, ...]
    confidence: float
    exclusions: tuple[str, ...]
    classically_broken: bool = False
    hndl_exposed: bool = False
    forward_secrecy: bool | None = None
    deprecated_pqc_draft: bool = False
    oid: str | None = None
    classical_security_bits: int | None = None
    nist_quantum_level: int | None = None
    pqc_standard: str | None = None
    children: tuple[ClassifiedNode, ...] = ()
    maintenance: tuple[Advice, ...] = ()

    @property
    def scoreable(self) -> bool:
        return self.node.scoreable and not self.exclusions

    def walk(self) -> tuple[ClassifiedNode, ...]:
        return (self, *(row for child in self.children for row in child.walk()))

    def to_asset(self) -> CryptoAsset:
        """Return an independent public payload; exclusions/evidence stay in this record."""
        normalized = self.node.normalized
        identity = normalized.identity
        params = identity.parameters
        finding = normalized.finding
        asset_type = identity.asset_type
        if self.node.kind == "container" and asset_type != "certificate":
            asset_type = "protocol"
        return CryptoAsset(
            asset_id=self.node.node_id,
            canonical_name=identity.algorithm_id or normalized.resolved_name,
            family=self.family,
            asset_type=asset_type,
            primitive=self.primitive,
            usage=identity.usage,
            key_size=params.key_size,
            curve=params.curve,
            mode=params.mode,
            parameter_set=params.parameter_set,
            oid=self.oid,
            tier=self.tier,
            threat=self.threat,
            classically_broken=self.classically_broken,
            hndl_exposed=self.hndl_exposed,
            forward_secrecy=self.forward_secrecy,
            deprecated_pqc_draft=self.deprecated_pqc_draft,
            classical_security_bits=self.classical_security_bits,
            nist_quantum_level=self.nist_quantum_level,
            pqc_standard=self.pqc_standard,
            rationale=self.rationale,
            recommendations=[advice.to_recommendation() for advice in self.recommendations],
            occurrences=[finding.location.model_copy(deep=True)],
            finding_ids=[finding.id],
            component_of=[self.node.parent_id] if self.node.parent_id else [],
            components=[child.node.node_id for child in self.children],
            negotiated=finding.negotiated,
            in_test_code_only=finding.in_test_code,
        )


def _tier(entry: Algorithm, params: Parameters, usage: Usage, kb: KnowledgeBase) -> tuple[Tier, Threat]:
    tier = entry.tier or entry.tier_by_key_size.get(str(params.key_size), entry.tier_by_key_size["unknown"])
    threat = entry.threat
    if entry.key_sizes and params.key_size is not None and params.key_size not in entry.key_sizes:
        return Tier.UNKNOWN, Threat.UNKNOWN
    if entry.id == "AES" and params.key_size == 192:
        tier = Tier(kb.scoring.aes_192_tier)
    if params.output_size is not None and entry.primitive_by_usage.get("default") in {"mac", "kdf"}:
        # The KB has no verified tag/KDF-output policy; explicit shortening must not inherit SAFE.
        return Tier.UNKNOWN, Threat.UNKNOWN
    if entry.follow_underlying_hash and params.underlying_hash:
        digest = kb.by_alias(params.underlying_hash)
        if digest is None or digest.primitive_by_usage.get("default") not in {"hash", "xof"}:
            return Tier.UNKNOWN, Threat.UNKNOWN
        return digest.tier or Tier.UNKNOWN, digest.threat
    if entry.follow_underlying_hash and params.underlying_cipher:
        cipher = kb.by_alias(params.underlying_cipher)
        if cipher is None or cipher.primitive_by_usage.get("default") not in {
            "block-cipher",
            "stream-cipher",
        }:
            return Tier.UNKNOWN, Threat.UNKNOWN
        return _tier(cipher, params, Usage.ENCRYPTION, kb)
    if entry.id in {"CMAC", "GMAC"}:
        cipher = kb.by_alias(params.underlying_cipher or "")
        if cipher is None or cipher.primitive_by_usage.get("default") != "block-cipher":
            return Tier.UNKNOWN, Threat.UNKNOWN
        return _tier(cipher, params, Usage.ENCRYPTION, kb)
    # SHA-1/MD5 collision policy must not leak into keyed MAC/KDF usage.
    if usage == Usage.MAC and entry.primitive_by_usage.get("default") in {"hash", "xof"}:
        mac = kb.by_alias("HMAC-" + entry.id)
        if mac is not None:
            return mac.tier or Tier.UNKNOWN, mac.threat
    # Observed truncation has no verified per-output policy in the packaged KB.
    if params.output_size is not None and entry.primitive_by_usage.get("default") in {"hash", "xof"}:
        nominal = {
            "SHA-224": 224,
            "SHA-256": 256,
            "SHA-384": 384,
            "SHA-512": 512,
            "SHA-512/224": 224,
            "SHA-512/256": 256,
            "SHA3-224": 224,
            "SHA3-256": 256,
            "SHA3-384": 384,
            "SHA3-512": 512,
        }.get(entry.id)
        if nominal is None or params.output_size != nominal:
            return Tier.UNKNOWN, Threat.UNKNOWN
    return tier, threat


def _replacement(ref: Replacement) -> str:
    target = ref.algorithm_id
    if ref.parameter_set:
        target += "-" + ref.parameter_set
    if ref.key_size:
        target += "-" + str(ref.key_size)
    if ref.mode:
        target += "-" + ref.mode.upper()
    return target


# Validity extending into 2031 or later (agreed with M2), not merely a date during 2030.
BEYOND_2030 = datetime(2031, 1, 1, tzinfo=UTC)


def _component_label(child: ClassifiedNode) -> str:
    # A nested container (e.g. a policy's cipher suite) has no single algorithm; name it instead.
    identity = child.node.normalized.identity.algorithm_id
    if identity is None and child.node.kind == "container":
        return child.to_asset().canonical_name
    return identity or "unresolved"


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.utcoffset() is not None else None
    except ValueError:
        return None


def _hygiene(node: EvidenceNode, scan_started_at: datetime | None) -> tuple[list[str], list[Advice]]:
    finding = node.normalized.finding
    extra = finding.extra
    notes: list[str] = []
    advice: list[Advice] = []
    flags = extra.get("hygiene_flags")
    observed_flags = {flag for flag in flags if isinstance(flag, str)} if isinstance(flags, list) else set()

    def warn(text: str, action: str) -> None:
        notes.append(text)
        advice.append(Advice(action, priority=1))

    if extra.get("rotation_status") is False or "rotation_disabled" in observed_flags:
        warn("Observed KMS rotation is disabled (hygiene).", "Review key rotation policy.")
    if str(extra.get("state", "")).casefold() == "pendingdeletion":
        warn("Key is pending deletion (hygiene).", "Confirm dependencies before key deletion.")
    origin = str(extra.get("origin", "")).upper()
    if origin == "EXTERNAL":
        warn("Key material has external origin (hygiene).", "Review imported key-material lifecycle.")
    if origin == "AWS_CLOUDHSM":
        notes.append("HSM backing is impact context; quantum tier is unchanged.")
    if extra.get("multi_region") is True or "multi_region_key" in observed_flags:
        notes.append("Multi-region key is impact context; quantum tier is unchanged.")
    if origin == "IMPORTED" or str(extra.get("type", "")).upper() == "IMPORTED":
        warn("Certificate was imported (hygiene).", "Review imported certificate renewal ownership.")
    expiry = _timestamp(extra.get("not_after"))
    reference = _timestamp(extra.get("source_timestamp")) or scan_started_at
    if extra.get("not_after") is not None and expiry is None:
        notes.append("Certificate expiry is not a valid timezone-aware timestamp; expiry advice unresolved.")
    if expiry is not None:
        if reference is None:
            notes.append("Expiry advice requires source timestamp or explicit scan start.")
        elif expiry <= reference:
            status = str(extra.get("cert_status", extra.get("state", ""))).upper()
            if status == "ISSUED" and bool(extra.get("in_use_by")):
                warn(
                    "Certificate is expired, ISSUED and still in use (hygiene).",
                    "Renew the expired in-use certificate.",
                )
        elif expiry - reference < timedelta(days=90):
            warn("Certificate expires within 90 days (hygiene).", "Plan certificate renewal within 90 days.")
    if extra.get("hand_rolled") is True:
        notes.append("Hand-rolled implementation: quantum policy is not an implementation audit.")
        advice.append(
            Advice(
                "Review the hand-rolled implementation and prefer a maintained cryptographic library.",
                priority=2,
            )
        )
    if "tls_verify_disabled" in observed_flags:
        warn(
            "Observed TLS certificate verification is disabled (hygiene); quantum tier unchanged.",
            "Enable TLS certificate and hostname verification.",
        )
    if "private_key_material" in observed_flags:
        warn(
            "Private key material is stored in the scanned files (hygiene); quantum tier unchanged.",
            "Remove the private key from the repository or image, rotate it and keep it in a secret store.",
        )
    if "hardcoded_key" in observed_flags:
        warn("Observed hard-coded key material (hygiene).", "Remove and rotate hard-coded key material.")
    iterations = extra.get("iterations")
    if node.normalized.identity.algorithm_id == "PBKDF2" and type(iterations) is int and iterations < 100000:
        warn(
            "Observed PBKDF2 iterations are below the repository hygiene threshold; quantum tier unchanged.",
            "Review PBKDF2 work factor for the deployment.",
        )
    handled = {"rotation_disabled", "multi_region_key", "tls_verify_disabled", "private_key_material"}
    for flag in sorted(observed_flags - handled):
        notes.append(f"Observed hygiene context: {flag}.")
    return notes, advice


def classify(
    node: EvidenceNode, kb: KnowledgeBase, *, scan_started_at: datetime | None = None
) -> ClassifiedNode:
    """Classify one evidence tree. Reference time is explicit and timezone-aware."""
    if scan_started_at is not None and scan_started_at.utcoffset() is None:
        raise ValueError("scan_started_at must be timezone-aware")
    children = tuple(classify(child, kb, scan_started_at=scan_started_at) for child in node.children)
    normalized = node.normalized
    identity = normalized.identity
    params = identity.parameters
    finding = normalized.finding
    entry = kb.algorithms.get(identity.algorithm_id or "")
    notes = [*normalized.notes, *node.notes]
    advice: list[Advice] = []
    exclusions: list[str] = []
    maintenance: list[Advice] = []
    confidence = finding.confidence
    tier, threat = Tier.UNKNOWN, Threat.UNKNOWN
    family, primitive = "Unknown", "unknown"
    broken, hndl = False, False
    oid = standard = None
    bits = level = None
    fs = node.forward_secrecy
    legacy = normalized.legacy_name or bool(entry and entry.deprecated_pqc_draft)
    if not node.scoreable:
        exclusions.append("container" if node.kind == "container" else "trace-or-noncrypto")
    noncrypto = (
        finding.extra.get("hygiene_only") is True
        or finding.kind_hint in {KindHint.PLAINTEXT, KindHint.LIBRARY, KindHint.PROTOCOL_VERSION}
        or bool(entry and entry.scoring_excluded)
    )
    if noncrypto:
        tier, threat = Tier.UNKNOWN, Threat.NONE
        exclusions.append("hygiene-or-noncrypto")
        notes.append("Visible hygiene/noncrypto observation; excluded from quantum scoring and readiness.")
        if finding.kind_hint == KindHint.PLAINTEXT:
            notes.append(
                "Plaintext has no cryptographic confidentiality; this is separate from quantum migration."
            )
            advice.append(
                Advice("Enable encrypted transport; review redirect and forwarding behavior.", priority=1)
            )
        elif finding.kind_hint == KindHint.PROTOCOL_VERSION and alias_key(normalized.resolved_name) in {
            "tls1.0",
            "tls1.1",
            "tlsv1",
            "tlsv1.0",
            "tlsv1.1",
            "sslv3",
            "ssl3.0",
            # SSL 2.0 is prohibited by RFC 6176.
            "sslv2",
            "ssl2.0",
        }:
            broken = True
            notes.append("Observed obsolete protocol version is a classical hygiene weakness.")
            advice.append(
                Advice("Migrate obsolete transport to TLS 1.3 with verified hybrid key exchange.", priority=1)
            )
        elif entry and entry.id == "INSECURE-RNG":
            broken = True
            advice.append(Advice("Use an operating-system cryptographic random generator.", priority=1))
        maintenance.extend(advice)
    elif node.kind == "container":
        # Only a suite that encodes key exchange/authentication (TLS <= 1.2) answers for it; a
        # TLS 1.3 suite takes its components' tier and the session verdict keeps authentication.
        negotiates = any(
            child.node.normalized.identity.usage in {Usage.KEY_EXCHANGE, Usage.AUTHENTICATION}
            for child in children
        )
        summary = summarize_verdict(
            children,
            require_authentication=finding.kind_hint == KindHint.CIPHER_SUITE and negotiates,
            authentication_observable=finding.extra.get("authentication_observable") is True,
        )
        tier = summary.tier
        threat = next((child.threat for child in children if child.tier == tier), Threat.UNKNOWN)
        family, primitive = "Composite", "other"
        notes.append(summary.rationale)
        notes.append(
            "Components: "
            + "; ".join(
                f"{child.node.role}={_component_label(child)} "
                f"({child.tier.value}{', classical weakness' if child.classically_broken else ''})"
                for child in children
            )
            + "."
        )
        broken = any(child.classically_broken for child in children)
        hndl = summary.hndl_exposed
        advice.extend(item for child in children for item in child.recommendations)
    elif entry is None:
        notes.append("No verified KB identity; UNKNOWN without invented cryptographic facts.")
        advice.append(
            Advice("Identify the algorithm and parameters from authoritative evidence.", priority=2)
        )
    else:
        family = entry.family
        primitive = entry.primitive_by_usage.get(
            identity.usage, entry.primitive_by_usage.get("default", "unknown")
        )
        primitive = (
            entry.primitive_by_mode.get(cast(Mode, params.mode), primitive) if params.mode else primitive
        )
        if identity.usage == Usage.MAC and primitive in {"hash", "xof"}:
            primitive = "mac"
        elif identity.usage == Usage.KDF and primitive in {"hash", "xof"}:
            primitive = "kdf"
        tier, threat = _tier(entry, params, identity.usage, kb)
        notes.append(entry.note)
        if normalized.conflicts or normalized.unknown_reasons:
            # Identity-secure critical algorithms remain critical despite size/mode uncertainty.
            # Usage/registry identity conflicts cannot establish even that identity.
            uncertain_identity = any(
                c.field in {"usage", "algorithm", "codepoint", "iana_name", "registry", "name", "kind_hint"}
                for c in normalized.conflicts
            )
            if tier != Tier.CRITICAL or uncertain_identity or normalized.unknown_reasons:
                tier, threat = Tier.UNKNOWN, Threat.UNKNOWN
            notes.extend(c.reason for c in normalized.conflicts)
            notes.extend(normalized.unknown_reasons)
            advice.append(
                Advice(
                    "Resolve conflicting or incomplete parameter evidence before approving deployment.",
                    priority=1,
                )
            )
        else:
            broken = entry.classically_broken
            condition = entry.classically_broken_if
            if condition:
                broken |= (
                    condition.key_size_lt is not None
                    and params.key_size is not None
                    and params.key_size < condition.key_size_lt
                ) or identity.usage in condition.usages
            if entry.id in {"CMAC", "GMAC"} and params.underlying_cipher:
                cipher = kb.by_alias(params.underlying_cipher)
                broken |= bool(cipher and cipher.classically_broken)
            oid = entry.oid
            if params.parameter_set:
                oid = entry.oids.get(params.parameter_set, oid)
                level = entry.nist_quantum_level_by_param.get(params.parameter_set)
            if entry.id == "AES" and params.key_size is not None and params.mode == "gcm":
                oid = entry.oids.get(f"AES-{params.key_size}-GCM")
            bits = entry.classical_security_bits
            level = level or entry.nist_quantum_level
            standard = entry.pqc_standard if entry.standards_status == "final" else None
            if level is not None:
                notes.append(
                    "Verified parameter-set NIST category is conditional on a conforming implementation; no audit is implied."
                )
            if tier == Tier.UNKNOWN:
                oid = standard = None
                bits = level = None
            if legacy:
                oid = standard = None
                level = None
                notes.append(
                    "Legacy/draft name does not establish final-standard conformance; final facts withheld."
                )
            if fs is None and identity.usage == Usage.KEY_EXCHANGE:
                fs = entry.forward_secrecy
        if entry.id == "AES" and params.key_size is None and not normalized.conflicts:
            confidence = min(confidence, 0.5)
            notes.append("AES key size not determinable; conservative MEDIUM policy, no inferred size.")
        if entry.id == "AES" and params.mode == "ecb":
            notes.append("Observed ECB mode exposes block patterns (hygiene); quantum tier follows key size.")
            advice.append(
                Advice(
                    "Replace observed ECB with authenticated encryption.", "AES-256-GCM", "NIST SP 800-38D", 1
                )
            )
            maintenance.append(advice[-1])
        if identity.usage in {Usage.SIGNATURE, Usage.AUTHENTICATION}:
            notes.append(
                "Signatures/authentication are not HNDL exposure for previously recorded confidentiality."
            )
        hndl = (
            tier == Tier.CRITICAL
            and threat == Threat.SHOR
            and identity.usage == Usage.KEY_EXCHANGE
            and finding.location.source_type in _TRANSIT
        )
        if hndl:
            notes.append(
                "Shor-vulnerable in-transit key exchange permits harvest-now-decrypt-later exposure."
            )
            if fs is False and entry.id == "RSA":
                notes.append(
                    "Static RSA transport has no forward secrecy: a future server-key break decrypts recorded sessions."
                )
        if node.kind == "hybrid":
            notes.append(
                "Atomic hybrid combiner: trace halves do not override its tier or contribute quantum scores."
            )
        if tier in {Tier.CRITICAL, Tier.MEDIUM} or legacy:
            ref = entry.replacement.get(identity.usage, entry.replacement.get("default"))
            if ref:
                target = _replacement(ref)
                if identity.usage == Usage.MAC and entry.primitive_by_usage.get("default") in {"hash", "xof"}:
                    target = "HMAC-" + target
                # Unobserved use is not a use to name; the text stays a roadmap grouping key.
                usage_text = "" if identity.usage == Usage.UNKNOWN else f"{identity.usage.value} "
                action = f"Migrate {usage_text}to {target}."
                advice_standard = ref.standard
                if ref.algorithm_id == "ML-KEM" and identity.usage == Usage.ENCRYPTION:
                    action = f"Use {target} for key establishment with authenticated data encryption; a KEM is not bulk encryption."
                if identity.usage in {Usage.SIGNATURE, Usage.AUTHENTICATION} and entry.primitive_by_usage.get(
                    "default"
                ) in {"hash", "xof"}:
                    # A hash replaces the digest inside a signature scheme, not the signature itself.
                    action = f"Use {target} as the signature hash."
                    if finding.raw_name.lower() == "ssh-rsa":
                        # RFC 8332 (sourced on the KB ssh-rsa entry) keeps the RSA key; ML-DSA stays separate.
                        action = "Replace ssh-rsa signatures with rsa-sha2-512 or rsa-sha2-256; the RSA key is reused."
                        target, advice_standard = "rsa-sha2-512", "IETF RFC 8332"
                advice.append(Advice(action, target, advice_standard, 1 if tier == Tier.CRITICAL else 2))
            elif identity.usage == Usage.UNKNOWN and tier == Tier.CRITICAL and entry.replacement:
                # A key whose use is not observed (a key file, an RSA/EC generation) still needs a path: name
                # each per-use replacement the KB states, without guessing which use applies.
                paths = {
                    usage.value if isinstance(usage, Usage) else str(usage): _replacement(ref)
                    for usage, ref in entry.replacement.items()
                }
                signature = paths.get("signature") or paths.get("authentication")
                exchange = paths.get("key_exchange") or paths.get("encryption")
                if signature and exchange:
                    advice.append(
                        Advice(
                            f"Identify the key's use, then migrate signatures to {signature} "
                            f"and key establishment to {exchange}.",
                            priority=1,
                        )
                    )
            elif identity.usage == Usage.MAC:
                # HMAC is specified by FIPS 198-1 (sourced on the KB HMAC-SHA384 entry).
                advice.append(
                    Advice(
                        "Use a maintained HMAC-SHA384 implementation.",
                        "HMAC-SHA384",
                        "NIST FIPS 198-1",
                        priority=2,
                    )
                )
        if (
            entry.id == "SHA-1"
            and identity.usage == Usage.SIGNATURE
            and finding.kind_hint == KindHint.CERTIFICATE
        ):
            notes.append("Observed SHA-1 certificate signature requires renewal (hygiene).")
            advice.append(Advice("Renew the certificate with a maintained signature scheme.", priority=1))
        if tier == Tier.UNKNOWN:
            notes.append("Required underlying algorithm, parameters or policy are unresolved.")
            advice.append(
                Advice("Verify the missing algorithm parameters and implementation provenance.", priority=2)
            )
    validity = _timestamp(finding.extra.get("not_after"))
    if (
        finding.kind_hint == KindHint.CERTIFICATE
        and tier in {Tier.CRITICAL, Tier.MEDIUM}
        and validity is not None
        and validity >= BEYOND_2030
    ):
        # Migration context from the absolute validity end; independent of the scan reference time.
        notes.append("Certificate validity extends beyond 2030 with quantum-vulnerable cryptography.")
        advice.append(
            Advice("Reissue the certificate with a quantum-safe signature scheme before 2031.", priority=2)
        )
    hygiene_notes, hygiene_advice = _hygiene(node, scan_started_at)
    notes.extend(hygiene_notes)
    advice.extend(hygiene_advice)
    maintenance.extend(hygiene_advice)
    if node.kind == "container":
        maintenance.extend(item for child in children for item in child.maintenance)
    unique_advice = tuple(
        sorted(set(advice), key=lambda a: (a.priority, a.action, a.target_algorithm or "", a.standard or ""))
    )
    return ClassifiedNode(
        node,
        tier,
        threat,
        family,
        primitive,
        " ".join(dict.fromkeys(notes)),
        unique_advice,
        confidence,
        tuple(sorted(set(exclusions))),
        broken,
        hndl,
        fs,
        legacy,
        oid,
        bits,
        level,
        standard,
        children,
        tuple(sorted(set(maintenance), key=lambda a: (a.priority, a.action))),
    )
