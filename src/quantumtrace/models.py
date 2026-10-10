"""Frozen shared contracts for QuantumTrace scanner and consumer integration."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator


class SourceType(str, Enum):
    """Evidence source identifiers shared by scanners and reports."""

    PCAP = "pcap"
    LIVE = "live"
    CODE = "code"
    CONFIG = "config"
    KMS = "kms"
    LOADBALANCER = "loadbalancer"
    KEYFILE = "keyfile"
    BINARY = "binary"
    SSH = "ssh"
    ACM = "acm"


class KindHint(str, Enum):
    """Raw detected object kinds; classification belongs to the engine."""

    CIPHER_SUITE = "cipher_suite"
    GROUP = "group"
    SIGNATURE_SCHEME = "signature_scheme"
    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL_VERSION = "protocol_version"
    POLICY = "policy"
    LIBRARY = "library"
    PLAINTEXT = "plaintext"


class Usage(str, Enum):
    """The cryptographic purpose observed by a scanner."""

    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    RNG = "rng"
    AUTHENTICATION = "authentication"
    UNKNOWN = "unknown"


class Tier(str, Enum):
    """Quantum risk verdict assigned by the central engine."""

    CRITICAL = "CRITICAL"
    MEDIUM = "MEDIUM"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"


class Threat(str, Enum):
    """The quantum attack associated with an engine verdict."""

    SHOR = "shor"
    GROVER = "grover"
    NONE = "none"
    UNKNOWN = "unknown"


class Location(BaseModel):
    """File, network, or resource evidence for a detected occurrence."""

    source_type: SourceType
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    flow: str | None = None
    sni: str | None = None
    frame: int | None = None
    resource_id: str | None = None
    target: str | None = None


class Finding(BaseModel):
    """Raw scanner evidence, without engine-assigned risk or recommendations."""

    id: str
    raw_name: str
    kind_hint: KindHint
    usage: Usage = Usage.UNKNOWN
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    library: str | None = None
    language: str | None = None
    protocol: str | None = None
    negotiated: bool | None = None
    in_test_code: bool = False
    detector: str
    confidence: float = Field(1.0, ge=0, le=1)
    location: Location
    session_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanError(BaseModel):
    """A recoverable scanner failure retained alongside usable evidence."""

    detector: str
    path: str | None = None
    message: str


class Recommendation(BaseModel):
    """A migration action assigned by the engine."""

    action: str
    target_algorithm: str | None
    standard: str | None
    priority: int


class CryptoAsset(BaseModel):
    """A classified asset with traceable evidence and component relationships."""

    asset_id: str
    canonical_name: str
    family: str
    asset_type: Literal["algorithm", "certificate", "protocol", "related-crypto-material"]
    primitive: str
    usage: Usage
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    parameter_set: str | None = None
    oid: str | None = None
    tier: Tier
    threat: Threat
    classically_broken: bool = False
    hndl_exposed: bool = False
    forward_secrecy: bool | None = None
    deprecated_pqc_draft: bool = False
    classical_security_bits: int | None = None
    nist_quantum_level: int | None = None
    pqc_standard: str | None = None
    rationale: str
    recommendations: list[Recommendation] = Field(default_factory=list)
    occurrences: list[Location] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    component_of: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    negotiated: bool | None = None
    in_test_code_only: bool = False
    risk_points: float = 0.0
    max_points: float = 0.0


class TLSSession(BaseModel):
    """TLS or SSH session view, including unobservable authentication."""

    session_id: str
    flow: str
    sni: str | None
    version: str | None
    offered_groups: list[str] = Field(default_factory=list)
    negotiated_group: str | None = None
    offered_cipher_suites: list[str] = Field(default_factory=list)
    negotiated_cipher_suite: str | None = None
    offered_sig_schemes: list[str] = Field(default_factory=list)
    cert_key: str | None = None
    cert_sig_alg: str | None = None
    pq_status: Literal["pq_hybrid", "pq_pure", "classical", "unknown"]
    verdict_tier: Tier
    source: str
    transport: Literal["tls", "ssh"] = "tls"
    service: str | None = None
    peer_banners: list[str] = Field(default_factory=list)


class RiskSummary(BaseModel):
    """Enterprise and per-source risk computed by the scoring engine."""

    score: int
    grade: Literal["A", "B", "C", "D", "E", "F"]
    readiness_pct: float
    counts_by_tier: dict[str, int]
    counts_by_source: dict[str, dict[str, int]]
    score_by_source: dict[str, int]
    hndl_exposed_count: int
    top_risks: list[str]


class RoadmapItem(BaseModel):
    """A phased migration action linking affected assets and evidence counts."""

    phase: Literal[0, 1, 2, 3]
    action: str
    asset_ids: list[str] = Field(default_factory=list)
    occurrence_count: int = Field(ge=0)


class ScanOptions(BaseModel):
    """Directory exclusions and optional scanner selection for a scan."""

    model_config = ConfigDict(extra="forbid")

    exclude_dirs: list[Annotated[str, StringConstraints(min_length=1)]] = Field(
        default_factory=lambda: [".git", "node_modules", "venv", ".venv", "vendor", "out", "agents"]
    )
    scanner_names: list[Annotated[str, StringConstraints(min_length=1)]] | None = None

    @field_validator("exclude_dirs")
    @classmethod
    def validate_directory_names(cls, names: list[str]) -> list[str]:
        """Require individual directory names instead of ambiguous path patterns."""
        if any(name in {".", ".."} or not name.strip() or "/" in name or "\\" in name for name in names):
            raise ValueError("exclude_dirs must contain nonempty directory names, not paths")
        return names

    @field_validator("scanner_names")
    @classmethod
    def validate_scanner_names(cls, names: list[str] | None) -> list[str] | None:
        """Validate names structurally; registry selection validates availability."""
        if names is not None and any(not name.strip() for name in names):
            raise ValueError("scanner_names must contain nonempty names")
        return names


class ScanResult(BaseModel):
    """Versioned serialized integration boundary for reports, API, and UI."""

    schema_version: str = "1.0"
    tool_version: str
    scan_id: str
    started_at: str
    finished_at: str
    inputs: list[str]
    findings: list[Finding]
    assets: list[CryptoAsset]
    sessions: list[TLSSession] = Field(default_factory=list)
    summary: RiskSummary
    errors: list[ScanError] = Field(default_factory=list)
    roadmap: list[RoadmapItem] | None = Field(default=None, exclude_if=lambda value: value is None)
