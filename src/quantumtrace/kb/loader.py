"""Validate packaged policy data without interpreting scanner evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from enum import Enum
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    field_validator,
    model_validator,
)

from quantumtrace.models import Threat, Tier, Usage

Text = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]
Primitive = Literal[
    "drbg",
    "mac",
    "block-cipher",
    "stream-cipher",
    "signature",
    "hash",
    "pke",
    "xof",
    "kdf",
    "key-agree",
    "kem",
    "ae",
    "combiner",
    "other",
    "unknown",
]
Mode = Literal["cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"]
PositiveInt = Annotated[int, Field(strict=True, gt=0)]
QuantumLevel = Annotated[int, Field(strict=True, ge=1, le=5)]
UsageKey = Literal["default"] | Usage


class KnowledgeBaseError(ValueError):
    """Required policy data is missing, malformed, or internally inconsistent."""


def alias_key(value: str) -> str:
    """Return the specified punctuation-insensitive KB alias index key."""
    return re.sub(r"[\s_\-/]", "", value.casefold())


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    @model_validator(mode="after")
    def freeze_maps(self) -> Self:
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, dict):
                object.__setattr__(self, name, MappingProxyType(value))
        return self


class Source(_FrozenModel):
    """A traceable fact or repository policy, distinct from risk classification."""

    url: Text
    checked_on: date
    note: Text

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        if not value.startswith(("https://", "repo:")):
            raise ValueError("sources must be primary HTTPS references or repository policy")
        return value


class Replacement(_FrozenModel):
    """A usage-specific migration target referencing another KB entry."""

    algorithm_id: Text
    parameter_set: Text | None = None
    key_size: PositiveInt | None = None
    mode: Mode | None = None
    standard: Text | None = None


class Component(_FrozenModel):
    """A hybrid combiner component; its tier does not override the combiner."""

    algorithm_id: Text
    parameter_set: Text | None = None
    curve: Text | None = None
    key_size: PositiveInt | None = None
    usage: Usage = Usage.UNKNOWN


class BrokenCondition(_FrozenModel):
    """Observed parameters or usages required for a classical-break policy flag."""

    key_size_lt: PositiveInt | None = None
    usages: tuple[Usage, ...] = ()

    @model_validator(mode="after")
    def require_condition(self) -> Self:
        if self.key_size_lt is None and not self.usages:
            raise ValueError("broken condition cannot be empty")
        return self


class Algorithm(_FrozenModel):
    """Immutable algorithm policy and independently sourced optional facts."""

    id: Text
    family: Text
    primitive_by_usage: Mapping[UsageKey, Primitive]
    primitive_by_mode: Mapping[Mode, Primitive] = Field(default_factory=dict)
    tier: Tier | None = None
    tier_by_key_size: Mapping[str, Tier] = Field(default_factory=dict)
    threat: Threat
    aliases: tuple[Text, ...] = ()
    patterns: tuple[Text, ...] = ()
    modes: tuple[Mode, ...] = ()
    key_sizes: tuple[PositiveInt, ...] = ()
    parameter_sets: tuple[Text, ...] = ()
    param_map: Mapping[str, str] = Field(default_factory=dict)
    curve_aliases: Mapping[str, str] = Field(default_factory=dict)
    oid: Text | None = None
    oids: Mapping[str, Text] = Field(default_factory=dict)
    classical_security_bits: PositiveInt | None = None
    nist_quantum_level: QuantumLevel | None = None
    nist_quantum_level_by_param: Mapping[str, QuantumLevel] = Field(default_factory=dict)
    pqc_standard: Text | None = None
    standards_status: Literal["not_claimed", "final", "in_development", "pre_standard"] = "not_claimed"
    classically_broken: StrictBool = False
    classically_broken_if: BrokenCondition | None = None
    deprecated_pqc_draft: StrictBool = False
    deprecated_aliases: tuple[Text, ...] = ()
    note_if_alias: Mapping[str, Text] = Field(default_factory=dict)
    replacement: Mapping[UsageKey, Replacement] = Field(default_factory=dict)
    components: tuple[Component, ...] = ()
    forward_secrecy: StrictBool | None = None
    follow_underlying_hash: StrictBool = False
    warnings: tuple[Text, ...] = ()
    scoring_excluded: StrictBool = False
    note: Text
    sources: tuple[Source, ...] = Field(min_length=1)

    @field_validator("oid", "oids")
    @classmethod
    def validate_oids(cls, value: Any) -> Any:
        values = value.values() if isinstance(value, Mapping) else (value,) if value else ()
        for oid in values:
            if not re.fullmatch(r"[012](?:\.(?:0|[1-9]\d*)){1,}", oid):
                raise ValueError(f"invalid OID {oid!r}")
            arcs = [int(arc) for arc in oid.split(".")]
            if arcs[0] < 2 and arcs[1] > 39:
                raise ValueError(f"invalid OID arcs {oid!r}")
        return value

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if (self.tier is None) == (not self.tier_by_key_size):
            raise ValueError("provide exactly one of tier or tier_by_key_size")
        if not self.primitive_by_usage:
            raise ValueError("primitive_by_usage cannot be empty")
        if self.tier_by_key_size:
            if "unknown" not in self.tier_by_key_size:
                raise ValueError("key-size policy requires an unknown fallback")
            if set(self.tier_by_key_size) != {str(size) for size in self.key_sizes} | {"unknown"}:
                raise ValueError("key-size policy must cover exactly the declared key sizes")
        params = set(self.parameter_sets)
        if len(params) != len(self.parameter_sets) or len(set(self.key_sizes)) != len(self.key_sizes):
            raise ValueError("duplicate parameters or key sizes")
        if not set(self.param_map.values()) <= params or not set(self.nist_quantum_level_by_param) <= params:
            raise ValueError("parameter metadata refers to undeclared parameters")
        if len(set(self.modes)) != len(self.modes) or not set(self.primitive_by_mode) <= set(self.modes):
            raise ValueError("invalid mode metadata")
        if self.pqc_standard and self.standards_status == "not_claimed":
            raise ValueError("a PQC standard requires explicit standards status")
        if self.deprecated_pqc_draft and self.standards_status != "pre_standard":
            raise ValueError("deprecated drafts cannot claim final standards status")
        names = {alias_key(alias) for alias in (self.id, *self.aliases)}
        if not {alias_key(alias) for alias in self.deprecated_aliases} <= names:
            raise ValueError("deprecated alias must be declared")
        if not {alias_key(alias) for alias in self.note_if_alias} <= names:
            raise ValueError("alias notes must reference declared aliases")
        return self


class Occurrence(_FrozenModel):
    cap: PositiveInt
    log_divisor: Annotated[float, Field(strict=True, gt=0)]


class GradeBand(_FrozenModel):
    grade: Literal["A", "B", "C", "D", "E", "F"]
    minimum: Annotated[int, Field(strict=True, ge=0, le=100)]
    maximum: Annotated[int, Field(strict=True, ge=0, le=100)]


class HNDLFloor(_FrozenModel):
    score: Annotated[int, Field(strict=True, ge=0, le=100)]
    condition: Literal["hndl_exposed_and_negotiated"]


class Scoring(_FrozenModel):
    """Validated scoring configuration; as_dict() supplies an independent API payload."""

    tier_weights: Mapping[Tier, Annotated[float, Field(strict=True, ge=0)]]
    exposure: Mapping[
        Literal[
            "negotiated_key_exchange",
            "public_loadbalancer_policy",
            "negotiated_other",
            "kms_enabled",
            "production",
            "offered_only",
            "kms_inactive",
            "test_only",
        ],
        Annotated[float, Field(strict=True, gt=0)],
    ]
    broken_multiplier: Annotated[float, Field(strict=True, ge=1)]
    occurrence: Occurrence
    grade_bands: tuple[GradeBand, ...]
    hndl_floor: HNDLFloor
    aes_192_tier: Literal[Tier.MEDIUM, Tier.SAFE] = Tier.MEDIUM

    @model_validator(mode="after")
    def validate_scoring(self) -> Self:
        if set(self.tier_weights) != set(Tier) or self.tier_weights[Tier.CRITICAL] <= 0:
            raise ValueError("all tier weights and a positive CRITICAL weight are required")
        if not (
            self.tier_weights[Tier.CRITICAL]
            >= self.tier_weights[Tier.MEDIUM]
            >= self.tier_weights[Tier.UNKNOWN]
            >= self.tier_weights[Tier.SAFE]
            == 0
        ):
            raise ValueError("tier weights must be ordered; SAFE must be zero")
        if len(self.exposure) != 8:
            raise ValueError("all exposure categories are required")
        if tuple(band.grade for band in self.grade_bands) != tuple("ABCDEF"):
            raise ValueError("grade bands must be A through F")
        next_score = 0
        for band in self.grade_bands:
            if band.minimum != next_score or band.maximum < band.minimum:
                raise ValueError("grade bands must cover 0..100 without gaps/overlaps")
            next_score = band.maximum + 1
        if next_score != 101:
            raise ValueError("grade bands must end at 100")
        return self

    def as_dict(self) -> dict[str, Any]:
        """Return mutable JSON-compatible data without exposing the stored configuration."""
        return {name: _plain(getattr(self, name)) for name in type(self).model_fields}


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return {name: _plain(getattr(value, name)) for name in type(value).model_fields}
    if isinstance(value, Mapping):
        return {_plain(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML that refuses duplicate keys instead of silently overwriting them."""


def _mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int)) or isinstance(key, bool):
            raise KnowledgeBaseError("YAML mapping keys must be strings or integers")
        if key in result:
            raise KnowledgeBaseError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True)
class PatternRule:
    """A compiled rule, in deterministic algorithm/pattern order."""

    algorithm_id: str
    expression: re.Pattern[str]


@dataclass(frozen=True)
class KnowledgeBase:
    """Validated indexes. Lookups identify entries; classification belongs to the engine."""

    algorithms: Mapping[str, Algorithm]
    aliases: Mapping[str, str]
    patterns: tuple[PatternRule, ...]
    scoring: Scoring
    optional_registries: Mapping[str, bool]

    def get(self, algorithm_id: str) -> Algorithm:
        """Look up a canonical entry ID, raising KeyError for missing entries."""
        return self.algorithms[algorithm_id]

    def by_alias(self, raw_name: str) -> Algorithm | None:
        """Find an exact normalized alias; composite decomposition is a later engine step."""
        identifier = self.aliases.get(alias_key(raw_name))
        return self.algorithms[identifier] if identifier is not None else None


def _read(name: str, directory: Path | None) -> Any:
    try:
        text = (
            (directory / name).read_text(encoding="utf-8")
            if directory
            else (resources.files("quantumtrace.kb").joinpath(name).read_text(encoding="utf-8"))
        )
        return yaml.load(text, Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
        raise KnowledgeBaseError(f"{name}: {exc}") from exc


def load_scoring(directory: Path | None = None) -> Scoring:
    """Load required scoring data from a directory or packaged resources."""
    try:
        return Scoring.model_validate(_read("scoring.yaml", directory))
    except ValueError as exc:
        raise KnowledgeBaseError(f"scoring.yaml: {exc}") from exc


def load_kb(directory: Path | None = None) -> KnowledgeBase:
    """Load required policies and report presence of owner-managed optional registries."""
    data = _read("algorithms.yaml", directory)
    if not isinstance(data, list) or not data:
        raise KnowledgeBaseError("algorithms.yaml must be a nonempty list")
    algorithms: dict[str, Algorithm] = {}
    aliases: dict[str, str] = {}
    patterns: list[PatternRule] = []
    seen_patterns: dict[str, str] = {}
    try:
        for item in data:
            entry = Algorithm.model_validate(item)
            if entry.id in algorithms:
                raise ValueError(f"duplicate algorithm ID {entry.id}")
            algorithms[entry.id] = entry
        for identifier, entry in sorted(algorithms.items()):
            for alias in (identifier, *entry.aliases):
                key = alias_key(alias)
                if not key or (key in aliases and aliases[key] != identifier):
                    raise ValueError(f"conflicting or empty alias {alias!r}")
                aliases[key] = identifier
            for pattern in entry.patterns:
                if not pattern.startswith("^") or not pattern.endswith("$"):
                    raise ValueError(f"{identifier}: pattern must be anchored")
                if pattern in seen_patterns and seen_patterns[pattern] != identifier:
                    raise ValueError(f"conflicting pattern {pattern}")
                compiled = re.compile(pattern, re.IGNORECASE)
                if not set(compiled.groupindex) <= {"size", "curve", "mode", "param", "variant"}:
                    raise ValueError(f"{identifier}: unknown pattern capture")
                patterns.append(PatternRule(identifier, compiled))
                seen_patterns[pattern] = identifier
            references: tuple[Component | Replacement, ...] = (*entry.components, *entry.replacement.values())
            for ref in references:
                if ref.algorithm_id not in algorithms:
                    raise ValueError(f"{identifier}: missing reference {ref.algorithm_id}")
                target = algorithms[ref.algorithm_id]
                if ref.parameter_set and ref.parameter_set not in target.parameter_sets:
                    raise ValueError(f"{identifier}: undeclared target parameter {ref.parameter_set}")
                if isinstance(ref, Replacement):
                    if ref.key_size is not None and ref.key_size not in target.key_sizes:
                        raise ValueError(f"{identifier}: undeclared target key size")
                    if ref.mode is not None and ref.mode not in target.modes:
                        raise ValueError(f"{identifier}: undeclared target mode")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(identifier: str) -> None:
            if identifier in visiting:
                raise ValueError(f"cyclic component reference: {identifier}")
            if identifier in visited:
                return
            visiting.add(identifier)
            for ref in algorithms[identifier].components:
                visit(ref.algorithm_id)
            visiting.remove(identifier)
            visited.add(identifier)

        for identifier in sorted(algorithms):
            visit(identifier)
    except (ValueError, TypeError, re.error) as exc:
        raise KnowledgeBaseError(f"algorithms.yaml: {exc}") from exc
    registries = {}
    for name in ("tls_registry.yaml", "cloud_registry.yaml"):
        registries[name] = (
            (directory / name).is_file()
            if directory
            else (resources.files("quantumtrace.kb").joinpath(name).is_file())
        )
    return KnowledgeBase(
        MappingProxyType(dict(sorted(algorithms.items()))),
        MappingProxyType(dict(sorted(aliases.items()))),
        tuple(patterns),
        load_scoring(directory),
        MappingProxyType(registries),
    )
