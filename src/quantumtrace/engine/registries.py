"""Conservative adapters for the published M2/M4 packaged registry schemas."""

from __future__ import annotations

import re
from importlib.resources import files
from typing import Any

import yaml

from quantumtrace.engine.decompose import CloudResolution, ComponentSpec
from quantumtrace.engine.normalize import RegistryResolution
from quantumtrace.models import Finding, KindHint, SourceType, Usage

_NAMESPACES = {
    KindHint.CIPHER_SUITE: "cipher_suites",
    KindHint.GROUP: "groups",
    KindHint.SIGNATURE_SCHEME: "signature_schemes",
    KindHint.PROTOCOL_VERSION: "versions",
}


def _read(name: str) -> dict[str, Any]:
    data = yaml.safe_load(files("quantumtrace.kb").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("meta", {}).get("schema") != 1:
        raise ValueError(f"unsupported {name} schema")
    return data


class TLSRegistry:
    """Resolve only named, sourced rows without verify markers; keep namespaces separate."""

    def __init__(self) -> None:
        self.data = _read("tls_registry.yaml")

    def resolve(self, kind: KindHint, codepoint: str) -> RegistryResolution | None:
        namespace = _NAMESPACES.get(kind)
        row = self.data.get(namespace, {}).get(codepoint) if namespace else None
        if not isinstance(row, dict) or "verify" in row:
            return None
        name = row.get("label" if kind == KindHint.PROTOCOL_VERSION else "iana")
        if not isinstance(name, str) or not name.strip():
            return None
        # Version rows in M2's schema have no per-row reference. Preserve uncertainty.
        reference = row.get("ref")
        if not isinstance(reference, str) or not reference.strip():
            return None
        return RegistryResolution(
            kind, codepoint, name, True, f"https://www.iana.org/assignments/tls-parameters ({reference})"
        )

    def resolve_name(self, kind: KindHint, raw_name: str) -> RegistryResolution | None:
        namespace = _NAMESPACES.get(kind)
        if namespace is None:
            return None
        matches = []
        for code, row in self.data.get(namespace, {}).items():
            if isinstance(row, dict) and raw_name in row.get("openssl", []):
                resolved = self.resolve(kind, code)
                if resolved:
                    matches.append(resolved)
        return matches[0] if len(matches) == 1 else None


class CloudRegistry:
    """Translate verified recipes; conditional KMS mappings require an observed partition."""

    def __init__(self, tls: TLSRegistry) -> None:
        self.data = _read("cloud_registry.yaml")
        self.tls = tls

    def resolve(self, finding: Finding) -> CloudResolution | None:
        specs: list[ComponentSpec] = []
        sources = self.data["meta"]["sources"]
        source = ""
        if finding.location.source_type == SourceType.KMS and finding.kind_hint == KindHint.KEY:
            row = self.data.get("kms_key_specs", {}).get(finding.raw_name)
            if not isinstance(row, dict) or row.get("verified") is not True:
                return None
            arn = finding.location.resource_id or ""
            match = re.fullmatch(r"arn:([^:]+):kms:[^:]+:[^:]+:key/.+", arn)
            if match is None:
                return None
            partition = match.group(1)
            recipe = row.get("partitions", {}).get(partition)
            if recipe is None and partition in row.get("default_partitions", []):
                recipe = row.get("default")
            if not isinstance(recipe, dict) or not isinstance(recipe.get("algorithm"), str):
                return None
            if finding.usage not in {Usage.ENCRYPTION, Usage.UNKNOWN}:
                return None
            specs.append(
                ComponentSpec(
                    recipe["algorithm"],
                    finding.usage,
                    "key",
                    key_size=recipe.get("key_size"),
                    mode=recipe.get("mode"),
                    inherit_parameters=True,
                )
            )
            source = sources["kms_key_spec"]
        elif finding.location.source_type == SourceType.LOADBALANCER and finding.kind_hint == KindHint.POLICY:
            row = self.data.get("elb_policies", {}).get(finding.raw_name)
            if not isinstance(row, dict) or row.get("verified") is not True:
                return None
            source = " ".join(sources[key] for key in row["source"].split("+"))
            for name in row.get("cipher_suites", []):
                if not name.startswith("TLS_"):
                    resolved = self.tls.resolve_name(KindHint.CIPHER_SUITE, name)
                    if resolved is None:
                        # Retain unsupported names explicitly; never fill a guessed suite.
                        specs.append(ComponentSpec(name, Usage.UNKNOWN, "unresolved_cipher_suite"))
                        continue
                    name = resolved.iana_name
                specs.append(ComponentSpec(name, Usage.UNKNOWN, "cipher_suite", kind=KindHint.CIPHER_SUITE))
            if row.get("groups_verified") is True:
                specs.extend(
                    ComponentSpec(name, Usage.KEY_EXCHANGE, "key_exchange", kind=KindHint.GROUP)
                    for name in row.get("groups", [])
                )
        if not specs or not source:
            return None
        return CloudResolution(finding.raw_name, finding.location.source_type, tuple(specs), True, source)
