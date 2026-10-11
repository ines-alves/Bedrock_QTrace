"""KMS key inventory adapter: one KEY finding per key, facts only."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id, register

USAGE = {
    "SIGN_VERIFY": Usage.SIGNATURE,
    "ENCRYPT_DECRYPT": Usage.ENCRYPTION,
    "KEY_AGREEMENT": Usage.KEY_EXCHANGE,
    "GENERATE_VERIFY_MAC": Usage.MAC,
}


def _load_inventory(path: Path) -> dict | None:
    """Return the parsed inventory when the content has the ListKeys/DescribeKey shape."""
    if path.suffix != ".json":
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    keys = data.get("Keys") if isinstance(data, dict) else None
    if isinstance(keys, list) and keys and all(isinstance(k, dict) and _spec(k) for k in keys):
        return data
    return None


def _spec(key: dict) -> str | None:
    """KeySpec, or the deprecated CustomerMasterKeySpec that older SDKs and DescribeKey responses still
    return alone (AWS KMS API reference, KeyMetadata, checked 2026-10-11)."""
    spec = key.get("KeySpec") or key.get("CustomerMasterKeySpec")
    return spec if isinstance(spec, str) and spec else None


@register
class KmsScanner:
    name = "cloud.kms"
    source_type = SourceType.KMS

    def can_handle(self, path: Path) -> bool:
        return _load_inventory(path) is not None

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        data = _load_inventory(path)
        rel = path.relative_to(root).as_posix()
        if data is None:
            yield ScanError(detector=self.name, path=rel, message="not a KMS key inventory")
            return
        for key in data["Keys"]:
            # ListKeys exports carry KeyArn; DescribeKey KeyMetadata names the same value Arn.
            resource_id = key.get("KeyArn") or key.get("Arn") or key.get("KeyId") or key.get("AliasName")
            if not resource_id:
                yield ScanError(
                    detector=self.name, path=rel, message="key without KeyArn, KeyId or AliasName"
                )
                continue
            spec = _spec(key) or ""
            rsa = re.fullmatch(r"RSA_(\d+)", spec)
            nist = re.fullmatch(r"ECC_NIST_P(\d+)", spec)
            flags = []
            if key.get("KeyRotationStatus") == "DISABLED":
                flags.append("rotation_disabled")
            if key.get("MultiRegion"):
                flags.append("multi_region_key")
            loc = Location(
                source_type=SourceType.KMS, file=rel, resource_id=resource_id, target=key.get("AliasName")
            )
            yield Finding(
                id=finding_id(self.name, spec, loc),
                raw_name=spec,
                kind_hint=KindHint.KEY,
                usage=USAGE.get(key.get("KeyUsage"), Usage.UNKNOWN),
                key_size=int(rsa.group(1)) if rsa else None,
                curve=f"P-{nist.group(1)}" if nist else None,
                detector=self.name,
                location=loc,
                extra={
                    "alias": key.get("AliasName"),
                    "key_usage": key.get("KeyUsage"),
                    "origin": key.get("Origin"),
                    "state": key.get("KeyState"),
                    "rotation_status": key.get("KeyRotationStatus"),
                    "valid_to": key.get("ValidTo"),
                    "deletion_date": key.get("DeletionDate"),
                    "multi_region": key.get("MultiRegion"),
                    "source_timestamp": data.get("GeneratedAt"),
                    "hygiene_flags": flags,
                },
            )
