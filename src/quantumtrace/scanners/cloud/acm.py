"""ACM certificate adapter: one CERTIFICATE finding per certificate, facts only."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id, register

CURVES = {"EC_prime256v1": "P-256", "EC_secp384r1": "P-384"}


def _load_dump(path: Path) -> dict | None:
    """Return the parsed dump when the content has the ListCertificates/DescribeCertificate shape."""
    if path.suffix != ".json":
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    certs = data.get("Certificates") if isinstance(data, dict) else None
    if (
        isinstance(certs, list)
        and certs
        and all(isinstance(c, dict) for c in certs)
        and any("CertificateArn" in c and "KeyAlgorithm" in c for c in certs)
    ):
        return data
    return None


@register
class AcmScanner:
    name = "cloud.acm"
    source_type = SourceType.ACM

    def can_handle(self, path: Path) -> bool:
        return _load_dump(path) is not None

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        data = _load_dump(path)
        rel = path.relative_to(root).as_posix()
        if data is None:
            yield ScanError(detector=self.name, path=rel, message="not an ACM certificate dump")
            return
        for cert in data["Certificates"]:
            arn = cert.get("CertificateArn")
            algorithm = cert.get("KeyAlgorithm")
            if not arn or not algorithm:
                yield ScanError(
                    detector=self.name, path=rel, message="certificate without CertificateArn or KeyAlgorithm"
                )
                continue
            rsa = re.fullmatch(r"RSA_(\d+)", algorithm)
            loc = Location(
                source_type=SourceType.ACM, file=rel, resource_id=arn, target=cert.get("DomainName")
            )
            yield Finding(
                id=finding_id(self.name, algorithm, loc),
                raw_name=algorithm,
                kind_hint=KindHint.CERTIFICATE,
                usage=Usage.AUTHENTICATION,
                key_size=int(rsa.group(1)) if rsa else None,
                curve=CURVES.get(algorithm),
                detector=self.name,
                location=loc,
                extra={
                    "domain": cert.get("DomainName"),
                    "origin": cert.get("Type"),
                    "state": cert.get("Status"),
                    "cert_status": cert.get("Status"),
                    "not_before": cert.get("NotBefore"),
                    "not_after": cert.get("NotAfter"),
                    "in_use_by": cert.get("InUseBy"),
                    "signature_algorithm": cert.get("SignatureAlgorithm"),
                    "key_algorithm": algorithm,
                    "source_timestamp": data.get("GeneratedAt"),
                    "hygiene_flags": [],
                },
            )
