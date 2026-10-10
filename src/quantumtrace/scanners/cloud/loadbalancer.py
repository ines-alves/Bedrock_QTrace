"""Load balancer listener adapter: one finding per listener, facts only."""

from __future__ import annotations

import json
from collections.abc import Iterator
from functools import cache
from importlib import resources
from pathlib import Path

import yaml

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType
from quantumtrace.scanners.base import finding_id, register

TLS_PROTOCOLS = {"HTTPS", "TLS"}
# Policy not in kb/cloud_registry.yaml: the engine cannot expand it, so the detection is less certain.
UNKNOWN_POLICY_CONFIDENCE = 0.5


@cache
def _known_policies() -> frozenset[str]:
    text = resources.files("quantumtrace.kb").joinpath("cloud_registry.yaml").read_text(encoding="utf-8")
    return frozenset(yaml.safe_load(text)["elb_policies"])


def _load_dump(path: Path) -> dict | None:
    """Return the parsed dump when the content has the DescribeLoadBalancers/Listeners shape."""
    if path.suffix != ".json":
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    lbs = data.get("LoadBalancers") if isinstance(data, dict) else None
    if isinstance(lbs, list) and lbs and all(isinstance(b, dict) and "Listeners" in b for b in lbs):
        return data
    return None


def _redirects_to_https(listener: dict) -> bool:
    actions = listener.get("DefaultActions") or []
    return bool(actions) and all(
        a.get("Type") == "redirect" and (a.get("RedirectConfig") or {}).get("Protocol") == "HTTPS"
        for a in actions
    )


@register
class LoadBalancerScanner:
    name = "cloud.loadbalancer"
    source_type = SourceType.LOADBALANCER

    def can_handle(self, path: Path) -> bool:
        return _load_dump(path) is not None

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        data = _load_dump(path)
        rel = path.relative_to(root).as_posix()
        if data is None:
            yield ScanError(detector=self.name, path=rel, message="not a load balancer listener dump")
            return
        for lb in data["LoadBalancers"]:
            lb_name = lb.get("LoadBalancerName")
            scheme = lb.get("Scheme")
            for listener in lb["Listeners"]:
                arn = listener.get("ListenerArn")
                protocol = listener.get("Protocol")
                if not arn or not protocol:
                    yield ScanError(
                        detector=self.name, path=rel, message=f"listener of {lb_name} without ARN or protocol"
                    )
                    continue
                loc = Location(source_type=SourceType.LOADBALANCER, file=rel, resource_id=arn, target=lb_name)
                extra = {
                    "lb_name": lb_name,
                    "lb_type": lb.get("Type"),
                    "listener_protocol": protocol,
                    "port": listener.get("Port"),
                    "listener_arn": arn,
                    "public_exposure": scheme == "internet-facing" if scheme else None,
                    "source_timestamp": data.get("GeneratedAt"),
                }
                if protocol in TLS_PROTOCOLS:
                    policy = listener.get("SslPolicy")
                    if not policy:
                        yield ScanError(
                            detector=self.name,
                            path=rel,
                            message=f"{protocol} listener {arn} without SslPolicy",
                        )
                        continue
                    extra.update(
                        ssl_policy=policy,
                        hygiene_flags=[],
                        certificate_arns=[c["CertificateArn"] for c in listener.get("Certificates", [])],
                    )
                    yield Finding(
                        id=finding_id(self.name, policy, loc),
                        raw_name=policy,
                        kind_hint=KindHint.POLICY,
                        protocol=protocol,
                        detector=self.name,
                        confidence=1.0 if policy in _known_policies() else UNKNOWN_POLICY_CONFIDENCE,
                        location=loc,
                        extra=extra,
                    )
                elif protocol == "HTTP":
                    redirect = _redirects_to_https(listener)
                    extra.update(
                        hygiene_only=True,
                        redirects_to_https=redirect,
                        hygiene_flags=["redirect_only_listener"] if redirect else [],
                    )
                    yield Finding(
                        id=finding_id(self.name, f"{protocol}:{listener.get('Port')}", loc),
                        raw_name=f"{protocol}:{listener.get('Port')}",
                        kind_hint=KindHint.PLAINTEXT,
                        protocol="http",
                        detector=self.name,
                        location=loc,
                        extra=extra,
                    )
                else:
                    yield ScanError(
                        detector=self.name,
                        path=rel,
                        message=f"unsupported listener protocol {protocol}: {arn}",
                    )
