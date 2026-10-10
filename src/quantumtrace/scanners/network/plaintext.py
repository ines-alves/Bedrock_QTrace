"""Plaintext ``Flow`` records to ``PLAINTEXT`` findings, independent of which parser produced them.

Detect-only and hygiene-only: a plaintext finding is never a session, carries no tier, threat, score,
``pq_status`` or verdict, and is excluded from the quantum score by the engine (M2M4-03, M1M2-12).

What is emitted:

* one finding per HTTP flow, from its first request. The request line is the evidence for the
  ``http`` label, so the port is not what makes the flow plaintext.
* nothing for a STARTTLS / SSLRequest that no TLS followed. The upgrade request was seen, but a
  refusal was not, and the capture may simply have ended: a ``ScanError`` names the stream instead
  of a guessed finding (M1M2-14). A refusal-based finding needs an agreed evidence key first.

Shape of the output: ``M2M4-03`` and the M1M2-11 to M1M2-14 replies.
"""

from __future__ import annotations

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id
from quantumtrace.scanners.network.purepy import Flow, PureResult
from quantumtrace.scanners.network.tls_session import SCANNER

DETECTOR_HTTP = "pcap.plaintext.http"
HTTP_KEYS = ("method", "path", "host", "server", "status")


def _http_finding(flow: Flow, file: str) -> Finding | ScanError:
    info = flow.http
    assert info is not None  # kind == "http" always carries it
    location = Location(source_type=SourceType.PCAP, file=file, flow=flow.flow, frame=info.frame)
    return Finding(
        id=finding_id(DETECTOR_HTTP, "HTTP", location),
        raw_name="HTTP",
        kind_hint=KindHint.PLAINTEXT,
        usage=Usage.UNKNOWN,
        protocol="http",
        negotiated=None,  # nothing is negotiated in the clear
        detector=DETECTOR_HTTP,
        confidence=1.0,  # the request line was observed, not inferred from a port
        location=location,
        session_id=None,  # never a session (M2M4-03)
        extra={
            "hygiene_only": True,
            "http": {
                "method": info.method,
                "path": info.path,
                "host": info.host,
                "server": info.server,
                "status": info.status,
            },
        },
    )


def _flow_findings(flow: Flow, file: str) -> list[Finding | ScanError]:
    where = f"stream {flow.stream_id} {flow.flow}"
    out: list[Finding | ScanError] = []
    if flow.kind == "http":
        out.append(_http_finding(flow, file))
    elif flow.kind == "plaintext":
        out.append(
            ScanError(
                detector=SCANNER,
                path=file,
                message=(
                    f"{where}: upgrade requested ({flow.upgrade_request}, label from the port) but "
                    "no TLS was observed; a refusal is not established, so no plaintext finding "
                    "is emitted"
                ),
            )
        )
    else:
        return out
    out.extend(ScanError(detector=SCANNER, path=file, message=f"{where}: {w}") for w in flow.warnings)
    return out


def build_findings(result: PureResult, file: str, parser_errors: bool = True) -> list[Finding | ScanError]:
    """Findings and errors for every plaintext flow of a parse result, in stream order.

    ``file`` is the root-relative posix path (see ``tls_session.relative_posix``). A caller that
    also runs the TLS and SSH builders on the same result passes ``parser_errors=False`` to all but
    one of them, so each parser error is reported once.
    """
    out: list[Finding | ScanError] = []
    if parser_errors:
        out.extend(ScanError(detector=SCANNER, path=file, message=e) for e in result.errors)
    for flow in sorted(result.flows, key=lambda f: f.stream_id):
        out.extend(_flow_findings(flow, file))
    return out
