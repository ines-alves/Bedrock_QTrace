"""The registered ``pcap`` scanner adapter: capture file in, Finding / ScanError entries out.

tshark is the primary parser and purepy the fallback. Both return the same ``PureResult`` /
``Flow`` records, so the three builders (``tls_session``, ``ssh``, ``plaintext``) are parser
independent. This module only chooses the parser, reports problems once, and orders the output:
parser and cross-check errors, then TLS, SSH and plaintext findings, each in stream order.

Detect-only and never raises: every failure is a ``ScanError``. A capture that the active parser
cannot read is an error, never an empty success. The adapter does not instantiate ``TLSSession``
and assigns no tier, threat, score or verdict.
"""

from __future__ import annotations

import dataclasses
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path

from quantumtrace.models import Finding, ScanError, SourceType
from quantumtrace.scanners.base import register
from quantumtrace.scanners.network import plaintext, purepy, ssh, tls_session, tshark
from quantumtrace.scanners.network.purepy import PureResult

NAME = "pcap"
EXTENSIONS = frozenset({".pcap", ".pcapng", ".cap"})

# purepy reads the whole file into memory; the second opinion is only worth its cost on small files.
CROSS_CHECK_MAX_BYTES = 32 * 1024 * 1024
PUREPY_MAX_BYTES = 256 * 1024 * 1024
MIN_CAPTURE_BYTES = 24  # the classic pcap global header; a pcapng section header is longer

_KINDS = ("tls", "ssh", "plaintext")


def _is_classic_pcap(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) in purepy._PCAP_MAGICS
    except OSError:
        return False


def _counts(result: PureResult) -> Counter[str]:
    counts: Counter[str] = Counter()
    for flow in result.flows:
        kind = "plaintext" if flow.kind in ("http", "plaintext") else flow.kind
        if kind in _KINDS:
            counts[kind] += 1
    return counts


def _clean(message: str, path: Path) -> str:
    """Messages name the capture by its file name, never by an absolute path."""
    return message.replace(str(path), path.name)


def _unique(messages: list[str]) -> list[str]:
    return list(dict.fromkeys(messages))


@register
class PcapScanner:
    name = NAME
    source_type = SourceType.PCAP

    def can_handle(self, path: Path) -> bool:
        """By extension only, no I/O: an unreadable or empty capture must reach scan()."""
        return Path(path).suffix.lower() in EXTENSIONS

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        path = Path(path)
        try:
            rel = tls_session.relative_posix(path, root)
        except Exception:
            rel = path.name
        try:
            out = self._scan(path, rel)
        except Exception as exc:
            out = [self._error(rel, f"pcap scan failed: {type(exc).__name__}")]
        yield from out

    # -- internals ----------------------------------------------------------------------------

    @staticmethod
    def _error(rel: str, message: str) -> ScanError:
        return ScanError(detector=tls_session.SCANNER, path=rel, message=message)

    def _scan(self, path: Path, rel: str) -> list[Finding | ScanError]:
        try:
            size = path.stat().st_size
        except OSError:
            return [self._error(rel, "capture cannot be read")]
        if size == 0:
            return [self._error(rel, "capture is empty")]
        if size < MIN_CAPTURE_BYTES:
            return [self._error(rel, "file is too short to be a capture")]

        result = self._parse(path, size)
        errors = [self._error(rel, message) for message in _unique(result.errors)]
        no_errors = dataclasses.replace(result, errors=[])

        out: list[Finding | ScanError] = list(errors)
        for label, build in (
            ("tls", lambda: tls_session.build_findings(no_errors, rel)),
            ("ssh", lambda: ssh.build_findings(no_errors, rel, parser_errors=False)),
            ("plaintext", lambda: plaintext.build_findings(no_errors, rel, parser_errors=False)),
        ):
            out.extend(self._build(label, build, rel))
        return out

    def _build(
        self, label: str, build: Callable[[], list[Finding | ScanError]], rel: str
    ) -> list[Finding | ScanError]:
        try:
            return list(build())
        except Exception as exc:
            return [self._error(rel, f"{label} findings failed: {type(exc).__name__}")]

    def _parse(self, path: Path, size: int) -> PureResult:
        """The authoritative ``PureResult`` with every message already path-free and deduplicated."""
        classic = _is_classic_pcap(path)
        if not tshark.tshark_available():
            result = self._purepy(path, size, missing_tshark=True)
            return self._finish(result, path)

        result = tshark.read_flows_tshark(path, timeout=tshark.DEFAULT_TIMEOUT)
        if result.errors and not result.flows:
            if classic and size <= PUREPY_MAX_BYTES:
                fallback = purepy.read_flows(path)
                if fallback.flows:
                    fallback.errors = [
                        *result.errors,
                        "tshark failed; flows come from the built-in parser",
                        *fallback.errors,
                    ]
                    return self._finish(fallback, path)
                result.errors = [*result.errors, *fallback.errors]
            return self._finish(result, path)

        if not result.errors and classic and size <= CROSS_CHECK_MAX_BYTES:
            # Also when tshark found nothing: a link type it cannot decode is a clean, empty run.
            result.errors.extend(self._second_opinion(result, purepy.read_flows(path)))
        return self._finish(result, path)

    @staticmethod
    def _purepy(path: Path, size: int, missing_tshark: bool) -> PureResult:
        if size > PUREPY_MAX_BYTES:
            res = PureResult()
            hint = "install tshark" if missing_tshark else "use tshark"
            res.errors.append(f"capture is too large for the built-in parser; {hint}")
            return res
        return purepy.read_flows(path)

    @staticmethod
    def _second_opinion(primary: PureResult, second: PureResult) -> list[str]:
        if second.errors:
            # With flows in hand the second parser merely could not read it all and there is nothing
            # to compare. Without any, its errors are the only evidence of an unreadable capture.
            return [] if primary.flows else list(second.errors)
        left, right = _counts(primary), _counts(second)
        return [
            f"parsers disagree on {kind} flows: tshark {left[kind]}, built-in parser {right[kind]}; "
            "tshark result used"
            for kind in _KINDS
            if left[kind] != right[kind]
        ]

    @staticmethod
    def _finish(result: PureResult, path: Path) -> PureResult:
        result.errors = _unique([_clean(message, path) for message in result.errors])
        return result
