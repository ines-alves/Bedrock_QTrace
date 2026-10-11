"""Scanner protocol, deterministic registration, and evidence helpers."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, TypeVar

from quantumtrace.models import Finding, Location, ScanError, SourceType


class Scanner(Protocol):
    """Pure detection adapter; failures are yielded as ScanError entries."""

    name: str
    source_type: SourceType

    def can_handle(self, path: Path) -> bool:
        """Return whether this adapter accepts the input path."""
        ...

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        """Yield raw findings and recoverable errors with root-relative evidence."""
        ...


REGISTRY: list[Scanner] = []
ScannerT = TypeVar("ScannerT", bound=Scanner)


def register(scanner_class: type[ScannerT]) -> type[ScannerT]:
    """Register one no-argument instance and return the original decorated class."""
    scanner = scanner_class()
    if not scanner.name or not scanner.name.strip():
        raise ValueError("scanner name must be nonempty")
    if any(existing.name == scanner.name for existing in REGISTRY):
        raise ValueError(f"duplicate scanner name: {scanner.name}")
    REGISTRY.append(scanner)
    REGISTRY.sort(key=lambda item: item.name)
    return scanner_class


def select_scanners(scanner_names: list[str] | None = None) -> list[Scanner]:
    """Select registered adapters by name, rejecting unknown requested names."""
    available = {scanner.name for scanner in REGISTRY}
    if scanner_names is not None:
        unknown = sorted(set(scanner_names) - available)
        if unknown:
            raise ValueError(f"unknown scanner names: {', '.join(unknown)}")
        selected = set(scanner_names)
    else:
        selected = available
    return sorted((scanner for scanner in REGISTRY if scanner.name in selected), key=lambda item: item.name)


def finding_id(detector: str, raw_name: str, loc: Location) -> str:
    """Hash detector|raw_name|file|line|flow|frame|resource_id to 12 hex characters.

    Missing evidence fields serialize as empty strings. SHA1 is used for stable
    identity only; timestamps and other metadata do not participate in the hash.
    """
    values = (detector, raw_name, loc.file, loc.line, loc.flow, loc.frame, loc.resource_id)
    content = "|".join("" if value is None else str(value) for value in values)
    return hashlib.sha1(content.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


# Test layouts beyond test/tests: integration-test source sets (Gradle/Maven), itest modules, Go
# testdata, Gradle testFixtures and pytest conftest.py (outside validation F9).
_TEST_SEGMENTS = re.compile(
    r"(?:tests?|examples?|mocks?)(?:[_-].+)?|itests?|integration[_-]?tests?|testdata|test[_-]?fixtures|conftest"
)
# JUnit/TestNG class files: FooTest, FooTests, FooIT, FooTestCase (case-sensitive, so "latest" or
# "Contest" never match).
_JVM_TEST_CLASS = re.compile(r"[A-Za-z0-9_]+(?:Test|Tests|IT|TestCase)\.(?:java|kt|groovy|scala)")


def is_test_path(path: str | Path) -> bool:
    """Identify test/example/mock segments and conventional Python, Go and JVM test filenames."""
    for segment in str(path).replace("\\", "/").split("/"):
        stem = (
            segment.lower().rsplit(".", 1)[0]
            if "." in segment and not segment.startswith(".")
            else segment.lower()
        )
        if _TEST_SEGMENTS.fullmatch(stem):
            return True
        if stem.endswith("_test") or _JVM_TEST_CLASS.fullmatch(segment):
            return True
    return False
