"""Registration and evidence identity tests using local fake adapters."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from quantumtrace.models import Finding, Location, ScanError, ScanOptions, SourceType
from quantumtrace.scanners import base


@pytest.fixture(autouse=True)
def isolated_registry() -> Iterator[None]:
    """Restore global registrations after each test, including future adapters."""
    original = base.REGISTRY[:]
    base.REGISTRY.clear()
    yield
    base.REGISTRY[:] = original


class FixtureScanner:
    """Minimal adapter satisfying the shared protocol."""

    name = "fixture.z"
    source_type = SourceType.CODE
    instances = 0

    def __init__(self) -> None:
        type(self).instances += 1

    def can_handle(self, path: Path) -> bool:
        return path.suffix == ".fixture"

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        yield ScanError(detector=self.name, path=str(path.relative_to(root)), message="fixture error")


def test_decorator_returns_class_and_registers_one_instance() -> None:
    before = FixtureScanner.instances
    decorated = base.register(FixtureScanner)
    assert decorated is FixtureScanner
    assert FixtureScanner.instances == before + 1
    assert len(base.REGISTRY) == 1
    scanner = base.REGISTRY[0]
    assert scanner.can_handle(Path("input.fixture"))
    assert not scanner.can_handle(Path("input.txt"))
    assert isinstance(list(scanner.scan(Path("input.fixture"), Path(".")))[0], ScanError)


def test_duplicate_names_do_not_change_registry() -> None:
    base.register(FixtureScanner)
    original = base.REGISTRY[:]
    with pytest.raises(ValueError, match="duplicate scanner name: fixture.z"):
        base.register(FixtureScanner)
    assert base.REGISTRY == original


def test_registration_and_selection_order_do_not_depend_on_import_order() -> None:
    class EarlierScanner(FixtureScanner):
        name = "fixture.a"

    base.register(FixtureScanner)
    base.register(EarlierScanner)
    assert [scanner.name for scanner in base.REGISTRY] == ["fixture.a", "fixture.z"]
    assert [scanner.name for scanner in base.select_scanners()] == ["fixture.a", "fixture.z"]
    assert base.select_scanners([]) == []
    selected = ScanOptions(scanner_names=["fixture.z", "fixture.z", "fixture.a"])
    assert [scanner.name for scanner in base.select_scanners(selected.scanner_names)] == [
        "fixture.a",
        "fixture.z",
    ]


def test_unknown_requested_scanners_raise_explicit_error() -> None:
    base.register(FixtureScanner)
    options = ScanOptions(scanner_names=["missing.z", "fixture.z", "missing.a"])
    with pytest.raises(ValueError, match="unknown scanner names: missing.a, missing.z"):
        base.select_scanners(options.scanner_names)


def test_empty_registry_and_invalid_registration() -> None:
    assert base.select_scanners() == []
    with pytest.raises(ValueError, match="unknown scanner names"):
        base.select_scanners(["missing"])

    class InvalidScanner(FixtureScanner):
        name = " "

    with pytest.raises(ValueError, match="scanner name must be nonempty"):
        base.register(InvalidScanner)
    assert base.REGISTRY == []


def test_id_has_pinned_hash_and_empty_evidence_convention() -> None:
    location = Location(source_type=SourceType.CODE, file="src/a.py", line=7)
    # SHA1 of the fixed UTF-8 input: code.fixture|RSA|src/a.py|7|||
    assert base.finding_id("code.fixture", "RSA", location) == "baeac59f67a4"
    assert base.finding_id("code.fixture", "RSA", location) == base.finding_id(
        "code.fixture", "RSA", location
    )
    empty = Location(source_type=SourceType.CODE)
    assert base.finding_id("code.fixture", "RSA", empty) == base.finding_id(
        "code.fixture", "RSA", empty.model_copy(update={"file": ""})
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"file": "other.py"},
        {"line": 8},
        {"flow": "other flow"},
        {"frame": 2},
        {"resource_id": "other resource"},
    ],
)
def test_identity_changes_with_specified_evidence(changes: dict[str, str | int]) -> None:
    location = Location(source_type=SourceType.CODE, file="src/a.py", line=7)
    changed = Location.model_validate(location.model_dump() | changes)
    assert base.finding_id("fixture", "RSA", changed) != base.finding_id("fixture", "RSA", location)


def test_detector_and_raw_name_participate_but_metadata_does_not() -> None:
    location = Location(source_type=SourceType.CODE, file="src/a.py", line=7)
    original = base.finding_id("fixture", "RSA", location)
    assert base.finding_id("other", "RSA", location) != original
    assert base.finding_id("fixture", "AES", location) != original
    metadata = location.model_copy(
        update={"snippet": "different", "sni": "host", "source_type": SourceType.PCAP}
    )
    assert base.finding_id("fixture", "RSA", metadata) == original
    assert base.finding_id("fixture", "RSA", location.model_copy(update={"line": 0})) != base.finding_id(
        "fixture", "RSA", location.model_copy(update={"line": None})
    )


@pytest.mark.parametrize(
    "path",
    [
        "tests/a.py",
        "src/test/a.py",
        "examples/main.go",
        "mock/a.java",
        "mocks/a.py",
        "src/test_key.py",
        "src/key_test.py",
        "TESTS/a.py",
        "src/test-data/a.py",
        r"C:\repo\tests\a.py",
        "itest/misc/src/main/java/A.java",
        "web/src/integration-test/java/A.java",
        "test-support/a.py",
        "lib/testdata/key.go",
        "core/src/testFixtures/java/A.java",
        "pkg/conftest.py",
        "core/src/main/java/FooTests.java",
        "core/src/main/java/FooIT.java",
        "core/src/main/kotlin/FooTest.kt",
    ],
)
def test_test_paths_detect_conventional_segments(path: str) -> None:
    assert base.is_test_path(Path(path))


@pytest.mark.parametrize(
    "path",
    [
        "src/latest.py",
        "src/contest.py",
        "src/mockery.py",
        "src/examplecorp/a.py",
        "src/production.py",
        "src/testing/a.py",
        "src/main/java/Latest.java",
        "src/main/java/Contest.java",
        "src/main/java/TestUtils.java",
        "attestation/a.go",
        "src/main/python/FooTest.py",
    ],
)
def test_test_paths_do_not_match_unrelated_substrings(path: str) -> None:
    assert not base.is_test_path(path)
