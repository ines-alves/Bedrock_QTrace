"""Smoke checks for the installed project foundation."""

import json
from importlib.metadata import version

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

import quantumtrace


def test_installed_version_matches_package() -> None:
    """The editable distribution exposes the same version as its import."""
    assert quantumtrace.__version__ == "0.1.0"
    assert version("quantumtrace") == quantumtrace.__version__


def test_packaged_cyclonedx_dependency_supports_strict_json_validation() -> None:
    """Installed validation dependencies accept valid data and reject unknown fields."""
    validator = JsonStrictValidator(SchemaVersion.V1_6)
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
    assert validator.validate_str(json.dumps(document)) is None
    assert validator.validate_str(json.dumps(document | {"unexpected": True})) is not None
