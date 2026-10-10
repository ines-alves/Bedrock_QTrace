"""Smoke checks for the installed project foundation."""

from importlib.metadata import version

import quantumtrace


def test_installed_version_matches_package() -> None:
    """The editable distribution exposes the same version as its import."""
    assert quantumtrace.__version__ == "0.1.0"
    assert version("quantumtrace") == quantumtrace.__version__
