"""The version has one source. These fail when a call site restates it again."""

import tomllib
from pathlib import Path

from sec_recon_agent.api.stream import app
from sec_recon_agent.version import package_version

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_installed_version_matches_pyproject() -> None:
    declared = tomllib.loads(_PYPROJECT.read_text())["project"]["version"]
    assert package_version() == declared


def test_api_reports_the_package_version() -> None:
    assert app.version == package_version()
