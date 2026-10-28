"""The package version, read from one place: the installed distribution metadata.

`pyproject.toml` is the source. Four call sites used to restate it (two copies of
this helper, two hard-coded strings), and the hard-coded ones sat at 0.1.0 under
the v0.1.1 and v0.1.2 tags, so a released gate reported the wrong tool_version.
"""

from importlib.metadata import PackageNotFoundError, version

_DISTRIBUTION = "sec-recon-agent"


def package_version() -> str:
    try:
        return version(_DISTRIBUTION)
    except PackageNotFoundError:
        # A source tree that was never installed (no dist-info to read).
        return "0.0.0"
