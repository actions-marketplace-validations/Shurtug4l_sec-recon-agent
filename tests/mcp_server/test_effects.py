"""Tests for the per-tool effects table and the MCP annotations derived from it."""

import asyncio
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

from sec_recon_agent.mcp_server.effects import (
    TOOL_EFFECTS,
    ToolEffects,
    annotations_for,
    declared_tool,
)
from sec_recon_agent.mcp_server.nvd_client import NVD_BASE_URL
from sec_recon_agent.mcp_server.server import _register_tools, mcp
from sec_recon_agent.mcp_server.tools.epss import EPSS_API_URL, EPSS_TRUSTED_HOST
from sec_recon_agent.mcp_server.tools.exploits import (
    EXPLOITDB_CSV_URL,
    EXPLOITDB_TRUSTED_HOST,
    GITHUB_REPOS_URL,
    GITHUB_SEARCH_URL,
)
from sec_recon_agent.mcp_server.tools.kev import KEV_CATALOG_URL, KEV_TRUSTED_HOST
from sec_recon_agent.mcp_server.tools.osv import OSV_API_URL, OSV_TRUSTED_HOST

EGRESS_FILTER = Path(__file__).resolve().parents[2] / "deploy" / "egress-proxy" / "filter"


def _served_tools() -> dict[str, object]:
    _register_tools()
    return {tool.name: tool.annotations for tool in asyncio.run(mcp.list_tools())}


def test_effects_table_matches_the_served_tool_set() -> None:
    # Exact set both ways: an undeclared tool fails at import, a stale entry here.
    assert set(_served_tools()) == set(TOOL_EFFECTS)


def test_served_annotations_are_derived_from_the_effects_table() -> None:
    for name, annotations in _served_tools().items():
        assert annotations == annotations_for(TOOL_EFFECTS[name]), name


def test_declared_tool_refuses_an_undeclared_function() -> None:
    def undeclared_tool() -> None:
        pass

    with pytest.raises(KeyError, match="undeclared_tool"):
        declared_tool()(undeclared_tool)


def test_read_only_tool_annotations() -> None:
    annotations = annotations_for(
        ToolEffects((), writes_server_cache=True, mutates_external_state=False)
    )
    assert annotations.readOnlyHint is True
    assert annotations.destructiveHint is False
    assert annotations.idempotentHint is True
    assert annotations.openWorldHint is False


def test_mutating_tool_annotations_fail_toward_destructive() -> None:
    annotations = annotations_for(
        ToolEffects(("example.org",), writes_server_cache=False, mutates_external_state=True)
    )
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is True
    assert annotations.idempotentHint is False
    assert annotations.openWorldHint is True


def test_no_tool_mutates_external_state() -> None:
    # Pins the read-only posture mcp_self_audit.md and owasp_llm_top10.md claim.
    assert [name for name, e in TOOL_EFFECTS.items() if e.mutates_external_state] == []


def _egress_filter_rules() -> list[str]:
    lines = EGRESS_FILTER.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


@pytest.mark.parametrize(
    ("tool", "url"),
    [
        ("cve_lookup", NVD_BASE_URL),
        ("patch_lookup", NVD_BASE_URL),
        ("epss_score", EPSS_API_URL),
        ("kev_check", KEV_CATALOG_URL),
        ("exploit_check", EXPLOITDB_CSV_URL),
        ("exploit_check", GITHUB_SEARCH_URL),
        ("exploit_check", GITHUB_REPOS_URL),
        ("osv_lookup", OSV_API_URL),
    ],
)
def test_called_urls_are_declared_and_allowed_by_the_egress_proxy(tool: str, url: str) -> None:
    # Ties the three inventories together: the URL the tool calls, its declared
    # hosts, and the opt-in egress allowlist. A new outbound call in a tool is
    # still caught only in review.
    host = urlparse(url).hostname or ""
    declared = TOOL_EFFECTS[tool].network_hosts
    assert any(host == d or host.endswith("." + d) for d in declared), (tool, host)
    assert any(re.search(rule, host, re.IGNORECASE) for rule in _egress_filter_rules()), host


@pytest.mark.parametrize(
    ("tool", "host_lock"),
    [
        ("epss_score", EPSS_TRUSTED_HOST),
        ("kev_check", KEV_TRUSTED_HOST),
        ("exploit_check", EXPLOITDB_TRUSTED_HOST),
        ("osv_lookup", OSV_TRUSTED_HOST),
    ],
)
def test_declared_hosts_track_the_host_lock_constants(tool: str, host_lock: str) -> None:
    assert host_lock in TOOL_EFFECTS[tool].network_hosts
