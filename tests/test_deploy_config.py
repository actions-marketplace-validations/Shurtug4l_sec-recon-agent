"""Drift tests over the deployment wiring the code assumes.

The bearer gate on the MCP transport is a two-ended control: mcp-server
enforces it, agent-api's client presents it. Both read MCP_AUTH_TOKEN, so
docker-compose has to forward the variable to BOTH services or the control
cannot be enabled (the token reaches neither, or reaches the server alone
and the agent 401s on every tool call). These tests pin that wiring and the
operator-facing documentation of it.
"""

from pathlib import Path

import yaml
from _pytest.monkeypatch import MonkeyPatch

from sec_recon_agent.config import DEFAULT_MCP_ALLOWED_HOSTS, settings

ROOT = Path(__file__).resolve().parents[1]


def _compose_env(service: str) -> dict[str, str]:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    environment = compose["services"][service]["environment"]
    assert isinstance(environment, dict)
    return environment


def test_mcp_auth_token_reaches_both_ends_of_the_transport() -> None:
    for service in ("mcp-server", "agent-api"):
        env = _compose_env(service)
        assert "MCP_AUTH_TOKEN" in env, f"{service} does not receive MCP_AUTH_TOKEN"
        assert env["MCP_AUTH_TOKEN"] == "${MCP_AUTH_TOKEN:-}"


def test_mcp_allowed_hosts_reaches_the_server() -> None:
    assert _compose_env("mcp-server")["MCP_ALLOWED_HOSTS"] == "${MCP_ALLOWED_HOSTS:-}"


def test_env_example_documents_both_mcp_variables() -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "\nMCP_AUTH_TOKEN=" in text
    assert "\nMCP_ALLOWED_HOSTS=" in text
    # The stale claim the 2026-09-22 audit caught must not come back.
    assert "does NOT publish :8001" not in text


def test_allowed_hosts_blank_means_the_default(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mcp_allowed_hosts", "")
    assert settings.mcp_allowed_hosts_list == list(DEFAULT_MCP_ALLOWED_HOSTS)
    monkeypatch.setattr(settings, "mcp_allowed_hosts", " , ,")
    assert settings.mcp_allowed_hosts_list == list(DEFAULT_MCP_ALLOWED_HOSTS)


def test_allowed_hosts_parses_a_csv(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mcp_allowed_hosts", "recon.internal:*, 10.0.0.5:8001 ")
    assert settings.mcp_allowed_hosts_list == ["recon.internal:*", "10.0.0.5:8001"]


def test_run_bounds_are_operator_tunable_in_compose() -> None:
    env = _compose_env("agent-api")
    for name in (
        "AGENT_REQUEST_LIMIT",
        "AGENT_TOOL_CALLS_LIMIT",
        "AGENT_TOTAL_TOKENS_LIMIT",
        "TRIAGE_DEADLINE_SECONDS",
    ):
        assert name in env, f"agent-api does not receive {name}"


def test_blank_run_bounds_keep_the_defaults() -> None:
    """compose forwards an unset host variable as "". A safety bound that reads
    "" as "disabled" ships disabled by default, which is how the first cut of
    this wiring behaved inside the container; blank must mean default."""
    from sec_recon_agent.config import Settings

    blank = Settings(
        _env_file=None,
        agent_request_limit="",
        agent_tool_calls_limit="",
        agent_total_tokens_limit="",
        triage_deadline_seconds="",
    )
    assert blank.agent_request_limit == 25
    assert blank.agent_tool_calls_limit == 40
    assert blank.agent_total_tokens_limit == 250_000
    assert blank.triage_deadline_seconds == 300.0


def test_run_bounds_are_disabled_only_by_an_explicit_off() -> None:
    from sec_recon_agent.config import Settings

    off = Settings(
        _env_file=None,
        agent_tool_calls_limit="off",
        agent_total_tokens_limit="OFF",
        triage_deadline_seconds="none",
    )
    assert off.agent_tool_calls_limit is None
    assert off.agent_total_tokens_limit is None
    assert off.triage_deadline_seconds is None
    tuned = Settings(_env_file=None, agent_tool_calls_limit="12", triage_deadline_seconds="45.5")
    assert tuned.agent_tool_calls_limit == 12
    assert tuned.triage_deadline_seconds == 45.5
