"""Pydantic AI triage agent.

Wires the ten MCP tools (cve_lookup, cve_semantic_search, exploit_check,
kev_check, epss_score, patch_lookup, osv_lookup, sbom_ingest,
nmap_parse_xml, attack_mapping) into a single agent that emits a typed
TriageReport.

The MCP transport is HTTP+SSE; SSE is inferred from the `/sse` URL suffix.
The agent connects to the sec-recon MCP server (default :8001). Caller is
responsible for entering `agent.run_toolsets()` before invoking
`agent.run(...)`, or using `agent.iter(...)` which manages it implicitly.
"""

import os

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset
from pydantic_ai.models.anthropic import AnthropicModelSettings

from sec_recon_agent.agent.prompts import SYSTEM_PROMPT
from sec_recon_agent.agent.schema import TriageReport
from sec_recon_agent.config import settings


def export_anthropic_api_key_to_env() -> None:
    """Move ANTHROPIC_API_KEY from pydantic-settings into os.environ.

    Pydantic AI's Anthropic provider reads the key from os.environ rather
    than from our Settings object. We push it once at process startup
    (called from `api/stream.py::main` and `mcp_server/server.py::main`)
    so SecretStr leaks the secret only at the latest moment possible.
    Do NOT call this from request handlers.
    """
    if settings.anthropic_api_key and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = settings.anthropic_api_key.get_secret_value()


# Allowlist of LLM model identifiers the API will honor when a per-request
# override is supplied via TriageRequest.model. Keeping it explicit prevents
# (a) accidentally pointing the agent at an unintended provider or sandbox
# model via a body param, and (b) the comparison eval suite from being
# weaponized as a probe for arbitrary model strings.
ALLOWED_MODELS: frozenset[str] = frozenset(
    {
        "claude-haiku-4-5-20251001",
        "claude-sonnet-4-6",
        "claude-opus-4-7",
    },
)

# Short aliases the eval CLI can pass in place of the full identifier.
MODEL_ALIASES: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-6",
    "opus": "claude-opus-4-7",
}


def resolve_model(override: str | None) -> str:
    """Return the model identifier to use for one triage call.

    `override` may be:
      - None: use settings.llm_model (the default for the deployment);
      - a short alias (haiku / sonnet / opus): expand via MODEL_ALIASES;
      - a full identifier: must appear in ALLOWED_MODELS.

    Any other value raises ValueError; the API surface translates that
    into HTTP 400.
    """
    if override is None:
        return settings.llm_model
    candidate = MODEL_ALIASES.get(override, override)
    if candidate not in ALLOWED_MODELS:
        raise ValueError(
            f"model {override!r} is not on the allowlist; choose one of {sorted(ALLOWED_MODELS)}",
        )
    return candidate


def mcp_client_headers() -> dict[str, str] | None:
    """HTTP headers the agent's MCP client sends, or None when the gate is off.

    The transport crosses a container boundary (agent-api -> mcp-server), so
    when the server is gated by MCP_AUTH_TOKEN this client has to present the
    same secret on every request; without the header the SSE handshake is
    refused with 401 and no tool is reachable. Both processes read the token
    from the same setting, so enabling the gate is one variable, not a code
    change on either side. A blank token means off on both ends: compose
    forwards the variable as an empty string when the operator left it unset.
    """
    token = settings.mcp_auth_token
    if token is None or not token.get_secret_value():
        return None
    return {"Authorization": f"Bearer {token.get_secret_value()}"}


def _mcp_toolset() -> MCPToolset:
    """The HTTP+SSE toolset for the co-deployed MCP server."""
    return MCPToolset(f"{settings.mcp_server_url}/sse", headers=mcp_client_headers())


# Prompt caching. Every round of the ReAct loop re-sends the whole
# conversation: the system prompt, the eleven tool schemas, the output schema
# and every earlier tool return. On the recorded golden runs 74% of the billed
# input was that re-sent prefix (log4shell: 102,652 input tokens billed for a
# final context of 26,170). Three breakpoints, out of Anthropic's four:
# instructions, tool definitions, and the automatic one that follows the
# conversation as it grows, so round n reads rounds 1..n-1 from cache.
# Cache reads are priced at a tenth of input, writes at 1.25x (eval/cost.py
# carves both out of the total input pydantic-ai reports); the budget rail
# therefore charges what is actually billed.
CACHING_MODEL_SETTINGS = AnthropicModelSettings(
    anthropic_cache=True,
    anthropic_cache_instructions=True,
    anthropic_cache_tool_definitions=True,
)


def build_agent(model_override: str | None = None) -> Agent[None, TriageReport]:
    """Construct the triage agent wired to the local MCP server.

    The Anthropic API key must already be in os.environ when this is
    invoked (see `export_anthropic_api_key_to_env`). Building the agent
    inside a request handler is fine; exporting the secret per request
    is not.

    `model_override` lets one request bypass `settings.llm_model` (the
    deployment default) in favor of a specific Anthropic model. The
    override goes through `resolve_model` which enforces an allowlist.
    """
    model = resolve_model(model_override)

    return Agent(
        model=f"{settings.llm_provider}:{model}",
        output_type=TriageReport,
        toolsets=[_mcp_toolset()],
        system_prompt=SYSTEM_PROMPT,
        model_settings=CACHING_MODEL_SETTINGS,
    )
