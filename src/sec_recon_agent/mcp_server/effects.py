"""Declared side effects per MCP tool, the single source of the tool annotations.

Every tool registers through `declared_tool`, which looks its effects up by
function name and fails at import time when the entry is missing: a tool
cannot be served without stating what it touches. The MCP annotations
(`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) are
derived from the entry, never written by hand, so the hints a client uses to
gate approvals cannot drift from the declared behavior.

Annotations are client-side metadata: pydantic-ai does not forward them to
the model, and they are outside the record-replay staleness hash
(`eval/cassette.py::llm_surface`).
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from mcp.types import ToolAnnotations

from sec_recon_agent.mcp_server.server import mcp

F = TypeVar("F", bound=Callable[..., Any])


@dataclass(frozen=True)
class ToolEffects:
    # No defaults: each entry states every effect explicitly.
    # An exact host, or a host-lock domain whose subdomains the tool accepts
    # after a redirect (cisa.gov covers www.cisa.gov).
    network_hosts: tuple[str, ...]
    # Fixed-path state the server owns (KEV / Exploit-DB manifests, the Chroma
    # index). Declared for the audit, but it does not change the caller's
    # environment, so it does not clear readOnlyHint.
    writes_server_cache: bool
    # Any write outside that server-owned state: remote APIs, messages, and
    # local paths the caller influences. True clears readOnlyHint.
    mutates_external_state: bool


TOOL_EFFECTS: dict[str, ToolEffects] = {
    "attack_mapping": ToolEffects((), writes_server_cache=False, mutates_external_state=False),
    "cve_lookup": ToolEffects(
        ("services.nvd.nist.gov",), writes_server_cache=False, mutates_external_state=False
    ),
    # Local index only: a cold volume creates the Chroma dir and collection.
    # The ONNX embedding model is baked into the image (Dockerfile); a cold
    # non-Docker cache fetches it once, outside the tool's own domain.
    "cve_semantic_search": ToolEffects((), writes_server_cache=True, mutates_external_state=False),
    "epss_score": ToolEffects(
        ("api.first.org",), writes_server_cache=False, mutates_external_state=False
    ),
    "exploit_check": ToolEffects(
        ("gitlab.com", "api.github.com"), writes_server_cache=True, mutates_external_state=False
    ),
    "kev_check": ToolEffects(("cisa.gov",), writes_server_cache=True, mutates_external_state=False),
    "nmap_parse_xml": ToolEffects((), writes_server_cache=False, mutates_external_state=False),
    "osv_lookup": ToolEffects(
        ("api.osv.dev",), writes_server_cache=False, mutates_external_state=False
    ),
    "patch_lookup": ToolEffects(
        ("services.nvd.nist.gov",), writes_server_cache=False, mutates_external_state=False
    ),
    "sbom_ingest": ToolEffects((), writes_server_cache=False, mutates_external_state=False),
}


def annotations_for(effects: ToolEffects) -> ToolAnnotations:
    mutates = effects.mutates_external_state
    return ToolAnnotations(
        readOnlyHint=not mutates,
        destructiveHint=mutates,
        idempotentHint=not mutates,
        openWorldHint=bool(effects.network_hosts),
    )


def declared_tool() -> Callable[[F], F]:
    """`@mcp.tool()` with annotations derived from the tool's TOOL_EFFECTS entry.

    Raises KeyError at import for an undeclared tool, so the server never
    starts with one.
    """

    def decorator(fn: F) -> F:
        name = fn.__name__
        if name not in TOOL_EFFECTS:
            raise KeyError(f"MCP tool {name!r} has no TOOL_EFFECTS entry in effects.py")
        mcp.tool(annotations=annotations_for(TOOL_EFFECTS[name]))(fn)
        return fn

    return decorator
