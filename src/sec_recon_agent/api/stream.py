"""FastAPI surface for the triage agent.

Endpoints:
- POST /v1/triage: streams agent progress over Server-Sent Events. Emits
  a `started` event, one `node` event per agent step (model request,
  tool call, tool result), and a final `final` event carrying the
  TriageReport JSON.
- GET /v1/health: liveness probe.
- GET /v1/meta: exposes the system prompt and the tool inventory so the
  UI's transparency view can show what the agent is told and what it can
  reach. Read-only, no auth, single-tenant demo.
- POST /v1/export/{sarif,openvex}: stateless render of an
  already-produced TriageReport into SARIF 2.1.0 / OpenVEX v0.2.0 via
  the pure functions in export/.

The agent reaches the MCP server over its own HTTP+SSE connection; the
API process and the MCP server are independent.
"""

import asyncio
import hmac
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sec_recon_agent.audit.models import TriageEvent

import structlog
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sse_starlette.sse import EventSourceResponse
from starlette.responses import JSONResponse

from sec_recon_agent.agent.prompts import SYSTEM_PROMPT
from sec_recon_agent.agent.schema import TriageReport
from sec_recon_agent.agent.triage import build_agent, export_anthropic_api_key_to_env, resolve_model
from sec_recon_agent.api.budget import budget_tracker
from sec_recon_agent.config import settings
from sec_recon_agent.eval.cost import estimate_cost_usd
from sec_recon_agent.export.openvex import DEFAULT_AUTHOR, ProductIdentityError, to_openvex
from sec_recon_agent.export.sarif import to_sarif
from sec_recon_agent.mcp_server.errors import CveNotFoundError
from sec_recon_agent.observability import setup_tracing
from sec_recon_agent.version import package_version

# Exceptions whose string form is safe to surface to the SSE client.
# Everything else is replaced with a generic message: internal exception
# messages can leak filesystem paths, query parameters, or library
# internals that the client should not see.
_SAFE_TO_ECHO: tuple[type[BaseException], ...] = (CveNotFoundError,)

log = structlog.get_logger()

app = FastAPI(
    title="sec-recon-agent",
    description="Type-safe security triage via Pydantic AI + MCP.",
    version=package_version(),
)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
# Two accepted carriers: `Authorization: Bearer <key>` (the canonical form for
# API keys behind a reverse proxy) and `X-API-Key: <key>` (convenient for
# curl tests). Both go through the same allowlist + constant-time compare.
# When no API keys are configured, the dependency is a no-op so local
# development does not need ceremony.

_bearer_scheme = HTTPBearer(auto_error=False)
_x_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


def _candidate_keys(
    bearer: HTTPAuthorizationCredentials | None,
    x_api_key: str | None,
) -> list[str]:
    keys: list[str] = []
    if bearer is not None and bearer.scheme.lower() == "bearer":
        keys.append(bearer.credentials)
    if x_api_key:
        keys.append(x_api_key)
    return keys


def _key_matches_allowlist(presented: str) -> bool:
    """Constant-time comparison against every configured key."""
    presented_bytes = presented.encode("utf-8")
    found = False
    for stored in settings.api_keys:
        # Compare every entry even after a match — keeps the timing flat.
        if hmac.compare_digest(presented_bytes, stored.get_secret_value().encode("utf-8")):
            found = True
    return found


async def verify_api_key(
    bearer: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    x_api_key: str | None = Depends(_x_api_key_scheme),
) -> None:
    """No-op when `settings.api_keys` is empty; otherwise requires one of
    the configured keys via Bearer or X-API-Key header."""
    if not settings.api_keys:
        return
    for presented in _candidate_keys(bearer, x_api_key):
        if _key_matches_allowlist(presented):
            return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing or invalid API key",
        headers={"WWW-Authenticate": 'Bearer realm="sec-recon-agent"'},
    )


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# Per-IP using slowapi. When `settings.rate_limit_per_minute` is falsy we
# install the limiter but use a string that effectively never trips, so
# the dependency wiring stays uniform between dev and production.


def _rate_limit_string() -> str:
    rate = settings.rate_limit_per_minute or 0
    if rate <= 0:
        return "1000000/minute"  # effectively unlimited
    return f"{rate}/minute"


limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_exceeded_handler(_request: Request, _exc: RateLimitExceeded) -> JSONResponse:
    # Generic message — never echo the configured limit upstream; the
    # specific limit is operational info that does not belong in client
    # responses.
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "rate limit exceeded"},
    )


# ---------------------------------------------------------------------------
# Operational safety rails (S4)
# ---------------------------------------------------------------------------
# Two guards in front of /v1/triage, both refusing with 503 *before* the agent
# is built (no LLM spend on a refused request):
# - Kill-switch: an env flag OR a sentinel file, checked per request, so an
#   operator can disable the service live without a redeploy.
# - Denial-of-wallet: a rolling-window cap on estimated LLM spend (api/budget).
# The messages are deliberately generic; the configured ceiling and the switch
# mechanism are operational details that do not belong in client responses.


def _kill_switch_engaged() -> bool:
    if settings.kill_switch:
        return True
    path = settings.kill_switch_file
    return bool(path and path.exists())


async def enforce_operational_limits() -> None:
    """Dependency guarding the triage endpoint. Raises 503 when the service is
    disabled or the rolling budget is exhausted."""
    if _kill_switch_engaged():
        log.warning("triage_refused_kill_switch")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Triage is temporarily disabled.",
        )
    if await budget_tracker.would_block():
        log.warning("triage_refused_budget_exhausted")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Triage is temporarily unavailable; try again later.",
        )


class TriageRequest(BaseModel):
    # Cap is generous to absorb pasted SBOMs (CycloneDX/SPDX can easily
    # hit tens of KB) while still bounding the worst case for both DoS
    # and LLM token cost. Tool-level caps (e.g. sbom_ingest's 5 MB,
    # cve_semantic_search's truncation at 1000 chars) provide the
    # downstream safety net.
    query: str = Field(min_length=1, max_length=100_000)
    # Optional per-request LLM override. Subject to the allowlist in
    # agent/triage.py::ALLOWED_MODELS (plus haiku/sonnet/opus aliases).
    # Used by sec-recon-eval --model for differential evaluation; the
    # frontend never sets it.
    model: str | None = Field(default=None, max_length=64)


@app.get("/v1/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


class ToolMeta(BaseModel):
    name: str
    description: str


class MetaResponse(BaseModel):
    system_prompt: str
    model: str
    tools: list[ToolMeta]


@app.get("/v1/meta", response_model=MetaResponse, dependencies=[Depends(verify_api_key)])
async def meta() -> MetaResponse:
    """Expose the agent's "what is it told" and "what can it reach" so a
    transparency UI can render them. The system prompt is the literal
    string the LLM receives. The tool list is curated here, not introspected
    from the MCP server: the tools are part of the project contract,
    not a runtime discovery (which would couple this endpoint to live MCP
    connectivity)."""
    return MetaResponse(
        system_prompt=SYSTEM_PROMPT,
        model=f"{settings.llm_provider}:{settings.llm_model}",
        tools=[
            ToolMeta(
                name="cve_lookup",
                description=(
                    "Fetch the full NVD record for a known CVE ID. "
                    "Returns CVSS v3 score and severity, CWE IDs, affected "
                    "CPEs, references."
                ),
            ),
            ToolMeta(
                name="cve_semantic_search",
                description=(
                    "Vector search over an indexed corpus of recent "
                    "high-severity CVEs. Use when the user describes a "
                    "product or symptom without naming a CVE."
                ),
            ),
            ToolMeta(
                name="exploit_check",
                description=(
                    "Look up public exploits and PoCs for a CVE. Queries "
                    "Exploit-DB and GitHub Code Search in parallel."
                ),
            ),
            ToolMeta(
                name="kev_check",
                description=(
                    "Check whether a CVE is on the CISA Known Exploited "
                    "Vulnerabilities catalog. Strongest 'patch now' signal "
                    "with federal due date and known-ransomware flag."
                ),
            ),
            ToolMeta(
                name="epss_score",
                description=(
                    "Fetch the FIRST.org EPSS probability that a CVE will "
                    "be exploited in the next 30 days, plus percentile "
                    "rank. Complements KEV for forward-looking prioritization."
                ),
            ),
            ToolMeta(
                name="patch_lookup",
                description=(
                    "Return the fixed-version information NVD declares "
                    "for a CVE: per affected CPE, the smallest version "
                    "where the fix landed plus any version-range start. "
                    "Pairs with cve_lookup when recommended_action needs "
                    "to cite a concrete release."
                ),
            ),
            ToolMeta(
                name="osv_lookup",
                description=(
                    "Inverse of cve_lookup: given a package at a version "
                    "(PyPI / npm / Go / Maven / crates.io / NuGet / "
                    "RubyGems), return every OSV.dev advisory that applies, "
                    "with CVE / GHSA aliases and the fixed version. Use when "
                    "the user names a dependency and version, not a CVE."
                ),
            ),
            ToolMeta(
                name="sbom_ingest",
                description=(
                    "Parse a CycloneDX / SPDX / requirements.txt SBOM "
                    "into a normalized list of components with name, "
                    "version, ecosystem, purl. Pairs with cve_semantic_"
                    "search for per-component triage."
                ),
            ),
            ToolMeta(
                name="nmap_parse_xml",
                description=(
                    "Parse Nmap XML scan output into structured hosts, "
                    "ports, services, and version banners. defusedxml-safe."
                ),
            ),
            ToolMeta(
                name="attack_mapping",
                description=(
                    "Map a list of CWE IDs to MITRE ATT&CK techniques and "
                    "their mitigations. Enriches the triage with "
                    "adversary-side context and defense-side guidance."
                ),
            ),
        ],
    )


# Upper bound on rows returned in one /v1/audit call: bounds the payload and
# stops a caller pulling an unbounded history in a single request.
_AUDIT_TAIL_MAX = 200


class AuditRow(BaseModel):
    """One audit-trail row as exposed over HTTP: the digest-only projection of
    a TriageEvent. The plaintext fields (query_plain / report_summary_plain)
    are deliberately absent - see the /v1/audit docstring."""

    event_id: str
    ts: str
    query_sha256: str
    query_length: int
    report_sha256: str
    severity: str | None
    confidence: str | None
    cves_count: int
    attack_techniques_count: int
    kev_hits: int
    ransomware_hits: int
    high_epss_hits: int
    ssvc_decision: str | None
    grounding_status: str | None
    model: str
    duration_ms: int
    outcome: str
    error_class: str | None
    prev_event_hash: str
    this_event_hash: str


class AuditVerification(BaseModel):
    """Live result of walking the hash chain. `ok` false means the chain broke;
    `broken_event_id` names the first tampered row."""

    ok: bool
    verified_count: int
    broken_event_id: str | None = None


class AuditResponse(BaseModel):
    enabled: bool
    count: int
    verification: AuditVerification
    events: list[AuditRow]  # most-recent-first, capped at the requested limit


def _to_audit_row(event: "TriageEvent") -> AuditRow:
    # Explicit field copy, not model_dump: it guarantees the plaintext fields
    # can never leak through this projection even if TriageEvent grows more.
    return AuditRow(
        event_id=event.event_id,
        ts=event.ts,
        query_sha256=event.query_sha256,
        query_length=event.query_length,
        report_sha256=event.report_sha256,
        severity=event.severity,
        confidence=event.confidence,
        cves_count=event.cves_count,
        attack_techniques_count=event.attack_techniques_count,
        kev_hits=event.kev_hits,
        ransomware_hits=event.ransomware_hits,
        high_epss_hits=event.high_epss_hits,
        ssvc_decision=event.ssvc_decision,
        grounding_status=event.grounding_status,
        model=event.model,
        duration_ms=event.duration_ms,
        outcome=event.outcome,
        error_class=event.error_class,
        prev_event_hash=event.prev_event_hash,
        this_event_hash=event.this_event_hash,
    )


@app.get("/v1/audit", response_model=AuditResponse, dependencies=[Depends(verify_api_key)])
async def audit(limit: int = 50) -> AuditResponse:
    """Read-only view of the tamper-evident triage audit trail: the most recent
    rows (digest-only) plus a live hash-chain verification.

    Minimal-disclosure by construction: even when plaintext retention is enabled
    in the database (AUDIT_INCLUDE_QUERY / AUDIT_INCLUDE_SUMMARY), this endpoint
    never returns the plaintext. Retention on local disk and exposure over HTTP
    are different trust boundaries; the plaintext stays reachable only via the
    local `sec-recon-audit` CLI against the DB file. A detected break is
    reported as `verification.ok = false` (not a 500), because surfacing tamper
    is the endpoint's whole point."""
    limit = max(1, min(limit, _AUDIT_TAIL_MAX))
    if not settings.audit_log_enabled:
        return AuditResponse(
            enabled=False,
            count=0,
            verification=AuditVerification(ok=True, verified_count=0),
            events=[],
        )
    from sec_recon_agent.audit.store import TamperDetectedError

    store = _get_audit_store()
    try:
        verified = store.verify()
        verification = AuditVerification(ok=True, verified_count=verified)
    except TamperDetectedError as exc:
        verification = AuditVerification(ok=False, verified_count=0, broken_event_id=exc.event_id)
    events = [_to_audit_row(e) for e in store.tail(limit)]
    return AuditResponse(
        enabled=True,
        count=store.count(),
        verification=verification,
        events=events,
    )


class ExportSarifRequest(BaseModel):
    report: TriageReport
    # Repo-relative path (or stable identifier) GitHub code scanning
    # attaches the alerts to, e.g. the SBOM or report file that produced
    # the triage.
    artifact_uri: str = Field(default="triage-report.json", min_length=1, max_length=500)


class ExportOpenVexRequest(BaseModel):
    report: TriageReport
    # purl(s) of the triaged product. Required: a standalone OpenVEX
    # statement without products is invalid, and product identity is
    # never guessed from the report.
    products: list[str] = Field(min_length=1, max_length=50)
    author: str = Field(default=DEFAULT_AUTHOR, min_length=1, max_length=200)


@app.post("/v1/export/sarif", dependencies=[Depends(verify_api_key)])
async def export_sarif(body: ExportSarifRequest) -> JSONResponse:
    """Stateless render of an already-produced TriageReport into SARIF
    2.1.0. Pure CPU transform of a schema-bounded body, so it goes
    unthrottled like /v1/meta; the report was validated by FastAPI on the
    way in."""
    return JSONResponse(content=to_sarif(body.report, artifact_uri=body.artifact_uri))


@app.post("/v1/export/openvex", dependencies=[Depends(verify_api_key)])
async def export_openvex(body: ExportOpenVexRequest) -> JSONResponse:
    """Stateless render into an OpenVEX v0.2.0 document. 422 when the
    supplied product identifiers are not purls."""
    try:
        doc = to_openvex(
            body.report,
            products=body.products,
            timestamp=datetime.now(UTC),
            author=body.author,
        )
    except ProductIdentityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return JSONResponse(content=doc)


@app.post(
    "/v1/triage",
    dependencies=[Depends(verify_api_key), Depends(enforce_operational_limits)],
)
@limiter.limit(_rate_limit_string)
async def triage(request: Request, req: TriageRequest) -> EventSourceResponse:
    """Run the triage agent and stream progress as SSE events."""
    # `request` is unused inside the body but slowapi needs it as the
    # first parameter to read the client address. Silence the linter.
    del request
    return EventSourceResponse(_triage_events(req))


async def _triage_events(req: TriageRequest) -> AsyncIterator[dict[str, Any]]:
    """The SSE event stream for one triage.

    Module-level rather than a closure inside the route so tests can drive it
    directly and close it mid-stream, which is exactly what a client
    disconnect looks like from inside the generator.

    Accounting invariant: whatever the run consumed is charged to the
    denial-of-wallet window and sealed into the audit trail on EVERY exit
    path (final event delivered, agent error, usage bound hit, deadline hit,
    client disconnect), never only on the happy path. A client that aborts
    the connection one round before completion is billed by the provider in
    full; a rail that recorded nothing for it would be defeated by the
    cheapest client behaviour there is.
    """
    try:
        agent = build_agent(model_override=req.model)
    except ValueError as exc:
        # Bad model override -> emit one error event and bail.
        yield {"event": "started", "data": req.model_dump_json()}
        yield {
            "event": "error",
            "data": _error_payload(exc, safe_message=str(exc)),
        }
        return
    # build_agent validated the override; resolve it once so the cost
    # estimate and the audit row name the model the run actually used.
    model_id = f"{settings.llm_provider}:{resolve_model(req.model)}"
    yield {"event": "started", "data": req.model_dump_json()}

    started_at = time.monotonic()
    # "incomplete" until the final event is on the wire: an exit that never
    # reaches that line must not seal into the audit chain as a success.
    outcome = "incomplete"
    error_class: str | None = None
    result_json: str | None = None
    run_ref: Any = None
    # Wall-clock bound on the run; asyncio.timeout(None) is a no-op deadline.
    deadline = asyncio.timeout(settings.triage_deadline_seconds)
    try:
        # Bound rounds, tool calls and tokens independently: Anthropic models
        # batch several tool calls per turn, so rounds alone bound neither,
        # and tokens are the cost driver since every round re-sends the whole
        # conversation. UsageLimitExceeded is raised before the over-budget
        # request and handled cleanly below.
        limits = UsageLimits(
            request_limit=settings.agent_request_limit,
            tool_calls_limit=settings.agent_tool_calls_limit,
            total_tokens_limit=settings.agent_total_tokens_limit,
        )
        async with deadline, agent.iter(req.query, usage_limits=limits) as run:
            run_ref = run
            async for node in run:
                yield {
                    "event": "node",
                    "data": _node_event_payload(node),
                }
            result_output = run.result.output  # type: ignore[union-attr]
            messages = _extract_messages(run)
        # Stamp the deterministic verdicts onto the report AFTER the model
        # returns. The LLM is told to leave `ssvc` and `grounding` null;
        # both are computed from the captured trajectory (what the tools
        # returned), not from the fields the model wrote, and they are the
        # authoritative, reproducible forms the audit trail records.
        invocations = _invocations_for(messages)
        result_output = result_output.model_copy(
            update={
                "ssvc": _ssvc_for(result_output, invocations),
                "grounding": _grounding_for(result_output, invocations),
            },
        )
        result_json = result_output.model_dump_json()
        yield {"event": "final", "data": result_json}
        outcome = "success"
        usage = _extract_usage(run_ref)
        if usage is not None:
            yield {"event": "usage", "data": usage}
    except UsageLimitExceeded as exc:
        # Expected control-flow bound, not a crash: the run hit one of its
        # usage caps. Log at warning (not exception) and return a clear, safe
        # message instead of the generic "internal error".
        outcome = "error"
        error_class = exc.__class__.__name__
        log.warning("triage_usage_limit_exceeded", error=str(exc))
        yield {
            "event": "error",
            "data": _error_payload(
                exc,
                # pydantic-ai's message names the bound and its value
                # ("would exceed the request_limit of 25"): operational detail
                # the caller needs to narrow the query, nothing internal.
                safe_message=(
                    f"Triage stopped after reaching its usage budget ({exc}). "
                    "Narrow the query and retry; a tool may be failing repeatedly."
                ),
            ),
        }
    except TimeoutError as exc:
        outcome = "error"
        if deadline.expired():
            error_class = "TriageDeadlineExceeded"
            log.warning(
                "triage_deadline_exceeded",
                deadline_seconds=settings.triage_deadline_seconds,
            )
            yield {
                "event": "error",
                "data": _error_payload(
                    exc,
                    safe_message=(
                        "Triage stopped after exceeding its time budget of "
                        f"{settings.triage_deadline_seconds:g} seconds; a feed may be "
                        "slow. Retry, or narrow the query."
                    ),
                ),
            }
        else:
            # A TimeoutError raised inside the run, not by the deadline:
            # an ordinary failure, reported as such so its origin is honest.
            error_class = exc.__class__.__name__
            log.exception("triage_failed", error=str(exc))
            yield {"event": "error", "data": _error_payload(exc)}
    except (asyncio.CancelledError, GeneratorExit):
        # The client went away (sse-starlette cancels the task group on
        # disconnect) or the framework closed the generator. Neither a
        # success nor an error: seal it as what it is, charge what it
        # consumed (below), and let the cancellation propagate untouched.
        outcome = "cancelled"
        raise
    except Exception as exc:
        outcome = "error"
        error_class = exc.__class__.__name__
        log.exception("triage_failed", error=str(exc))
        yield {
            "event": "error",
            "data": _error_payload(exc),
        }
    finally:
        duration_ms = int((time.monotonic() - started_at) * 1000)
        # Charge whatever the run consumed, synchronously: after a disconnect
        # this block runs inside a cancelled scope, where an await never lands.
        _charge_run(model_id, _extract_usage(run_ref))
        # Best-effort: never fail the request because the audit log
        # failed. Worst case we log a warning and drop the event.
        try:
            _audit_triage(
                event_id=uuid.uuid4().hex,
                query=req.query,
                result_json=result_json,
                outcome=outcome,
                error_class=error_class,
                duration_ms=duration_ms,
                model=model_id,
            )
        except Exception:
            log.warning("audit_append_failed", exc_info=True)


def _audit_triage(
    *,
    event_id: str,
    query: str,
    result_json: str | None,
    outcome: str,
    error_class: str | None,
    duration_ms: int,
    model: str,
) -> None:
    """Append one TriageEvent to the audit store. Settings gate everything.

    `model` is the provider-prefixed id the run actually used (a per-request
    override included): a tamper-evident row that attests a run to a model it
    did not use is worse than no field.
    """
    if not settings.audit_log_enabled:
        return

    from sec_recon_agent.audit.models import (
        GENESIS_HASH,
        TriageEvent,
        sha256_hex,
        summarize_for_audit,
        utcnow_iso,
    )

    report_dict: dict[str, Any] = {}
    report_summary_plain: str | None = None
    if result_json is not None:
        try:
            report_dict = json.loads(result_json)
            if isinstance(report_dict.get("summary"), str):
                report_summary_plain = report_dict["summary"][:500]
        except (json.JSONDecodeError, TypeError):
            report_dict = {}

    summary = summarize_for_audit(report_dict)
    raw_for_hash = result_json if result_json is not None else ""

    event = TriageEvent(
        event_id=event_id,
        ts=utcnow_iso(),
        query_sha256=sha256_hex(query),
        query_length=len(query),
        query_plain=query if settings.audit_include_query else None,
        report_sha256=sha256_hex(raw_for_hash),
        severity=summary["severity"] if isinstance(summary["severity"], str) else None,
        confidence=(summary["confidence"] if isinstance(summary["confidence"], str) else None),
        cves_count=int(summary["cves_count"] or 0),
        attack_techniques_count=int(summary["attack_techniques_count"] or 0),
        kev_hits=int(summary["kev_hits"] or 0),
        ransomware_hits=int(summary["ransomware_hits"] or 0),
        high_epss_hits=int(summary["high_epss_hits"] or 0),
        ssvc_decision=(
            summary["ssvc_decision"] if isinstance(summary["ssvc_decision"], str) else None
        ),
        grounding_status=(
            summary["grounding_status"] if isinstance(summary["grounding_status"], str) else None
        ),
        report_summary_plain=(report_summary_plain if settings.audit_include_summary else None),
        model=model,
        duration_ms=duration_ms,
        outcome=outcome,
        error_class=error_class,
        prev_event_hash=GENESIS_HASH,  # AuditStore.append overwrites under its lock
    )
    _get_audit_store().append(event)


_AUDIT_STORE: "Any | None" = None


def _get_audit_store() -> Any:
    """Lazy singleton so test fixtures can monkeypatch settings.audit_db_path
    before the first call."""
    global _AUDIT_STORE
    if _AUDIT_STORE is None:
        from sec_recon_agent.audit.store import AuditStore

        _AUDIT_STORE = AuditStore(settings.audit_db_path)
    return _AUDIT_STORE


def _reset_audit_store() -> None:
    """Test-only: drop the cached store so a new db_path takes effect."""
    global _AUDIT_STORE
    if _AUDIT_STORE is not None:
        _AUDIT_STORE.close()
    _AUDIT_STORE = None


def _extract_usage(run: object) -> str | None:
    """Best-effort JSON usage payload for the SSE `usage` event.

    Reads token counts off the Pydantic AI run result so the eval harness can
    capture tokens / cost / p95 without a live billing call. The usage API has
    churned across pydantic-ai versions (request_tokens/response_tokens ->
    input_tokens/output_tokens), so we probe defensively and simply omit the
    event if we cannot read it. Returns a JSON string or None.
    """
    try:
        result = getattr(run, "result", None)
        usage_fn = getattr(result, "usage", None) or getattr(run, "usage", None)
        usage = usage_fn() if callable(usage_fn) else None
        if usage is None:
            return None

        def _pick(*names: str) -> int | None:
            for name in names:
                value = getattr(usage, name, None)
                if isinstance(value, int):
                    return value
            return None

        input_tokens = _pick("input_tokens", "request_tokens")
        output_tokens = _pick("output_tokens", "response_tokens")
        requests = _pick("requests")
        if input_tokens is None and output_tokens is None:
            return None
        return json.dumps(
            {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "requests": requests,
                # Prompt-cache traffic, priced at its own multipliers by the
                # budget rail and the eval scorecard; absent on fakes.
                "cache_read_tokens": _pick("cache_read_tokens"),
                "cache_write_tokens": _pick("cache_write_tokens"),
            },
        )
    except Exception:
        log.warning("usage_extract_failed", exc_info=True)
        return None


def _charge_run(model_id: str, usage_json: str | None) -> None:
    """Add one run's estimated USD cost to the denial-of-wallet window.

    Synchronous on purpose (see BudgetTracker.record_now): it runs from the
    generator's `finally`, which after a client disconnect executes inside a
    cancelled scope. Best-effort: no usage, an unparsable payload, or an
    unpriced model records nothing, and the tracker treats None as "unknown,
    do not count".
    """
    if usage_json is None:
        return
    try:
        payload = json.loads(usage_json)
    except (json.JSONDecodeError, TypeError):
        return
    budget_tracker.record_now(
        estimate_cost_usd(
            model=model_id,
            input_tokens=payload.get("input_tokens"),
            output_tokens=payload.get("output_tokens"),
            cache_read_tokens=payload.get("cache_read_tokens"),
            cache_write_tokens=payload.get("cache_write_tokens"),
        ),
    )


def _extract_messages(run: object) -> list[Any] | None:
    """Best-effort message history off the run, for the grounding verifier.

    Mirrors `_extract_usage`: the pydantic-ai run API churns across versions
    and test fakes may not model it, so we probe defensively and return None
    (grounding becomes `not_evaluated`) rather than fail the triage.
    """
    try:
        result = getattr(run, "result", None)
        messages_fn = getattr(result, "all_messages", None)
        if not callable(messages_fn):
            return None
        messages = messages_fn()
        return list(messages) if isinstance(messages, list) else None
    except Exception:
        log.warning("messages_extract_failed", exc_info=True)
        return None


def _invocations_for(messages: list[Any] | None) -> list[Any] | None:
    """Typed tool invocations off the message history; None when unavailable.

    None is the one "no trajectory" signal both stamps understand: grounding
    becomes NOT_EVALUATED and the SSVC verdict falls back to the report,
    stamped `basis=report`. An extraction failure degrades the same way
    instead of failing a triage the model already completed.
    """
    if messages is None:
        return None
    try:
        from sec_recon_agent.agent.trajectory import extract_tool_invocations

        return extract_tool_invocations(messages)
    except Exception:
        log.warning("trajectory_extract_failed", exc_info=True)
        return None


def _ssvc_for(report: Any, invocations: list[Any] | None) -> Any:
    """SSVC verdict over the trajectory evidence; never raises.

    A failure inside the evidence path degrades to the report-only verdict,
    which is stamped `basis=report` so the downgrade is visible to every
    consumer rather than silently presented as evidence-backed.
    """
    from sec_recon_agent.agent.ssvc import assess_ssvc

    try:
        return assess_ssvc(report.cves, invocations)
    except Exception:
        log.warning("ssvc_evidence_failed", exc_info=True)
        return assess_ssvc(report.cves, None)


def _grounding_for(report: Any, invocations: list[Any] | None) -> Any:
    """Grounding assessment for the final report; never raises.

    Any unexpected failure downgrades to an honest NOT_EVALUATED stamp: the
    verifier must never take a successful triage down with it.
    """
    from sec_recon_agent.agent.schema import GroundingAssessment, GroundingStatus

    try:
        if invocations is None:
            return GroundingAssessment(status=GroundingStatus.NOT_EVALUATED)
        from sec_recon_agent.agent.grounding import verify_grounding

        return verify_grounding(report, invocations)
    except Exception:
        log.warning("grounding_verify_failed", exc_info=True)
        return GroundingAssessment(status=GroundingStatus.NOT_EVALUATED)


def _node_event_payload(node: object) -> str:
    """JSON-serialize a minimal node descriptor.

    We deliberately surface only the node class name (not the full state),
    because (a) the Pydantic AI node API churns across versions and (b)
    raw internal state can leak instruction-like content from tool output
    into the SSE stream. Class name is a stable progress signal.
    """
    return json.dumps({"node": node.__class__.__name__})


def _error_payload(exc: BaseException, safe_message: str | None = None) -> str:
    if safe_message is not None:
        message = safe_message
    elif isinstance(exc, _SAFE_TO_ECHO):
        message = str(exc)
    else:
        message = "Internal error; check server logs."
    return json.dumps({"type": exc.__class__.__name__, "message": message})


def main() -> None:
    """Entry point for `uv run sec-recon-api`."""
    setup_tracing("sec-recon-agent-api")
    # Instrument the FastAPI app after the tracer provider is in place.
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(app)
    export_anthropic_api_key_to_env()
    uvicorn.run(
        "sec_recon_agent.api.stream:app",
        host=settings.agent_api_host,
        port=settings.agent_api_port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
