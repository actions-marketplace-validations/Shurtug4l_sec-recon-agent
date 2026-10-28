"""HTTP client that drives the agent API for the eval suite.

Speaks SSE byte-for-byte the way the frontend does. Returns the parsed
final TriageReport or raises EvalRunError on transport / protocol failure.

Why an HTTP client (and not pytest with an in-process app): the agent
needs the live MCP server too, which adds a process-management layer
that would couple the test setup to docker-compose. Hitting the live
stack also exercises the real SSE byte-layout the frontend depends on,
catching contract drift the unit tests cannot.
"""

import json
from dataclasses import dataclass

import httpx

from sec_recon_agent.agent.schema import TriageReport
from sec_recon_agent.eval.golden_set import GoldenCase

DEFAULT_API_URL = "http://127.0.0.1:8000"
# A real LLM run can take 30-60s depending on tool fan-out; cap generously.
DEFAULT_TIMEOUT_SECONDS = 180.0


class EvalRunError(Exception):
    """Raised when a triage call fails to produce a usable final event."""


@dataclass(frozen=True)
class CaseResult:
    """Raw outcome of a single triage invocation, pre-scoring.

    Token counts come from the `usage` SSE event the API emits after the final
    report; they are None when the stream carried no usage event (older API, a
    fake test agent, or a failed run). Cost is derived downstream from the model
    + token counts in eval/cost.py, not stored here.
    """

    case: GoldenCase
    report: TriageReport | None
    error: str | None
    elapsed_seconds: float
    input_tokens: int | None = None
    output_tokens: int | None = None
    requests: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None


def _iter_sse_events(text_iter: httpx.Response) -> list[dict[str, str]]:
    """Decode an SSE stream into a list of {event, data} records.

    sse-starlette emits CRLF frame separators; the parser tolerates both
    LF-only and CRLF for portability.
    """
    events: list[dict[str, str]] = []
    buffer = ""
    for chunk in text_iter.iter_text():
        buffer += chunk
        # Normalize CRLF -> LF so a single \n\n split works for both forms.
        buffer = buffer.replace("\r\n", "\n")
        while "\n\n" in buffer:
            frame, _, buffer = buffer.partition("\n\n")
            record: dict[str, str] = {}
            for line in frame.splitlines():
                if line.startswith("event: "):
                    record["event"] = line[len("event: ") :].strip()
                elif line.startswith("data: "):
                    record["data"] = line[len("data: ") :]
            if record:
                events.append(record)
    return events


_USAGE_KEYS = (
    "input_tokens",
    "output_tokens",
    "requests",
    "cache_read_tokens",
    "cache_write_tokens",
)


def _parse_usage(events: list[dict[str, str]]) -> dict[str, int | None]:
    """Pull the token counts from the last usage event; every key present,
    None when the stream carried no usable value for it."""
    empty: dict[str, int | None] = dict.fromkeys(_USAGE_KEYS)
    usage_payloads = [e["data"] for e in events if e.get("event") == "usage"]
    if not usage_payloads:
        return empty
    try:
        data = json.loads(usage_payloads[-1])
    except (json.JSONDecodeError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    return {
        key: (value if isinstance((value := data.get(key)), int) else None) for key in _USAGE_KEYS
    }


def run_case(
    case: GoldenCase,
    api_url: str = DEFAULT_API_URL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    model: str | None = None,
) -> CaseResult:
    """Send the case's query to the live API and parse the final report.

    `model` overrides the deployment default for this one call; must be
    on the backend's allowlist (haiku / sonnet / opus aliases also work).
    """
    import time

    url = api_url.rstrip("/") + "/v1/triage"
    body: dict[str, str] = {"query": case.query}
    if model is not None:
        body["model"] = model
    started = time.monotonic()
    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            with client.stream(
                "POST",
                url,
                json=body,
                headers={"Accept": "text/event-stream"},
            ) as response:
                if response.status_code != 200:
                    return CaseResult(
                        case=case,
                        report=None,
                        error=f"HTTP {response.status_code} from /v1/triage",
                        elapsed_seconds=time.monotonic() - started,
                    )
                events = _iter_sse_events(response)
    except httpx.HTTPError as exc:
        return CaseResult(
            case=case,
            report=None,
            error=f"transport error: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )

    elapsed = time.monotonic() - started

    final_payloads = [e["data"] for e in events if e.get("event") == "final"]
    error_payloads = [e["data"] for e in events if e.get("event") == "error"]
    if error_payloads:
        return CaseResult(
            case=case,
            report=None,
            error=f"agent error event: {error_payloads[-1]}",
            elapsed_seconds=elapsed,
        )
    if not final_payloads:
        return CaseResult(
            case=case,
            report=None,
            error="no final event in SSE stream",
            elapsed_seconds=elapsed,
        )

    raw = final_payloads[-1]
    try:
        # /v1/triage emits the final payload as a JSON string-of-JSON
        # (model_dump_json); a single json.loads gives us the report dict.
        parsed = json.loads(raw)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        report = TriageReport.model_validate(parsed)
    except (json.JSONDecodeError, ValueError) as exc:
        return CaseResult(
            case=case,
            report=None,
            error=f"final payload decode error: {exc}",
            elapsed_seconds=elapsed,
        )

    usage = _parse_usage(events)
    return CaseResult(
        case=case,
        report=report,
        error=None,
        elapsed_seconds=elapsed,
        input_tokens=usage["input_tokens"],
        output_tokens=usage["output_tokens"],
        requests=usage["requests"],
        cache_read_tokens=usage["cache_read_tokens"],
        cache_write_tokens=usage["cache_write_tokens"],
    )


def health_check(api_url: str = DEFAULT_API_URL, timeout_seconds: float = 5.0) -> bool:
    """Return True iff GET /v1/health responds 200 within `timeout_seconds`."""
    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.get(api_url.rstrip("/") + "/v1/health")
            return resp.status_code == 200
    except httpx.HTTPError:
        return False
