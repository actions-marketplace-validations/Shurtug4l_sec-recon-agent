"""Tests for the FastAPI surface.

The triage endpoint is exercised with a fake agent (no LLM, no MCP server)
to verify SSE wiring at the HTTP level. End-to-end agent behavior is
covered manually with curl against a running stack.
"""

import asyncio
import json
from collections import deque
from contextlib import asynccontextmanager
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi.testclient import TestClient

from sec_recon_agent.agent.schema import (
    Confidence,
    Severity,
    TriageReport,
)
from sec_recon_agent.api import stream as stream_module
from sec_recon_agent.api.stream import app
from sec_recon_agent.audit.models import sha256_hex
from sec_recon_agent.audit.store import AuditStore


@pytest.fixture
def fake_report() -> TriageReport:
    return TriageReport(
        summary="Fake summary for tests.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommended_action="Patch.",
        cves=[],
        reasoning_chain=["fake_tool() -> ok"],
    )


@pytest.fixture
def fake_agent_factory(fake_report: TriageReport) -> Any:
    """Return a build_agent replacement that yields scripted SSE events."""

    class _FakeNode:
        pass

    class _FakeResult:
        def __init__(self, output: TriageReport) -> None:
            self.output = output

        def all_messages(self) -> list[Any]:
            # Empty-but-present history: a real trajectory in which no tool
            # was called (grounding evaluates, unlike a missing history).
            return []

    class _FakeRun:
        def __init__(self, output: TriageReport) -> None:
            self._output = output
            self.result = _FakeResult(output)

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield _FakeNode()
                yield _FakeNode()

            return gen()

    class _FakeAgent:
        def __init__(self, output: TriageReport) -> None:
            self._output = output

        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits  # accepted for signature parity with the real agent
            yield _FakeRun(self._output)

    def _factory(model_override: str | None = None) -> _FakeAgent:
        # Test factory ignores model override — the fake agent does not
        # actually call an LLM, so any model string is equally fine.
        del model_override
        return _FakeAgent(fake_report)

    return _factory


def test_health_returns_ok() -> None:
    client = TestClient(app)
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_meta_returns_system_prompt_and_tool_inventory() -> None:
    """The transparency endpoint must surface the literal system prompt
    plus a stable tool inventory. The frontend's dashboard depends on
    both being present and well-shaped."""
    client = TestClient(app)
    response = client.get("/v1/meta")
    assert response.status_code == 200
    body = response.json()
    assert "system_prompt" in body
    assert "model" in body
    assert "tools" in body
    # System prompt must include the untrusted-content boundary mention;
    # if it drifts, the transparency view loses its key value.
    assert "untrusted" in body["system_prompt"].lower()
    # Tool inventory: ten tools, names match the MCP tool surface.
    names = {t["name"] for t in body["tools"]}
    assert names == {
        "cve_lookup",
        "cve_semantic_search",
        "exploit_check",
        "kev_check",
        "epss_score",
        "patch_lookup",
        "osv_lookup",
        "sbom_ingest",
        "nmap_parse_xml",
        "attack_mapping",
    }
    for tool in body["tools"]:
        assert tool["description"]  # non-empty


def test_triage_validates_missing_query() -> None:
    client = TestClient(app)
    response = client.post("/v1/triage", json={})
    assert response.status_code == 422


def test_triage_validates_empty_query() -> None:
    client = TestClient(app)
    response = client.post("/v1/triage", json={"query": ""})
    assert response.status_code == 422


def test_triage_streams_started_and_final_events(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
    fake_report: TriageReport,
) -> None:
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "CVE-2021-41773"}) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        body = "".join(response.iter_text())

    # SSE format: blank-line-separated frames, each `event: ...\ndata: ...`
    assert "event: started" in body
    assert "event: node" in body
    assert "event: final" in body

    # Final frame must carry the TriageReport JSON
    final_data_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and "Fake summary" in line
    )
    payload = json.loads(final_data_line[len("data: ") :])
    assert payload["summary"] == fake_report.summary
    assert payload["severity"] == "high"


def test_triage_stamps_ssvc_on_final_report(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    """The server computes the SSVC verdict deterministically and stamps it onto
    the report before emitting `final`, even when the model left `ssvc` null."""
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    final_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and "Fake summary" in line
    )
    payload = json.loads(final_line[len("data: ") :])
    assert payload["ssvc"] is not None
    # Fake report has no CVEs -> the deterministic verdict is Track.
    assert payload["ssvc"]["decision"] == "Track"
    assert payload["ssvc"]["rule"] == "no-cves"
    # An empty-but-present history is a real (tool-less) trajectory.
    assert payload["ssvc"]["basis"] == "evidence"


def test_triage_stamps_grounding_on_final_report(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    """The server verifies the report against the captured trajectory and
    stamps `grounding` before emitting `final`. A CVE-less report over an
    empty trajectory makes no checkable claims -> vacuously grounded."""
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    final_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and "Fake summary" in line
    )
    payload = json.loads(final_line[len("data: ") :])
    assert payload["grounding"] is not None
    assert payload["grounding"]["status"] == "grounded"
    assert payload["grounding"]["claims_checked"] == 0


def test_triage_grounding_flags_unbacked_claim(monkeypatch: MonkeyPatch) -> None:
    """A positive KEV claim with no kev_check evidence in the trajectory must
    surface as suspect/unbacked on the stamped assessment."""
    from pydantic_ai.messages import (
        ModelRequest,
        ModelResponse,
        ToolCallPart,
        ToolReturnPart,
    )

    from sec_recon_agent.agent.schema import CVEReference

    report = TriageReport(
        summary="One CVE, KEV claimed without evidence.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommended_action="Patch.",
        cves=[
            CVEReference(
                cve_id="CVE-2021-41773",
                summary="Apache path traversal.",
                severity=Severity.HIGH,
                exploits_public=False,
                nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                in_kev_catalog=True,
            ),
        ],
    )
    messages = [
        ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name="cve_lookup",
                    args={"cve_id": "CVE-2021-41773"},
                    tool_call_id="c1",
                ),
            ],
        ),
        ModelRequest(
            parts=[
                ToolReturnPart(
                    tool_name="cve_lookup",
                    content="upstream unavailable",
                    tool_call_id="c1",
                ),
            ],
        ),
    ]

    class _FakeResult:
        def __init__(self) -> None:
            self.output = report

        def all_messages(self) -> list[Any]:
            return list(messages)

    class _FakeRun:
        def __init__(self) -> None:
            self.result = _FakeResult()

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield object()

            return gen()

    class _FakeAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits
            yield _FakeRun()

    monkeypatch.setattr(stream_module, "build_agent", lambda model_override=None: _FakeAgent())

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    final_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and "One CVE" in line
    )
    payload = json.loads(final_line[len("data: ") :])
    grounding = payload["grounding"]
    assert grounding["status"] == "suspect"
    assert grounding["unbacked"] >= 1
    unbacked_fields = {f["field"] for f in grounding["findings"] if f["status"] == "unbacked"}
    assert "in_kev_catalog" in unbacked_fields


def test_triage_grounding_not_evaluated_without_message_history(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
) -> None:
    """A run object that cannot produce message history (legacy fakes, API
    churn) degrades to an honest not_evaluated stamp, never an error."""

    class _FakeResult:
        def __init__(self) -> None:
            self.output = fake_report

    class _FakeRun:
        def __init__(self) -> None:
            self.result = _FakeResult()

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield object()

            return gen()

    class _FakeAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits
            yield _FakeRun()

    monkeypatch.setattr(stream_module, "build_agent", lambda model_override=None: _FakeAgent())

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    final_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and "Fake summary" in line
    )
    payload = json.loads(final_line[len("data: ") :])
    assert payload["grounding"]["status"] == "not_evaluated"
    # No trajectory: the verdict rests on the report and says so.
    assert payload["ssvc"]["basis"] == "report"


def test_triage_emits_usage_event(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
) -> None:
    """When the run result exposes usage, the API emits a `usage` SSE event so
    the eval harness can capture tokens without a billing call."""

    class _Usage:
        input_tokens = 1234
        output_tokens = 567
        requests = 2

    class _FakeResult:
        def __init__(self, output: TriageReport) -> None:
            self.output = output

        def usage(self) -> _Usage:
            return _Usage()

    class _FakeRun:
        def __init__(self, output: TriageReport) -> None:
            self.result = _FakeResult(output)

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield object()

            return gen()

    class _FakeAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits
            yield _FakeRun(fake_report)

    monkeypatch.setattr(stream_module, "build_agent", lambda model_override=None: _FakeAgent())

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    assert "event: usage" in body
    usage_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and "input_tokens" in line
    )
    payload = json.loads(usage_line[len("data: ") :])
    assert payload["input_tokens"] == 1234
    assert payload["output_tokens"] == 567
    assert payload["requests"] == 2


def test_triage_round_cap_emits_clean_error(monkeypatch: MonkeyPatch) -> None:
    """When the agent exceeds its request-limit round cap, the endpoint emits a
    single human-readable error event (not the generic 'internal error') and no
    final report. The runaway loop terminates cleanly instead of thrashing to the
    client timeout."""
    from pydantic_ai.exceptions import UsageLimitExceeded

    from sec_recon_agent.config import settings

    class _FakeRun:
        result = None

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield object()  # one node, then the cap trips on the next round
                raise UsageLimitExceeded(
                    f"The next request would exceed the request_limit of "
                    f"{settings.agent_request_limit}",
                )

            return gen()

    class _FakeAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            # The cap must actually be wired into the run, at the configured value.
            assert usage_limits is not None
            assert usage_limits.request_limit == settings.agent_request_limit
            yield _FakeRun()

    monkeypatch.setattr(stream_module, "build_agent", lambda model_override=None: _FakeAgent())

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "loop forever"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    assert "event: error" in body
    assert "event: final" not in body
    err_line = next(
        line
        for line in body.splitlines()
        if line.startswith("data: ") and "UsageLimitExceeded" in line
    )
    payload = json.loads(err_line[len("data: ") :])
    assert payload["type"] == "UsageLimitExceeded"
    # Tailored, safe message -- not the generic internal-error fallback.
    assert "usage budget" in payload["message"]
    assert f"request_limit of {settings.agent_request_limit}" in payload["message"]
    assert "Internal error" not in payload["message"]


def test_triage_rejects_unknown_model_override(monkeypatch: MonkeyPatch) -> None:
    """A body that sets an unknown `model` must surface as an error
    event with the allowlist-violation message preserved.

    `resolve_model` raises ValueError before any LLM / MCP work happens,
    so this test routes through the real build_agent code path; the
    factory monkeypatch in other tests is unnecessary here.
    """

    def _build_agent_calling_real_resolve(model_override: str | None = None) -> Any:
        from sec_recon_agent.agent.triage import resolve_model

        resolve_model(model_override)  # may raise ValueError
        raise AssertionError("test expects resolve_model to raise before this point")

    monkeypatch.setattr(stream_module, "build_agent", _build_agent_calling_real_resolve)

    client = TestClient(app)
    with client.stream(
        "POST",
        "/v1/triage",
        json={"query": "test", "model": "gpt-4-secret"},
    ) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    assert "event: error" in body
    assert "allowlist" in body
    assert "gpt-4-secret" in body


def test_triage_appends_one_audit_event_on_success(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
    tmp_path: Any,
) -> None:
    """The triage handler must append exactly one audit event per call,
    even though the audit pipeline is best-effort."""
    from sec_recon_agent.audit.store import AuditStore
    from sec_recon_agent.config import settings

    audit_path = tmp_path / "audit.db"
    monkeypatch.setattr(settings, "audit_db_path", audit_path)
    monkeypatch.setattr(settings, "audit_log_enabled", True)
    monkeypatch.setattr(settings, "audit_include_query", False)
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    stream_module._reset_audit_store()

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "CVE-2021-41773"}) as response:
        assert response.status_code == 200
        for _ in response.iter_text():
            pass

    store = AuditStore(audit_path)
    try:
        assert store.count() == 1
        assert store.verify() == 1
        events = store.tail(limit=1)
        ev = events[0]
        assert ev.outcome == "success"
        assert ev.severity == "high"
        assert ev.grounding_status == "grounded"
        # Privacy: query_plain stays None when AUDIT_INCLUDE_QUERY is off.
        assert ev.query_plain is None
        # But the digest is always there.
        assert len(ev.query_sha256) == 64
        assert ev.query_length == len("CVE-2021-41773")
    finally:
        store.close()
        stream_module._reset_audit_store()


def test_triage_appends_audit_event_on_error(monkeypatch: MonkeyPatch, tmp_path: Any) -> None:
    """An agent failure still produces one audit event with outcome=error."""
    from sec_recon_agent.audit.store import AuditStore
    from sec_recon_agent.config import settings

    audit_path = tmp_path / "audit.db"
    monkeypatch.setattr(settings, "audit_db_path", audit_path)
    monkeypatch.setattr(settings, "audit_log_enabled", True)
    stream_module._reset_audit_store()

    class _BrokenAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits
            raise RuntimeError("boom")
            yield  # pragma: no cover

    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _BrokenAgent(),
    )

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        for _ in response.iter_text():
            pass

    store = AuditStore(audit_path)
    try:
        assert store.count() == 1
        ev = store.tail(1)[0]
        assert ev.outcome == "error"
        assert ev.error_class == "RuntimeError"
    finally:
        store.close()
        stream_module._reset_audit_store()


def test_meta_open_when_no_api_keys_configured() -> None:
    client = TestClient(app)
    resp = client.get("/v1/meta")
    assert resp.status_code == 200


def test_meta_requires_api_key_when_configured(monkeypatch: MonkeyPatch) -> None:
    from pydantic import SecretStr

    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "api_keys", [SecretStr("super-secret-123")])
    client = TestClient(app)

    # No header -> 401
    resp = client.get("/v1/meta")
    assert resp.status_code == 401
    assert "missing or invalid" in resp.json()["detail"]

    # Wrong key -> 401
    resp = client.get("/v1/meta", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401

    # Right key via Bearer -> 200
    resp = client.get(
        "/v1/meta",
        headers={"Authorization": "Bearer super-secret-123"},
    )
    assert resp.status_code == 200

    # Right key via X-API-Key -> 200
    resp = client.get("/v1/meta", headers={"X-API-Key": "super-secret-123"})
    assert resp.status_code == 200


def test_triage_requires_api_key_when_configured(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    from pydantic import SecretStr

    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "api_keys", [SecretStr("good-key")])
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    client = TestClient(app)

    # No header -> 401 from the dependency, no agent invocation happens
    resp = client.post("/v1/triage", json={"query": "test"})
    assert resp.status_code == 401

    # Good key -> 200 SSE stream
    with client.stream(
        "POST",
        "/v1/triage",
        json={"query": "test"},
        headers={"Authorization": "Bearer good-key"},
    ) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())
        assert "event: final" in body


def test_health_remains_open_even_with_api_keys_configured(
    monkeypatch: MonkeyPatch,
) -> None:
    """/v1/health is a liveness probe — must stay open for container
    orchestrators (Docker, Kubernetes) regardless of auth posture."""
    from pydantic import SecretStr

    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "api_keys", [SecretStr("good-key")])
    client = TestClient(app)

    resp = client.get("/v1/health")
    assert resp.status_code == 200


def test_triage_rate_limit_returns_429_when_exceeded(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    """With rate_limit_per_minute=2 the third request inside the window
    must come back as 429 with a generic detail (the configured limit
    must not be echoed)."""
    from sec_recon_agent.api.stream import limiter
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "rate_limit_per_minute", 2)
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    # slowapi caches the resolved limit per route; reset so the patched
    # value takes effect.
    limiter.reset()

    client = TestClient(app)
    # First two pass...
    for _ in range(2):
        with client.stream("POST", "/v1/triage", json={"query": "test"}) as r:
            assert r.status_code == 200
            for _ in r.iter_text():
                pass
    # ...third is throttled.
    resp = client.post("/v1/triage", json={"query": "test"})
    assert resp.status_code == 429
    body = resp.json()
    assert body == {"detail": "rate limit exceeded"}
    # The configured limit value must NOT appear in the response.
    assert "2" not in body["detail"]


def test_api_keys_parses_csv_from_env(monkeypatch: MonkeyPatch) -> None:
    """Settings field validator must split a comma-separated env value
    into a list of SecretStr — that is the carrier format users actually
    set in .env / docker-compose."""
    from sec_recon_agent.config import Settings

    monkeypatch.setenv("API_KEYS", "key-one, key-two,key-three")
    fresh = Settings()
    assert [k.get_secret_value() for k in fresh.api_keys] == [
        "key-one",
        "key-two",
        "key-three",
    ]


def test_rate_limit_empty_env_string_disables_limiter(monkeypatch: MonkeyPatch) -> None:
    """docker-compose interpolates an unset host var to "" via
    ${RATE_LIMIT_PER_MINUTE:-}; that empty string must not crash Settings
    and must mean "limiter disabled" (None), matching the documented
    default."""
    from sec_recon_agent.config import Settings

    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "")
    fresh = Settings()
    assert fresh.rate_limit_per_minute is None


def test_rate_limit_numeric_env_string_parsed(monkeypatch: MonkeyPatch) -> None:
    from sec_recon_agent.config import Settings

    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "30")
    fresh = Settings()
    assert fresh.rate_limit_per_minute == 30


def test_triage_emits_error_event_when_agent_raises(monkeypatch: MonkeyPatch) -> None:
    class _BrokenAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits
            raise RuntimeError("agent boom with internal context: /var/lib/secret")
            yield  # pragma: no cover

    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _BrokenAgent(),
    )

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    assert "event: error" in body
    # Exception class name is fine to echo
    assert "RuntimeError" in body
    # Original message must NOT leak (filesystem path, internal context)
    assert "agent boom" not in body
    assert "/var/lib/secret" not in body
    assert "Internal error" in body


_EXPORT_REPORT: dict[str, Any] = {
    "summary": "Critical Log4Shell exposure in the queried product.",
    "severity": "critical",
    "confidence": "high",
    "recommended_action": "Upgrade log4j-core to 2.17.1 or later immediately.",
    "cves": [
        {
            "cve_id": "CVE-2021-44228",
            "summary": "Log4Shell RCE in Apache Log4j2 via JNDI lookup.",
            "cvss_v3_score": 10.0,
            "severity": "critical",
            "exploits_public": True,
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "in_kev_catalog": True,
        },
    ],
}


def test_export_sarif_renders_the_posted_report() -> None:
    client = TestClient(app)
    resp = client.post(
        "/v1/export/sarif",
        json={"report": _EXPORT_REPORT, "artifact_uri": "data/sbom.json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == "2.1.0"
    results = body["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CVE-2021-44228"
    location = results[0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "data/sbom.json"


def test_export_sarif_defaults_the_artifact_uri() -> None:
    client = TestClient(app)
    resp = client.post("/v1/export/sarif", json={"report": _EXPORT_REPORT})
    assert resp.status_code == 200
    location = resp.json()["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "triage-report.json"


def test_export_sarif_rejects_an_invalid_report_body() -> None:
    client = TestClient(app)
    resp = client.post("/v1/export/sarif", json={"report": {"summary": "incomplete"}})
    assert resp.status_code == 422


def test_export_openvex_renders_affected_statements() -> None:
    client = TestClient(app)
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    resp = client.post(
        "/v1/export/openvex",
        json={"report": _EXPORT_REPORT, "products": [purl]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["@context"] == "https://openvex.dev/ns/v0.2.0"
    statement = body["statements"][0]
    assert statement["status"] == "affected"
    assert statement["products"][0]["identifiers"]["purl"] == purl


def test_export_openvex_requires_a_product_list() -> None:
    client = TestClient(app)
    resp = client.post("/v1/export/openvex", json={"report": _EXPORT_REPORT, "products": []})
    assert resp.status_code == 422


def test_export_openvex_rejects_non_purl_products() -> None:
    client = TestClient(app)
    resp = client.post(
        "/v1/export/openvex",
        json={"report": _EXPORT_REPORT, "products": ["log4j-core 2.14.1"]},
    )
    assert resp.status_code == 422
    assert "purl" in resp.json()["detail"]


def test_export_requires_api_key_when_configured(monkeypatch: MonkeyPatch) -> None:
    from pydantic import SecretStr

    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "api_keys", [SecretStr("good-key")])
    client = TestClient(app)

    resp = client.post("/v1/export/sarif", json={"report": _EXPORT_REPORT})
    assert resp.status_code == 401

    resp = client.post(
        "/v1/export/sarif",
        json={"report": _EXPORT_REPORT},
        headers={"X-API-Key": "good-key"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# S4 operational safety rails: kill-switch + denial-of-wallet budget
# ---------------------------------------------------------------------------

from sec_recon_agent.api import budget as budget_module  # noqa: E402
from sec_recon_agent.api.budget import BudgetTracker, budget_tracker  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_budget_window() -> Any:
    """Drop the shared tracker's window around every test so accumulated spend
    never leaks between tests (the tracker is a module singleton)."""
    budget_tracker.reset()
    yield
    budget_tracker.reset()


def test_triage_refused_when_kill_switch_env(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    """The env kill-switch refuses triage with 503 before the agent is built."""
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "kill_switch", True)
    # Wire a fake agent so a failure to short-circuit would otherwise 200.
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)

    client = TestClient(app)
    resp = client.post("/v1/triage", json={"query": "CVE-2021-41773"})
    assert resp.status_code == 503


def test_triage_refused_when_kill_switch_file_present(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
    tmp_path: Any,
) -> None:
    """A present sentinel file disables triage live; removing it re-enables it,
    with no restart in between (the path is checked per request)."""
    from sec_recon_agent.config import settings

    sentinel = tmp_path / "killswitch"
    monkeypatch.setattr(settings, "kill_switch", False)
    monkeypatch.setattr(settings, "kill_switch_file", sentinel)
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    client = TestClient(app)

    # Absent -> allowed.
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        assert "event: final" in "".join(response.iter_text())

    # Present -> refused.
    sentinel.touch()
    resp = client.post("/v1/triage", json={"query": "test"})
    assert resp.status_code == 503

    # Removed -> allowed again, no restart.
    sentinel.unlink()
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200


def test_triage_refused_when_budget_exhausted(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    """With a ceiling set and the rolling window already over it, triage is
    refused with 503; clearing the window re-enables it."""
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", 1.0)
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    # Preload the window above the ceiling (a recent event).
    budget_tracker._events.append((budget_module.time.monotonic(), 2.0))

    client = TestClient(app)
    resp = client.post("/v1/triage", json={"query": "test"})
    assert resp.status_code == 503

    budget_tracker.reset()
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200


def test_triage_allowed_when_budget_guard_disabled(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    """With no ceiling configured, even a large recorded spend never blocks."""
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", None)
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    budget_tracker._events.append((budget_module.time.monotonic(), 999.0))

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200


async def test_budget_tracker_disabled_never_blocks(monkeypatch: MonkeyPatch) -> None:
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", None)
    tracker = BudgetTracker()
    await tracker.record(5.0)
    assert tracker.enabled is False
    assert await tracker.would_block() is False
    # record() is a no-op while disabled: nothing accumulates.
    assert await tracker.spent_usd() == 0.0


async def test_budget_tracker_blocks_over_ceiling(monkeypatch: MonkeyPatch) -> None:
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", 0.10)
    tracker = BudgetTracker()
    await tracker.record(0.04)
    assert await tracker.would_block() is False
    await tracker.record(0.07)
    assert await tracker.spent_usd() == pytest.approx(0.11)
    assert await tracker.would_block() is True


async def test_budget_tracker_ignores_unknown_and_nonpositive(monkeypatch: MonkeyPatch) -> None:
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", 1.0)
    tracker = BudgetTracker()
    await tracker.record(None)  # unpriced model
    await tracker.record(0.0)
    await tracker.record(-1.0)
    assert await tracker.spent_usd() == 0.0


async def test_budget_tracker_prunes_outside_window(monkeypatch: MonkeyPatch) -> None:
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", 1.0)
    clock = {"now": 1000.0}
    monkeypatch.setattr(budget_module.time, "monotonic", lambda: clock["now"])
    tracker = BudgetTracker(window_seconds=100.0)
    await tracker.record(2.0)
    assert await tracker.spent_usd() == pytest.approx(2.0)
    # Advance past the window: the event ages out and the guard reopens.
    clock["now"] = 1000.0 + 101.0
    assert await tracker.spent_usd() == 0.0
    assert await tracker.would_block() is False


def _agent_with_history(report: TriageReport, messages: list[Any]) -> Any:
    """A fake agent whose run yields `report` and replays `messages` as its history."""

    class _FakeResult:
        def __init__(self) -> None:
            self.output = report

        def all_messages(self) -> list[Any]:
            return list(messages)

    class _FakeRun:
        def __init__(self) -> None:
            self.result = _FakeResult()

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield object()

            return gen()

    class _FakeAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits
            yield _FakeRun()

    return _FakeAgent()


def _final_payload(body: str, marker: str) -> dict[str, Any]:
    final_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and marker in line
    )
    return json.loads(final_line[len("data: ") :])  # type: ignore[no-any-return]


def _one_cve_report(summary: str, **cve_overrides: Any) -> TriageReport:
    from sec_recon_agent.agent.schema import CVEReference

    base: dict[str, Any] = {
        "cve_id": "CVE-2021-41773",
        "summary": "Apache path traversal.",
        "severity": Severity.HIGH,
        "exploits_public": False,
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    }
    base.update(cve_overrides)
    return TriageReport(
        summary=summary,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommended_action="Patch.",
        cves=[CVEReference(**base)],
    )


def test_triage_ssvc_reads_kev_from_the_tool_return_not_the_report(
    monkeypatch: MonkeyPatch,
) -> None:
    """The model downplays KEV (in_kev_catalog=False) while kev_check said True:
    the stamped verdict must be Act on the tool's word, basis evidence."""
    from pydantic_ai.messages import (
        ModelRequest,
        ModelResponse,
        ToolCallPart,
        ToolReturnPart,
    )

    report = _one_cve_report("KEV downplayed by the model.", in_kev_catalog=False)
    messages = [
        ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name="kev_check", args={"cve_id": "CVE-2021-41773"}, tool_call_id="k1"
                ),
            ],
        ),
        ModelRequest(
            parts=[
                ToolReturnPart(
                    tool_name="kev_check",
                    content={"cve_id": "CVE-2021-41773", "in_catalog": True},
                    tool_call_id="k1",
                ),
            ],
        ),
    ]
    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _agent_with_history(report, messages),
    )

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    ssvc = _final_payload(body, "KEV downplayed")["ssvc"]
    assert ssvc["decision"] == "Act"
    assert ssvc["rule"] == "kev-active-exploitation"
    # KEV came from evidence; the three feeds never called are named, not hidden.
    assert ssvc["basis"] == "mixed"
    assert "CVE-2021-41773:kev" not in ssvc["unverified_signals"]
    assert set(ssvc["unverified_signals"]) == {
        "CVE-2021-41773:exploit",
        "CVE-2021-41773:epss",
        "CVE-2021-41773:severity",
    }


def test_triage_ssvc_names_the_feed_the_model_never_called(monkeypatch: MonkeyPatch) -> None:
    """Suppressing kev_check cannot silently produce an evidence-backed verdict."""
    from pydantic_ai.messages import (
        ModelRequest,
        ModelResponse,
        ToolCallPart,
        ToolReturnPart,
    )

    report = _one_cve_report("KEV lookup suppressed.", in_kev_catalog=False)
    messages = [
        ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name="epss_score", args={"cve_id": "CVE-2021-41773"}, tool_call_id="e1"
                ),
            ],
        ),
        ModelRequest(
            parts=[
                ToolReturnPart(
                    tool_name="epss_score",
                    content={
                        "cve_id": "CVE-2021-41773",
                        "status": "found",
                        "probability": 0.02,
                        "percentile": 0.5,
                    },
                    tool_call_id="e1",
                ),
            ],
        ),
    ]
    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _agent_with_history(report, messages),
    )

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    ssvc = _final_payload(body, "KEV lookup suppressed")["ssvc"]
    assert ssvc["basis"] == "mixed"
    assert "CVE-2021-41773:kev" in ssvc["unverified_signals"]
    assert "CVE-2021-41773:epss" not in ssvc["unverified_signals"]
    assert ssvc["rationale"].endswith("not verified against tool returns.")


# --- run accounting on every exit path ---------------------------------------
#
# The denial-of-wallet rail used to charge a run only after the `final` event,
# and the outcome was "success" unless an Exception arrived. A client that
# dropped the connection one round early therefore cost the provider the full
# run, cost the window nothing, and sealed into the audit chain as a success.
# These tests drive the generator through each exit path and assert that the
# window grew and the audit sealed the honest outcome.


class _RunUsage:
    input_tokens = 20_000
    output_tokens = 1_000
    requests = 3


def _accounting_agent(
    report: TriageReport,
    *,
    nodes: int = 2,
    fail_at: int | None = None,
    sleep: float = 0.0,
    captured: dict[str, Any] | None = None,
) -> Any:
    """A fake agent whose run exposes usage, with optional mid-stream failure
    or slowness so the error and deadline paths can be exercised."""

    class _FakeResult:
        def __init__(self) -> None:
            self.output = report

        def all_messages(self) -> list[Any]:
            return []

    class _FakeRun:
        def __init__(self) -> None:
            self.result = _FakeResult()

        def usage(self) -> _RunUsage:
            return _RunUsage()

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                for index in range(nodes):
                    if sleep:
                        await asyncio.sleep(sleep)
                    if fail_at is not None and index >= fail_at:
                        raise RuntimeError("boom mid-run")
                    yield object()

            return gen()

    class _FakeAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            if captured is not None:
                captured["usage_limits"] = usage_limits
            yield _FakeRun()

    return _FakeAgent()


@pytest.fixture
def priced_budget_and_audit(monkeypatch: MonkeyPatch, tmp_path: Any) -> Any:
    """A live budget ceiling, a priced default model, and an audit db in tmp."""
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", 100.0)
    monkeypatch.setattr(settings, "llm_model", "claude-haiku-4-5-20251001")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "audit.db")
    monkeypatch.setattr(settings, "audit_log_enabled", True)
    stream_module.budget_tracker.reset()
    stream_module._reset_audit_store()
    yield tmp_path / "audit.db"
    stream_module.budget_tracker.reset()
    stream_module._reset_audit_store()


def _last_audit_row(audit_path: Any) -> Any:
    store = AuditStore(audit_path)
    try:
        assert store.count() == 1
        return store.tail(1)[0]
    finally:
        store.close()


# 20k input at $1/M plus 1k output at $5/M on haiku.
_HAIKU_RUN_USD = 0.025


async def test_client_disconnect_mid_stream_is_charged_and_sealed_as_cancelled(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
    priced_budget_and_audit: Any,
) -> None:
    """Closing the generator at a yield is what a dropped connection looks
    like from inside: the run must still be charged, and the audit row must
    say cancelled, not success."""
    monkeypatch.setattr(
        stream_module, "build_agent", lambda model_override=None: _accounting_agent(fake_report)
    )
    events = stream_module._triage_events(stream_module.TriageRequest(query="test"))
    assert (await events.__anext__())["event"] == "started"
    assert (await events.__anext__())["event"] == "node"
    await events.aclose()  # the client is gone

    assert await stream_module.budget_tracker.spent_usd() == pytest.approx(_HAIKU_RUN_USD)
    row = _last_audit_row(priced_budget_and_audit)
    assert row.outcome == "cancelled"
    assert row.error_class is None
    assert row.report_sha256 == sha256_hex("")
    assert row.model == "anthropic:claude-haiku-4-5-20251001"


def test_mid_run_failure_is_charged_and_sealed_as_error(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
    priced_budget_and_audit: Any,
) -> None:
    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _accounting_agent(fake_report, fail_at=1),
    )
    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        body = "".join(response.iter_text())
    assert "event: error" in body

    assert asyncio.run(stream_module.budget_tracker.spent_usd()) == pytest.approx(_HAIKU_RUN_USD)
    row = _last_audit_row(priced_budget_and_audit)
    assert row.outcome == "error"
    assert row.error_class == "RuntimeError"


def test_delivered_run_is_charged_and_sealed_as_success(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
    priced_budget_and_audit: Any,
) -> None:
    monkeypatch.setattr(
        stream_module, "build_agent", lambda model_override=None: _accounting_agent(fake_report)
    )
    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        body = "".join(response.iter_text())
    assert "event: final" in body and "event: usage" in body

    assert asyncio.run(stream_module.budget_tracker.spent_usd()) == pytest.approx(_HAIKU_RUN_USD)
    assert _last_audit_row(priced_budget_and_audit).outcome == "success"


def test_audit_row_and_charge_use_the_overridden_model(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
    priced_budget_and_audit: Any,
) -> None:
    """A per-request override must be what the audit attests and what the
    budget prices: sonnet at $3/M in, $15/M out on the same token counts."""
    monkeypatch.setattr(
        stream_module, "build_agent", lambda model_override=None: _accounting_agent(fake_report)
    )
    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test", "model": "sonnet"}) as response:
        "".join(response.iter_text())

    assert asyncio.run(stream_module.budget_tracker.spent_usd()) == pytest.approx(0.075)
    assert _last_audit_row(priced_budget_and_audit).model == "anthropic:claude-sonnet-4-6"


def test_deadline_stops_a_slow_run_charges_it_and_names_the_cause(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
    priced_budget_and_audit: Any,
) -> None:
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "triage_deadline_seconds", 0.05)
    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _accounting_agent(fake_report, nodes=3, sleep=0.5),
    )
    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        body = "".join(response.iter_text())

    error_line = next(line for line in body.splitlines() if '"type": "TimeoutError"' in line)
    assert "time budget" in error_line
    assert "0.05" in error_line
    assert asyncio.run(stream_module.budget_tracker.spent_usd()) == pytest.approx(_HAIKU_RUN_USD)
    row = _last_audit_row(priced_budget_and_audit)
    assert row.outcome == "error"
    assert row.error_class == "TriageDeadlineExceeded"


def test_run_bounds_reach_the_agent(monkeypatch: MonkeyPatch, fake_report: TriageReport) -> None:
    """Rounds, tool calls and tokens are bounded independently, from settings."""
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "agent_request_limit", 7)
    monkeypatch.setattr(settings, "agent_tool_calls_limit", 11)
    monkeypatch.setattr(settings, "agent_total_tokens_limit", 12_345)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _accounting_agent(fake_report, captured=captured),
    )
    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        "".join(response.iter_text())

    limits = captured["usage_limits"]
    assert limits.request_limit == 7
    assert limits.tool_calls_limit == 11
    assert limits.total_tokens_limit == 12_345


def test_budget_record_now_is_synchronous_and_respects_the_guard(monkeypatch: MonkeyPatch) -> None:
    from sec_recon_agent.config import settings

    tracker = stream_module.budget_tracker
    tracker.reset()
    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", None)
    tracker.record_now(1.0)
    assert tracker._events == deque()
    monkeypatch.setattr(settings, "denial_of_wallet_usd_per_day", 10.0)
    tracker.record_now(None)
    tracker.record_now(0.0)
    tracker.record_now(0.5)
    assert [usd for _, usd in tracker._events] == [0.5]
    tracker.reset()


def test_usage_event_and_charge_carry_cache_tokens(
    monkeypatch: MonkeyPatch,
    fake_report: TriageReport,
    priced_budget_and_audit: Any,
) -> None:
    """With prompt caching on, most input is cache traffic priced at its own
    multipliers; the usage event exposes it and the budget rail prices it."""

    class _CachedUsage:
        # Total input as pydantic-ai reports it: 10k uncached + the cache traffic.
        input_tokens = 130_000
        output_tokens = 1_000
        requests = 3
        cache_read_tokens = 100_000
        cache_write_tokens = 20_000

    class _FakeResult:
        def __init__(self) -> None:
            self.output = fake_report

        def all_messages(self) -> list[Any]:
            return []

    class _FakeRun:
        def __init__(self) -> None:
            self.result = _FakeResult()

        def usage(self) -> _CachedUsage:
            return _CachedUsage()

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield object()

            return gen()

    class _FakeAgent:
        @asynccontextmanager
        async def iter(self, query: str, usage_limits: Any = None) -> Any:
            del usage_limits
            yield _FakeRun()

    monkeypatch.setattr(stream_module, "build_agent", lambda model_override=None: _FakeAgent())
    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        body = "".join(response.iter_text())

    usage_line = next(line for line in body.splitlines() if '"cache_read_tokens"' in line)
    payload = json.loads(usage_line[len("data: ") :])
    assert payload["cache_read_tokens"] == 100_000
    assert payload["cache_write_tokens"] == 20_000
    # haiku: 10k uncached at $1/M + 100k reads at $0.1/M + 20k writes at $1.25/M + 1k out at $5/M
    expected = 0.01 + 0.01 + 0.025 + 0.005
    assert asyncio.run(stream_module.budget_tracker.spent_usd()) == pytest.approx(expected)
