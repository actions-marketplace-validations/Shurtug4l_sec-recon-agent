"""OpenTelemetry tracing setup for the two-process stack.

`setup_tracing(service_name)` is called once from each process's main()
entry point. By default spans go to stdout (no infrastructure needed);
set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://jaeger:4318`) to ship
them to an OTLP/HTTP backend instead.

What is instrumented automatically:
- httpx outbound calls (every NVD / GitHub / ExploitDB request)
- FastAPI routes (instrument_app must be called from api/stream.py
  after the app is built)

What needs manual spans (in the tool modules):
- Each MCP tool wraps its body with tracer.start_as_current_span. The
  attributes set are tool name and the CVE ID when applicable. Never
  user query text. Never API keys. Never LLM output content.

Trace propagation between the agent process and the MCP server flows
through W3C `traceparent` headers on the HTTP+SSE transport, which
the httpx instrumentation handles automatically on the client side
and FastAPI/Starlette handle on the server side.
"""

import os
from typing import Final

from opentelemetry import trace
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
)

from sec_recon_agent.version import package_version

_TRACER_INSTRUMENTATION_NAME: Final = "sec_recon_agent"


def _build_exporter() -> SpanExporter:
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return ConsoleSpanExporter()

    # Lazy import keeps the protobuf dependency cost out of the cold-start
    # path when no OTLP collector is configured (the common dev case).
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )

    # OTel SDK expects the full traces endpoint; users typically configure
    # the base URL. Append /v1/traces if not already present so both forms
    # work.
    base = endpoint.rstrip("/")
    if not base.endswith("/v1/traces"):
        base = base + "/v1/traces"
    return OTLPSpanExporter(endpoint=base)


def setup_tracing(service_name: str) -> None:
    """Initialize the global tracer provider and instrument httpx.

    Idempotent: if a real TracerProvider is already installed (e.g. the
    function is called twice during a test session, or the host process
    pre-configured OTel), this is a no-op.
    """
    current = trace.get_tracer_provider()
    # The default provider before set_tracer_provider() is a ProxyTracerProvider.
    # We only skip setup if a real TracerProvider is already in place.
    if isinstance(current, TracerProvider):
        return

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": package_version(),
        },
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(_build_exporter()))
    trace.set_tracer_provider(provider)

    # Auto-instrument outbound httpx (NVD, GitHub, ExploitDB).
    HTTPXClientInstrumentor().instrument()


def get_tracer() -> trace.Tracer:
    """Return the project tracer. Safe to call before setup_tracing
    (returns a proxy that becomes real once the provider is set)."""
    return trace.get_tracer(_TRACER_INSTRUMENTATION_NAME)
