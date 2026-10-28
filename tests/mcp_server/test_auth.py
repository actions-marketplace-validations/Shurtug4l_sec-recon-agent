"""Contract tests for the MCP bearer-auth ASGI middleware, plus the end-to-end
proof that the agent's own client can get through it on a real socket."""

import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import uvicorn
from pydantic import SecretStr
from pydantic_ai.mcp import MCPToolset

from sec_recon_agent.mcp_server import server as srv
from sec_recon_agent.mcp_server.auth import BearerAuthASGI


class _Recorder:
    """Capture every ASGI message a middleware emits via `send`."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.app_called = False

    async def send(self, message: dict[str, Any]) -> None:
        self.messages.append(message)

    async def passthrough_app(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.app_called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _empty_receive() -> dict[str, Any]:
    return {"type": "http.disconnect"}


def _http_scope(headers: list[tuple[bytes, bytes]]) -> dict[str, Any]:
    return {
        "type": "http",
        "method": "POST",
        "path": "/sse",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
    }


@pytest.mark.asyncio
async def test_rejects_missing_authorization() -> None:
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    await mw(_http_scope([]), _empty_receive, rec.send)

    assert not rec.app_called
    assert rec.messages[0]["status"] == 401


@pytest.mark.asyncio
async def test_rejects_wrong_token() -> None:
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    headers = [(b"authorization", b"Bearer nope")]
    await mw(_http_scope(headers), _empty_receive, rec.send)

    assert not rec.app_called
    assert rec.messages[0]["status"] == 401


@pytest.mark.asyncio
async def test_rejects_wrong_scheme() -> None:
    """Basic auth must not bypass the bearer gate."""
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    headers = [(b"authorization", b"Basic czNjcmV0")]
    await mw(_http_scope(headers), _empty_receive, rec.send)

    assert not rec.app_called
    assert rec.messages[0]["status"] == 401


@pytest.mark.asyncio
async def test_accepts_correct_token() -> None:
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    headers = [(b"authorization", b"Bearer s3cret")]
    await mw(_http_scope(headers), _empty_receive, rec.send)

    assert rec.app_called
    assert rec.messages[0]["status"] == 200


@pytest.mark.asyncio
async def test_passes_through_non_http_scope() -> None:
    """Lifespan / websocket scopes must not be challenged."""
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    await mw({"type": "lifespan"}, _empty_receive, rec.send)

    assert rec.app_called


def test_constructor_rejects_empty_token() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        BearerAuthASGI(lambda *_: None, token="")  # type: ignore[arg-type]


def test_build_app_without_token_returns_raw_sse_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """When MCP_AUTH_TOKEN is unset, build_app returns the SSE app unwrapped."""
    from sec_recon_agent.mcp_server import server as srv

    monkeypatch.setattr(srv.settings, "mcp_auth_token", None)
    app = srv.build_app()
    assert not isinstance(app, BearerAuthASGI)


def test_build_app_with_token_wraps_in_bearer_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """When MCP_AUTH_TOKEN is set, build_app wraps the SSE app in BearerAuthASGI."""
    from pydantic import SecretStr

    from sec_recon_agent.mcp_server import server as srv

    monkeypatch.setattr(srv.settings, "mcp_auth_token", SecretStr("s3cret"))
    app = srv.build_app()
    assert isinstance(app, BearerAuthASGI)


# --- end to end: the real ASGI app on a real socket -------------------------
#
# The unit tests above prove the middleware; they cannot prove that the
# agent's client can get THROUGH it. That gap is exactly how the control
# shipped for two months with an enablement path that took the stack down.
# So: serve build_app() with a token on an ephemeral loopback port, drive a
# tool listing with the same client class the agent uses, and assert the
# unauthenticated client is refused and a rebinding Host is refused.

TOKEN = "s3cret-live"


class _LiveServer:
    """uvicorn on 127.0.0.1:0 in a daemon thread; port known after startup."""

    def __init__(self, app: Any) -> None:
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"),
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self.port = 0

    def __enter__(self) -> "_LiveServer":
        self._thread.start()
        deadline = time.monotonic() + 15
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn did not start in time")
            time.sleep(0.02)
        self.port = self._server.servers[0].sockets[0].getsockname()[1]
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=15)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def live_authed_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_LiveServer]:
    monkeypatch.setattr(srv.settings, "mcp_auth_token", SecretStr(TOKEN))
    srv._register_tools()
    with _LiveServer(srv.build_app()) as live:
        yield live


def _flatten(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for sub in exc.exceptions for leaf in _flatten(sub)]
    return [exc]


async def test_agent_client_gets_through_the_gate_with_the_token(
    live_authed_server: _LiveServer,
) -> None:
    async with MCPToolset(
        f"{live_authed_server.url}/sse",
        headers={"Authorization": f"Bearer {TOKEN}"},
    ) as toolset:
        tools = await toolset.list_tools()
    names = {tool.name for tool in tools}
    assert "cve_lookup" in names and "kev_check" in names


async def test_agent_client_without_the_token_is_refused(
    live_authed_server: _LiveServer,
) -> None:
    # The SDK wraps the 401 in anyio task groups; flatten before asserting.
    with pytest.raises(Exception) as excinfo:
        async with MCPToolset(f"{live_authed_server.url}/sse") as toolset:
            await toolset.list_tools()
    leaves = _flatten(excinfo.value)
    assert any(
        isinstance(leaf, httpx.HTTPStatusError) and leaf.response.status_code == 401
        for leaf in leaves
    ), [repr(leaf) for leaf in leaves]


def test_rebinding_host_is_refused_even_with_the_token(live_authed_server: _LiveServer) -> None:
    """DNS rebinding: the attacker's page resolves to 127.0.0.1 but the
    browser sends the attacker's domain as Host. Refused before any tool code."""
    with httpx.Client(timeout=5) as client:
        response = client.get(
            f"{live_authed_server.url}/sse",
            headers={"Host": "evil.example:8001", "Authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 421


def test_browser_origin_is_refused_even_with_the_token(live_authed_server: _LiveServer) -> None:
    """Nothing browser-side talks to this server: any Origin header is refused."""
    with httpx.Client(timeout=5) as client:
        response = client.get(
            f"{live_authed_server.url}/sse",
            headers={"Origin": "http://127.0.0.1:3000", "Authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 403


def test_dns_rebinding_protection_is_explicit_not_inherited() -> None:
    """FastMCP auto-enables the protection only for loopback binds; compose
    binds 0.0.0.0, so the server must set it itself."""
    transport_security = srv.mcp.settings.transport_security
    assert transport_security is not None
    assert transport_security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:*" in transport_security.allowed_hosts
    assert "mcp-server:*" in transport_security.allowed_hosts
    assert transport_security.allowed_origins == []
