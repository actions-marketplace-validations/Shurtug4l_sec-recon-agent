"""Centralized settings loaded from environment variables."""

from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Loopback in both IP families plus the docker-compose service name, each with
# any port: the complete set of Host values a legitimate client of the MCP
# server sends. Everything else is a rebinding attempt or a misconfiguration.
DEFAULT_MCP_ALLOWED_HOSTS: tuple[str, ...] = (
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
    "mcp-server:*",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    anthropic_api_key: SecretStr | None = None
    nvd_api_key: SecretStr | None = None
    github_token: SecretStr | None = None

    # API authentication: comma-separated list of accepted keys. When
    # the list is empty (default), /v1/triage and /v1/meta are open.
    # When set, every protected endpoint requires
    # `Authorization: Bearer <key>` or `X-API-Key: <key>`. Health stays
    # public.
    #
    # NoDecode opts out of pydantic-settings's default "parse env value
    # as JSON" for list[] fields — we want plain CSV input, handled by
    # the validator below.
    api_keys: Annotated[list[SecretStr], NoDecode] = Field(default_factory=list)
    # Bearer token for the MCP transport. When unset (default), the MCP
    # server is open (relies on the docker-compose internal network /
    # localhost binding for isolation). When set, every HTTP request to
    # the MCP server must carry `Authorization: Bearer <token>`. Use this
    # whenever the MCP port is published beyond the container network.
    mcp_auth_token: SecretStr | None = None
    # Per-IP rate limit on /v1/triage, in requests per minute. 0 or
    # None disables the limiter. Set to e.g. 30 for a dev deployment;
    # production behind a real WAF would set this much lower or rely
    # on the WAF instead.
    rate_limit_per_minute: int | None = Field(default=None, ge=0, le=10_000)

    @field_validator("api_keys", mode="before")
    @classmethod
    def _split_api_keys(cls, raw: object) -> object:
        """Accept either a Python list or a comma-separated env string."""
        if raw is None or raw == "":
            return []
        if isinstance(raw, str):
            return [k.strip() for k in raw.split(",") if k.strip()]
        return raw

    @field_validator("rate_limit_per_minute", mode="before")
    @classmethod
    def _empty_rate_limit_to_none(cls, raw: object) -> object:
        # docker-compose passes RATE_LIMIT_PER_MINUTE: "${RATE_LIMIT_PER_MINUTE:-}",
        # which becomes "" when the host env var is unset. Pydantic 2.x does
        # not coerce "" to None for int|None fields, so treat empty string as
        # "limiter disabled" to keep the documented default behavior.
        if isinstance(raw, str) and raw.strip() == "":
            return None
        return raw

    llm_provider: str = "anthropic"
    # Default cheapest-tier model. Override via LLM_MODEL env (claude-sonnet-4-6
    # or claude-opus-4-7) for stronger reasoning at higher cost per query.
    llm_model: str = "claude-haiku-4-5-20251001"

    mcp_server_host: str = "127.0.0.1"
    mcp_server_port: int = Field(default=8001, ge=1024, le=65535)
    # Host header values the MCP server accepts (DNS-rebinding protection,
    # always on). Comma-separated; `host:*` matches any port. Blank means the
    # default below, so an operator cannot lock every client out by exporting
    # an empty variable. The compose service name is listed because that is
    # the Host the agent-api container sends; a browser page rebinding its own
    # domain to 127.0.0.1 sends that domain instead and is refused with 421.
    mcp_allowed_hosts: str = ""
    agent_api_host: str = "127.0.0.1"
    agent_api_port: int = Field(default=8000, ge=1024, le=65535)

    chroma_persist_dir: Path = Path("./data/cve_index")
    # Hybrid retrieval switch for cve_semantic_search: dense MiniLM cosine
    # fused (reciprocal-rank fusion) with an in-process BM25 over the same
    # corpus. CVE text is identifier-heavy (product names, version strings),
    # which dense embeddings blur and BM25 matches exactly. False restores
    # the dense-only path.
    retrieval_hybrid_enabled: bool = True
    audit_db_path: Path = Path("./data/audit.db")
    # Master switch. When False the API does not even open the audit
    # database; useful for ephemeral demos and for tests that don't want
    # a stray SQLite file in tmp.
    audit_log_enabled: bool = True
    # Privacy switches: default off. Operators with a compliance posture
    # that requires plain-text retention flip these on per-deployment.
    audit_include_query: bool = False
    audit_include_summary: bool = False

    nvd_rate_limit_per_30s: int = Field(default=5, ge=1, le=50)

    # Runaway-loop guard: the maximum number of model requests (ReAct rounds)
    # one triage may make before Pydantic AI raises UsageLimitExceeded. A
    # legitimate triage converges in a handful of rounds because Anthropic
    # models batch tool calls per turn; a stuck agent (a tool that keeps
    # failing, an over-broad query) otherwise thrashes for 180s+ until the
    # client times out. 25 leaves generous headroom over observed legitimate
    # use while bounding the pathological case; tune down after a live eval.
    # pydantic-ai's own default is 50, deliberately tightened here.
    agent_request_limit: int = Field(default=25, ge=1, le=200)

    # Orthogonal bounds on one run. The round cap above counts model
    # requests; Anthropic models batch tool calls per turn, so rounds alone
    # bound neither tool calls nor tokens, and tokens are what cost money:
    # every round re-sends the whole conversation. Both sit well above the
    # recorded golden runs (max 8 rounds, ~110k tokens on the SBOM case) and
    # well below the pathological case. Blank keeps the default; `off` disables.
    agent_tool_calls_limit: int | None = Field(default=40, ge=1, le=1000)
    agent_total_tokens_limit: int | None = Field(default=250_000, ge=1_000)

    # Wall-clock deadline for one triage, in seconds (`off` disables). Nothing else bounds
    # elapsed time: one NVD call can legitimately take ~75s (tenacity backoff
    # on top of the httpx timeout), so the deadline sits above the recorded
    # p95 (126s) with headroom for a slow feed and far below "until the
    # client gives up". The run is cancelled, whatever it consumed is still
    # charged to the budget window and sealed into the audit trail.
    triage_deadline_seconds: float | None = Field(default=300.0, gt=0)

    # Denial-of-wallet guard: a hard ceiling on estimated LLM spend (USD)
    # summed in-process over a rolling 24h window across all triage runs. None
    # disables it. When the window sum reaches the ceiling, /v1/triage refuses
    # new runs with 503 until older spend ages out. The window lives in memory,
    # so it resets on restart; that still bounds spend between restarts, which
    # is the denial-of-wallet threat for a reachable LLM endpoint. The
    # per-request round cap (agent_request_limit) bounds a single run's cost;
    # this bounds the aggregate an attacker can drive by repeating requests.
    denial_of_wallet_usd_per_day: float | None = Field(default=None, ge=0)

    # Kill-switch: when the env flag is set OR the sentinel file exists,
    # /v1/triage refuses with 503 without a redeploy. Both are checked per
    # request, so `touch`/`rm` on the sentinel path (a mounted volume) toggles
    # the service live; the env flag is the always-off form decided at deploy.
    kill_switch: bool = False
    kill_switch_file: Path | None = None

    @field_validator(
        "agent_request_limit",
        "agent_tool_calls_limit",
        "agent_total_tokens_limit",
        "triage_deadline_seconds",
        mode="before",
    )
    @classmethod
    def _run_bound_blank_is_default_off_is_none(cls, raw: object, info: ValidationInfo) -> object:
        # docker-compose passes an unset host var as "". For a safety bound an
        # empty value must keep the built-in default, never silently disable
        # it (that is how three bounds shipped disabled in compose on first
        # try). Disabling one is a deliberate, spelled-out choice: "off".
        if isinstance(raw, str):
            text = raw.strip().lower()
            if text == "":
                assert info.field_name is not None
                return cls.model_fields[info.field_name].default
            if text in {"off", "none", "disabled"}:
                return None
        return raw

    @field_validator("denial_of_wallet_usd_per_day", mode="before")
    @classmethod
    def _empty_budget_to_none(cls, raw: object) -> object:
        # docker-compose passes the unset host var as "", which pydantic will
        # not coerce to None for float|None. Treat empty string as "disabled".
        if isinstance(raw, str) and raw.strip() == "":
            return None
        return raw

    @field_validator("kill_switch_file", mode="before")
    @classmethod
    def _empty_kill_switch_file_to_none(cls, raw: object) -> object:
        if isinstance(raw, str) and raw.strip() == "":
            return None
        return raw

    @field_validator("kill_switch", mode="before")
    @classmethod
    def _empty_kill_switch_to_false(cls, raw: object) -> object:
        # docker-compose passes the unset host var as ""; pydantic will not
        # coerce "" to a bool. Treat empty string as "off".
        if isinstance(raw, str) and raw.strip() == "":
            return False
        return raw

    log_level: str = "INFO"

    @property
    def mcp_server_url(self) -> str:
        return f"http://{self.mcp_server_host}:{self.mcp_server_port}"

    @property
    def mcp_allowed_hosts_list(self) -> list[str]:
        """Parsed `mcp_allowed_hosts`; the built-in default when blank."""
        entries = [h.strip() for h in self.mcp_allowed_hosts.split(",") if h.strip()]
        return entries or list(DEFAULT_MCP_ALLOWED_HOSTS)


settings = Settings()
