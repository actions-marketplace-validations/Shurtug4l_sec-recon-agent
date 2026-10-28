# MCP server self-audit

This project *is* an MCP server (ten typed tools over HTTP+SSE) as well as an
MCP client (the Pydantic AI agent). An MCP server is a plugin surface exposed to
an LLM: every tool is an action the model can invoke with arguments it chooses,
against inputs (NVD descriptions, scan banners, SBOM text) an attacker may
control. This document audits that surface tool-by-tool and cross-cutting,
mapping findings to **OWASP LLM07 (Insecure Plugin / Tool Design)** and **OWASP
LLM08 (Excessive Agency)** and to the community "MCP security" anti-patterns
(tool poisoning, rug-pull, confused deputy, token pass-through, naming
collision). It is a self-audit, not a third-party certification; residual risks
are named, not hidden (same posture as [`security_findings.md`](security_findings.md)).

Every control below is grounded in code in `src/sec_recon_agent/mcp_server/`.
To re-run an external check, point an MCP security scanner at the SSE endpoint
(`:8001/sse`) with `MCP_AUTH_TOKEN` set; the findings here are what such a scan
should confirm.

## Attack surface at a glance

- **Transport**: FastMCP over HTTP+SSE (`server.py::build_app`). Optional bearer
  auth via `MCP_AUTH_TOKEN` (`auth.py::BearerAuthASGI`, `secrets.compare_digest`,
  constant-time), enforced by the server and presented by the agent's MCP client
  from the same setting (`agent/triage.py::_mcp_toolset`), so one variable gates
  both ends; an integration test drives the real app on a live socket. Default
  off: compose publishes `:8001` on the host loopback only, and the token is
  meant to be set whenever that is not acceptable or the port is published
  further. DNS-rebinding protection is always on (`TransportSecuritySettings`:
  Host allowlist from `MCP_ALLOWED_HOSTS`, no browser Origin accepted), because
  binding `0.0.0.0` in compose would otherwise leave FastMCP's loopback-only
  auto-enable off.
- **Primitives exposed**: tools only. The server exposes **no** MCP `resources`,
  `prompts`, `sampling`, `elicitation`, or `roots` primitives. Those are the
  primitives most abused for confused-deputy and prompt-injection-via-resource
  attacks; not exposing them removes that surface entirely.
- **Side effects**: every tool is **read-only** with respect to the caller.
  There is no tool that writes to a user-controlled path, sends a message,
  executes a command, or mutates external state. The only writes are local,
  server-owned state at fixed paths (KEV / Exploit-DB manifests, the Chroma
  index directory). This is the LLM08 posture: minimal agency by construction.
  The declarations behind the table below are checked; the table itself is
  not. Each tool's egress hosts and server-state writes are declared in
  `mcp_server/effects.py`; tests (`tests/mcp_server/test_effects.py`) pin that
  declaration to the served tool set, to each feed URL and `*_TRUSTED_HOST`,
  and to the egress-proxy allowlist, and assert that no tool mutates external
  state. The advertised MCP annotations (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`) are derived from it, and a tool without
  an entry fails registration. Whether a declaration is true remains a review
  property: a new outbound call inside a tool is caught in review, not by a
  test.
- **Untrusted content**: free-text fields lifted from third parties are wrapped
  in `<UNTRUSTED_CONTENT id="...">` markers carrying a per-process random id
  (`security.py::fence_untrusted`), marker-shaped tokens inside the payload are
  neutralized, and the system prompt names the markers and forbids following
  instructions found inside them.

## Per-tool audit

| Tool | Network egress | Untrusted free-text handling | Input caps / hardening | Side effects |
|---|---|---|---|---|
| `cve_lookup` | NVD (shared rate-limited client) | `references` marked UNTRUSTED (docstring + Field + prompt); description is data | `CveIdStr` regex-bounded | none (read) |
| `cve_semantic_search` | none at query (local ChromaDB) | `summary` fenced via `fence_untrusted` | query truncated (`MAX_QUERY_CHARS`), `top_k` clamped, offloaded to a thread | local index write only (a cold volume creates the Chroma collection) |
| `exploit_check` | Exploit-DB (`gitlab.com`, host-locked) + optional GitHub Code Search + GitHub repository metadata (`api.github.com`) | per-source status (`found` / `not_found` / `error` / `skipped`); GitHub hits as repository URLs only, from established repositories (5 stars or 30 days), bound to `HttpUrl`, capped; unverified candidates counted | host-lock on redirect (`EXPLOITDB_TRUSTED_HOST`), cached manifest, arms settle independently | local cache write only |
| `kev_check` | CISA (`cisa.gov`, host-locked) | `vulnerability_name` / `required_action` / `notes` fenced, `max_length` includes marker overhead | host-lock on redirect (`KEV_TRUSTED_HOST`), 24h disk cache | local cache write only |
| `epss_score` | FIRST.org (`api.first.org`, host-locked) | no free text (numeric + status enum) | host-lock, 4 MB response cap, typed errors | none (read) |
| `patch_lookup` | NVD (shared client) | `references` marked UNTRUSTED | `CveIdStr` bounded, fixed-entries capped | none (read) |
| `osv_lookup` | OSV.dev (`api.osv.dev`, host-locked) | `summary` fenced; `references` filtered to http(s) before `HttpUrl` bind | host-lock on redirect, response byte cap, ecosystem `Literal` (no unknown fallback) | none (read) |
| `nmap_parse_xml` | none (in-process) | `product` / `version` banners fenced (200-char budget); `service` / `protocol` / `state` / address / hostnames length-capped | `defusedxml(forbid_dtd=True)` (XXE-safe), 20 MB input cap, 1000-host cap, double-enforced | none (read) |
| `attack_mapping` | none (bundled JSON) | curated table, no untrusted text | 200-CWE list cap, 40-char per-entry cap, raises `InvalidCweInputError` | none (read) |
| `sbom_ingest` | none (in-process) | component names bounded, not fenced | JSON-only (no XML), 500-component cap, `truncated` flag | none (read) |

## Cross-cutting controls

### LLM07 - Insecure plugin / tool design

- **Typed I/O contract.** Every tool returns a Pydantic model (`models.py`);
  the agent's output is itself a validated `TriageReport`. There is no free-form
  string tool that the model could coerce into arbitrary behavior.
- **Input validation at the boundary.** Bounded inputs are `Annotated[... ,
  Field(...)]` at the MCP boundary AND re-checked at runtime for direct callers
  (the double-cap pattern on `nmap_parse_xml` / `attack_mapping`). CVE IDs are
  regex-bounded; the OSV ecosystem is a closed `Literal` (an unknown value is
  rejected rather than silently returning an empty "not vulnerable").
- **Untrusted-content fencing** (tool poisoning defense). Third-party free text
  is fenced; each tool's contract tests assert the markers on its fenced fields,
  and a sizing contract test (`tests/mcp_server/test_security.py`) pins the
  inventory of fenced fields against the security module's docstring and checks
  every cap is payload budget plus `FENCE_OVERHEAD`, so a new fenced field
  cannot ship undocumented or with a hand-typed cap. (An earlier revision of
  this note described a registration-walking coverage test that did not
  exist; corrected 2026-09-22.)
- **Host-locking** (SSRF / exfil defense). Every outbound feed pins its host and
  re-checks it after redirects (`*_TRUSTED_HOST`), so a hostile redirect cannot
  turn a tool into an SSRF pivot or a data-exfil channel.

### LLM08 - Excessive agency

- **No state-changing tools.** The blast radius of a fully compromised prompt is
  bounded by "the model produced a wrong triage report": there is no tool to
  delete, send, execute, or write to a caller-supplied path. Excessive agency is
  designed out.
- **Degraded mode.** On tool failure the system prompt forbids inventing CVE
  IDs, CVSS scores, release dates, or upgrade targets; the agent defers to named
  external sources. A failing tool cannot be leveraged into fabricated
  authority.
- **Deterministic prioritization.** The SSVC verdict is computed server-side
  from the collected signals, not by the LLM (`agent/ssvc.py`), so a
  prompt-injected model cannot silently downgrade an Act to a Track - the
  structured verdict is recomputed from the signals regardless of the prose.

### MCP-specific anti-patterns

- **Tool poisoning** (malicious instructions in tool output): mitigated by the
  fencing + system-prompt boundary + the red-team battery's `marker_forgery` and
  `indirect` payloads.
- **Rug-pull** (a tool changing behavior after approval): the tool surface is
  in-repo and versioned; there is no dynamic tool registration from an external
  server, so there is nothing to rug-pull. Adding/removing a tool is a code
  change gated by the `/v1/meta` exact-set contract test.
- **Confused deputy / token pass-through**: the server holds its own upstream
  credentials (`NVD_API_KEY`, `GITHUB_TOKEN`) as `SecretStr`; they are never
  echoed to the model or the client, and the model cannot cause the server to
  forward a caller-supplied token to a third party.
- **Naming collision**: single first-party server, no aggregation of external
  MCP servers, so no tool-name shadowing across servers.

### Logging & error hygiene

- **Observability allowlist.** Span attributes are a fixed, non-PII set;
  privacy invariant tests assert no secret, user query text, NVD description, or
  KEV vendor text lands in a span attribute (the EPSS span carries only the
  `epss.status` enum + numeric probability).
- **Error leakage.** The API surface echoes only whitelisted exception messages
  to the SSE client; everything else is replaced with a generic message so
  internal paths / library internals do not leak.

## Residual risks (accept-and-document)

- **Prompt injection is mitigated, not solved.** Defense in depth (fencing +
  system prompt + schema-bounded output + deterministic SSVC + red-team battery)
  raises the bar; it does not eliminate the class. Tracked in
  [`security_findings.md`](security_findings.md).
- **Auth is opt-in.** `MCP_AUTH_TOKEN` defaults off for frictionless local dev.
  Publishing `:8001` beyond loopback without setting it exposes the tools
  unauthenticated on the network - an explicit deployment decision, documented
  in the README and `.env.example`. Until 2026-09-22 the variable reached
  neither compose service and the agent's client sent no header, so the gate
  could not actually be turned on in the shipped topology; see
  [`security_findings.md`](security_findings.md).
- **Nmap output is attacker-controlled end to end.** `product` and `version`
  banners are fenced with their own budget; `service`, `protocol`, `state`,
  the address and the hostnames are short identifiers, length-capped but not
  fenced. A crafted scan can still put up to 200 characters of prose inside
  each fenced banner, which is a proportionate injection window, not a
  megabyte one (the caps landed 2026-09-22; before that only the banners were
  fenced and nothing was capped).
