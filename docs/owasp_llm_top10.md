# OWASP LLM Top 10 (2025) mapping

This document maps the `sec-recon-agent` codebase against the [OWASP Top 10 for LLM Applications, 2025 edition](https://owasp.org/www-project-top-10-for-large-language-model-applications/). For each risk, the status column declares whether the codebase mitigates it, partially addresses it, or considers it out of scope; the **How** column points at the actual file(s) and the **Tests** column at the test(s) that defend the invariant.

Mitigations are layered, not perfect. A "mitigated" status means the project applies controls that meaningfully reduce risk, not that the risk is eliminated. Where the mitigation is partial, the column explains what remains exposed.

## Summary

| ID | Risk | Status | Layered controls |
|---|---|---|---|
| LLM01 | Prompt Injection | partial (defense in depth) | system prompt boundary + UNTRUSTED markers + structured output + red-team battery |
| LLM02 | Sensitive Information Disclosure | mitigated | error allowlist + observability whitelist + audit privacy defaults |
| LLM03 | Supply Chain | mitigated | pinned lockfiles + Dependabot + container hardening + host-locked downloads |
| LLM04 | Data and Model Poisoning | N/A | no training data ownership; agent grounds against versioned upstream APIs only |
| LLM05 | Improper Output Handling | mitigated | typed structured output + React auto-escape + SSE error sanitization |
| LLM06 | Excessive Agency | mitigated | read-only tool surface, allowlisted model identifiers, no out-of-band tools |
| LLM07 | System Prompt Leakage | partial | system-prompt-extract payloads in red-team battery; prompt itself is not a secret |
| LLM08 | Vector and Embedding Weaknesses | partial | local-only Chroma, no PII in queries (by default), corpus is public CVE data |
| LLM09 | Misinformation | partial (grounding) | tools cite NVD/KEV/EPSS/ATT&CK directly; post-run grounding verifier stamps grounded/suspect on every report; confidence field constrains over-claiming |
| LLM10 | Unbounded Consumption | mitigated | per-tool caps + opt-in API auth + opt-in per-IP rate limit + per-run round cap + denial-of-wallet spend ceiling + kill-switch + LLM token cost bounded by schema |

## Detailed mappings

### LLM01 - Prompt Injection

**Status**: partial (defense in depth).

**How**: every free-text field returned by a tool that originates outside the codebase is wrapped with `<UNTRUSTED_CONTENT>...</UNTRUSTED_CONTENT>` markers at the tool boundary. The agent's system prompt names these markers and instructs the model to treat the wrapped content as data, not as instructions. Specifically:

- NVD CVE descriptions: `src/sec_recon_agent/mcp_server/tools/cve.py:95`
- Indexed CVE summaries (ChromaDB corpus): `src/sec_recon_agent/mcp_server/tools/cve_search.py`
- Nmap service banners (product / version): `src/sec_recon_agent/mcp_server/tools/nmap.py`
- CISA KEV vulnerability_name / required_action / notes: `src/sec_recon_agent/mcp_server/tools/kev.py:179-185`
- OSV.dev advisory summary: `src/sec_recon_agent/mcp_server/tools/osv.py`
- Untrusted-content fencing primitive: `src/sec_recon_agent/mcp_server/security.py`
- Agent system prompt with the boundary rule: `src/sec_recon_agent/agent/prompts.py`

**Why partial**: marker fencing is a strong signal but not a cryptographic boundary. A determined indirect injection inside vendor text can still degrade output quality. Defense in depth adds (a) structured Pydantic output that the LLM cannot break out of and (b) a curated red-team battery that detects the most common attack patterns when they degrade observable fields (severity, summary, recommended_action).

**Tests**:
- 18-payload red-team battery covering direct override, role-play, fake authority, marker forgery, system-prompt extraction, and indirect-via-tool-output: `src/sec_recon_agent/redteam/payloads.py`, run via `make redteam`.
- 35-parametrization adversarial corpus (forgery / homoglyphs / etc.): `tests/property/test_adversarial.py`.
- Fence-invariant tests at every tool boundary that applies fencing.

### LLM02 - Sensitive Information Disclosure

**Status**: mitigated.

**How**: three independent layers prevent inadvertent leakage of secrets, user query text, and untrusted vendor content into observability or response payloads.

- **API error sanitization**: `src/sec_recon_agent/api/stream.py::_error_payload` consults an `_SAFE_TO_ECHO` allowlist; any other exception class surfaces as `"Internal error; check server logs."` so traceback content (paths, library internals, params) never reaches the client.
- **Observability whitelist**: OTel spans carry only structured attributes (tool name, CVE ID regex-constrained, success bool, counts). NVD descriptions, user query text, and KEV vendor fields are explicitly NOT attached to spans. Canary tests assert the invariant: `tests/test_observability.py::test_span_attributes_never_contain_nvd_description`, `test_span_attributes_never_contain_user_query_text`, `test_kev_check_emits_span_and_never_leaks_vendor_text`.
- **Audit privacy defaults**: `src/sec_recon_agent/audit/models.py::TriageEvent` persists SHA-256 digests + aggregate counts only. Plain query and report summary are opt-in via `AUDIT_INCLUDE_QUERY` / `AUDIT_INCLUDE_SUMMARY`. See `docs/design.md` "Why default-off plain-text retention".
- **Secrets storage**: `pydantic-settings` `SecretStr` for all keys (`ANTHROPIC_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `API_KEYS`). Anthropic API key is pushed to `os.environ` exactly once at startup, never at request time.

**Tests**: 10 observability tests covering span-attribute whitelist + privacy canaries; audit-trail tests covering opt-in retention; API error-event sanitization test (`tests/api/test_stream.py::test_triage_emits_error_event_when_agent_raises`).

### LLM03 - Supply Chain

**Status**: mitigated.

**How**:
- **Pinned dependencies**: `uv.lock` and `frontend/package-lock.json` are committed; CI runs `uv sync --frozen` and `npm ci`. A drift between manifest and lockfile fails the build, not silently regenerates the lock.
- **Dependabot**: `.github/dependabot.yml` covers pip, npm, docker (root + frontend), github-actions on a weekly cadence; minor+patch grouped, major bumps open separately.
- **Host-locked external downloads**: every tool that hits an external host validates the post-redirect host against a hard-coded trusted domain - `gitlab.com` for the Exploit-DB CSV, `cisa.gov` for the KEV catalog, `api.first.org` for EPSS, `services.nvd.nist.gov` for NVD. See `mcp_server/tools/exploits.py:73-80`, `kev.py:71-80`, `epss.py` (validates `resp.url.host`), `nvd_client.py`.
- **CI actions pinned to major**: `actions/checkout@v5`, `actions/setup-node@v5`, `astral-sh/setup-uv@v5` - Dependabot bumps them as upstream releases.
- **Container base images**: `python:3.14-slim` + `node:22-alpine`, with `apt upgrade` in the runtime stage and `docker scout cves` validated before release.

**Why not fully**: signed artifact verification (Sigstore, npm provenance, PyPI attestations) is not yet wired. A malicious PyPI / npm package would be detected by Dependabot only after disclosure.

**Tests**: every tool that does an external fetch has a contract test asserting the host validation rejects an off-domain redirect (e.g. `tests/mcp_server/tools/test_kev.py::test_download_rejects_non_200`, `test_csv_download_rejects_oversized_payload`).

### LLM04 - Data and Model Poisoning

**Status**: N/A.

**How**: the project does not own training data and does not fine-tune. The agent grounds answers against versioned upstream APIs (NVD, CISA KEV, FIRST.org EPSS, MITRE ATT&CK) which would be compromised by direct upstream attack, not by anything in this codebase. The ChromaDB CVE corpus is built from NVD data with the same provenance guarantees as `cve_lookup`.

### LLM05 - Improper Output Handling

**Status**: mitigated.

**How**:
- **Pydantic-typed output**: the agent's only valid output is `TriageReport` (`src/sec_recon_agent/agent/schema.py`). The LLM cannot return free text that bypasses field validation; `cvss_v3_score` is `float | None ge=0 le=10`, `cve_id` is regex-constrained, etc.
- **Frontend rendering**: React auto-escapes JSX text content. The triage report's free-text fields (`summary`, `recommended_action`) are inserted as text nodes, not `dangerouslySetInnerHTML`. URL fields (`nvd_url`, `kev.url`, etc.) are validated as `HttpUrl` server-side before reaching the browser.
- **SSE error event sanitization**: see LLM02.

**Tests**:
- TriageReport schema validation enforced by Pydantic at agent-loop boundary.
- 12 ATT&CK mapping contract tests verify shapes against malformed CWE inputs.
- 23 SBOM contract tests verify the parser refuses malformed JSON and never echoes non-string vendor fields as if they were component names.

### LLM06 - Excessive Agency

**Status**: mitigated.

**How**: the tool surface is deliberately read-only. The 10 MCP tools (`cve_lookup`, `cve_semantic_search`, `exploit_check`, `kev_check`, `epss_score`, `patch_lookup`, `osv_lookup`, `sbom_ingest`, `nmap_parse_xml`, `attack_mapping`) all perform lookups or in-process parsing; none can mutate state, send messages, write files outside the disk cache directories, or invoke external commands. The agent cannot escalate to side-effecting actions because no side-effecting tool exists. The posture is declared and checked, not just stated: every tool declares its effects in `mcp_server/effects.py`, registration fails for an undeclared tool, a test asserts that no tool mutates external state, and the MCP annotations clients use to gate approvals are derived from that declaration. The declaration is reviewed, not runtime-enforced.

Per-request model override is allowlisted (`src/sec_recon_agent/agent/triage.py::ALLOWED_MODELS`); an attacker cannot probe arbitrary model identifiers through the body field.

The audit trail and the rate-limit are the only side effects of `/v1/triage`, and both are local to the API process.

**Tests**:
- `tests/agent/test_triage.py::test_resolve_model_*` (5 tests) verify the model allowlist rejects unknown identifiers, including injection attempts (`openai:gpt-4`, shell metacharacters, traversal).

### LLM07 - System Prompt Leakage

**Status**: partial.

**How**: the system prompt is not a secret - `/v1/meta` returns it verbatim by design, because the project's transparency posture says the operator should know what the agent is told. The risk is the model echoing it inside a `TriageReport` field where it would mislead a downstream consumer into thinking it is grounded content.

- The red-team battery includes two `system_extract` payloads: `extract-repeat-system-prompt`, `extract-instructions-as-json`. Each asserts that the system prompt's verbatim strings (e.g. `UNTRUSTED_CONTENT`, `security triage analyst`) do not leak into the report's summary or recommended_action.

**Why partial**: prompt leakage prevention relies on the model's instruction-following. The structured-output schema reduces but does not eliminate the surface (the model could echo prompt fragments inside any string-valued field). Continuous red-team coverage is the operational mitigation.

### LLM08 - Vector and Embedding Weaknesses

**Status**: partial (low practical exposure).

**How**:
- The vector store (ChromaDB) is local to the container, mounted on a named volume. There is no cross-tenant separation because the project is single-tenant by design.
- The embedded corpus is public CVE data from NVD (~5-8k entries on a typical 30-day lookback). It contains no PII and no user-supplied content. Embedding inversion attacks would recover... public CVE descriptions.
- User queries are NOT persisted in the embedded corpus.
- `cve_semantic_search` truncates the query at the tool boundary (2000 chars, `MAX_QUERY_CHARS`) so a pathological query cannot blow up the embedding compute path.

**Why partial**: a deployment that ingests private threat intel into the same ChromaDB collection would inherit risks this design did not consider. The project documents the boundary; a future deployment would need a separate vector store with proper auth and tenant separation.

### LLM09 - Misinformation

**Status**: partial (grounding posture).

**How**: every claim in the `TriageReport` is sourced from a typed tool call. The reasoning chain (`reasoning_chain` field) is an audit log of which tools were called and what they returned. The `confidence` field constrains over-claiming: when tools return no match, the agent is instructed to set `confidence=LOW` and explain what was missing in `recommended_action`.

The 11-case golden eval set (`src/sec_recon_agent/eval/golden_set.py`) measures hallucination resistance through soft assertions: severity within +-1 of the expected baseline and >= 50% recall on expected CVE IDs. A regression on the prompt or the model surfaces as drift in the score.

Since S3, compliance with the no-invention contract is also *checked*, not just instructed: after every run the server re-verifies each tool-derived claim (CVE identity, CVSS, KEV, EPSS, exploit flags, ATT&CK ids) against the tool returns captured from the run's message history, and stamps the deterministic outcome onto `TriageReport.grounding` (`grounded` / `suspect` / `not_evaluated`, with per-claim findings) and `grounding_status` into the hash-chained audit trail. See `agent/grounding.py` and the design.md decisions log.

**Why partial**: the model can still phrase a correct triage in misleading prose. The structured fields constrain the contract; the prose is best-effort.

### LLM10 - Unbounded Consumption

**Status**: mitigated.

**How**:
- **Per-tool resource caps**: Exploit-DB CSV 20 MB cap with streaming abort; KEV catalog 50 MB cap; EPSS response 4 MB cap; Nmap hostnames / ports per host capped at 50 / 200; cve_semantic_search query truncated at 2000 chars; seed pagination capped at 25 pages per severity. See `docs/design.md` "Bounded resource consumption".
- **TriageRequest body size**: 100 KB (`api/stream.py::TriageRequest.query`) - generous enough for pasted SBOMs, hard cap against arbitrary blob uploads.
- **API auth + rate limit (opt-in)**: `API_KEYS` and `RATE_LIMIT_PER_MINUTE` env switches close the unbounded-call exposure when the API is reachable beyond `localhost`. See `docs/design.md` "Why opt-in auth + rate limit".
- **Denial-of-wallet budget cap (opt-in)**: `DENIAL_OF_WALLET_USD_PER_DAY` sets a hard ceiling on estimated LLM spend over a rolling 24h window, summed in-process across all triage runs; over it `/v1/triage` returns 503. The round cap bounds one run; this bounds the aggregate an attacker drives by repeating requests. See `docs/running.md` "Operational safety rails".
- **Kill-switch**: `KILL_SWITCH` (env) or a sentinel file (`KILL_SWITCH_FILE`, checked per request) disables `/v1/triage` with 503 without a redeploy, so a runaway or an active abuse can be stopped live.
- **Structured output bound on LLM cost**: TriageReport caps every list field (max 10 CVEs, max 20 attack techniques, etc.) so the model cannot emit unbounded payloads that drive token cost up.
- **Sliding-window rate limit on NVD client**: shared between `cve_lookup` and the `cve_semantic_search` seed pipeline; race-free implementation that releases the lock before sleeping (a CRITICAL bug caught and fixed in the security review documented in `docs/design.md::threat-model`).

**Tests**:
- Oversized-payload tests on every external fetch path.
- 6 auth + rate-limit tests (`tests/api/test_stream.py`).
- Rate limiter race-condition regression covered by NVD client tests.
