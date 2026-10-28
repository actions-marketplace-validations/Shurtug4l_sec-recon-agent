# Security findings - open and accepted

The Trivy workflow uploads a SARIF report to the GitHub Security tab on every successful image build and on a weekly schedule. The findings listed below are the **currently open** alerts on `main`; each one has been triaged with a documented decision.

This document covers two sources:
1. **Supply-chain findings** from Trivy / npm-audit / pip-audit / Dependabot (dependencies we ship in containers or pin in lockfiles).
2. **Internal audit findings** from periodic multi-agent review of our own code (MCP tool surface, agent flow, governance posture).

**Posture**: open findings stay open. Dismissing a CVE that we technically own (it ships inside our container) without a fix would be optics, not security. Documenting them publicly is the more honest signal: a reviewer can see the analysis, agree or disagree, and we can revisit when an upstream fix lands. The same posture applies to internal findings: we list them with the current mitigation and the planned fix path, rather than hiding them until the fix lands.

**Refresh cadence**: Trivy weekly Monday cron via `.github/workflows/ci-docker-scan.yml`. Dependabot alerts are enabled repo-wide over the `pip` and `npm` lockfiles, with automated security-update PRs. Internal audit is run on-demand (last: 2026-05-18) by spawning specialized review subagents in parallel against the code surface.

---

## Triage matrix

### Supply chain (Trivy / npm-audit / pip-audit)

| Severity | CVE / GHSA | Package | Path | Disposition | Reason |
|---|---|---|---|---|---|
| CRITICAL | CVE-2026-45829 / GHSA-f4j7-r4q5-qw2c | chromadb 1.5.9 | backend image (vector store) | accept + VEX `not_affected`, alert dismissed `not_used` | the vulnerable path is ChromaDB's pre-auth server request handling, which never runs here (embedded `PersistentClient`, no ChromaDB service); no upstream patch exists; see detailed triage + `security/vex/chromadb_cve_2026_45829.openvex.json` |
| CRITICAL | CVE-2026-45833 / GHSA-36p7-vc44-83pf | chromadb 1.5.9 | backend image (vector store) | accept + VEX `not_affected`, alert dismissed `tolerable_risk` | code injection via a collection config carrying `trust_remote_code`; the sink DOES run in embedded mode, so the justification is `vulnerable_code_cannot_be_controlled_by_adversary`, not the execute-path one: no HTTP update endpoint exists, one in-repo writer sets the default ONNX embedding function, and the Hugging Face loaders the payload needs are not in `uv.lock`; see detailed triage + `security/vex/chromadb_cve_2026_45833.openvex.json` |
| HIGH | CVE-2026-45830 / GHSA-2wm9-hf6c-p5cr | chromadb 1.5.9 | backend image (vector store) | accept + VEX `not_affected`, alert dismissed `not_used` | missing cross-tenant authorization in the HTTP server's request handling; no server, no tenants, no authenticated remote user here; see detailed triage + `security/vex/chromadb_cve_2026_45830.openvex.json` |
| HIGH | CVE-2026-45831 / GHSA-xph7-9rjv-w5fr | chromadb 1.5.9 | backend image (vector store) | accept + VEX `not_affected`, alert dismissed `not_used` | `SimpleRBACAuthorizationProvider` ignores resource scope; the class is instantiated only under `chroma_server_authz_provider`, never configured here; see detailed triage + `security/vex/chromadb_cve_2026_45831.openvex.json` |
| CRITICAL | CVE-2026-59873 | tar 7.5.11 (npm bundled) | frontend image, `node:22-alpine` base | **fixed (structural)** | npm/corepack/yarn removed from the runtime stage; no package manager on any runtime code path; see detailed triage |
| HIGH (x2) + MEDIUM | GHSA-6v7p-g79w-8964, CVE-2025-47273, CVE-2026-59890 | msgpack 1.1.2, setuptools 70.3.0 (pip vendored) | backend image, `python:3.14-slim` base | **fixed (structural)** | copies vendored inside the base image's pip (`pip/_vendor/vendor.txt`), in no lockfile and so unreachable by any bump; pip removed from the runtime stage, which never invokes it (uv builds the venv in the builder stage); see detailed triage |
| HIGH | GHSA-f88m-g3jw-g9cj | sharp | `frontend`, `next` transitive | **fixed (npm override)** | lifted via package.json `overrides` - next's semver range caps at 0.34.x so Dependabot could not reach the fix. The override is a floor (`^0.35.4`) since 2026-09-21: written as the exact `0.35.0` it blocked its own next fix (GHSA-rgj7-g3m4-5g8c, libheif), because Dependabot cannot edit `overrides`; sharp is dormant here (no `next/image` usage in src, demo export runs `images.unoptimized`) |
| HIGH | GHSA picomatch ReDoS | picomatch | `frontend` build chain | closed upstream | transitive parents refreshed over time; tree now at 2.3.2 / 4.0.4, alert no longer open (verified 2026-07-22) |
| MEDIUM | postcss XSS via stringify | postcss | `frontend` build chain | **fixed (npm override)** | build-time CSS toolchain, output is static; the project's own postcss was already 8.5.x but `next` vendored a nested 8.4.31 that Dependabot cannot reach by construction (security updates run `update-subdependencies: false`); closed 2026-07-28 with an `"postcss": "$postcss"` override that dedupes `next` onto the root copy - a literal range is rejected with `EOVERRIDE` because postcss is also a direct dependency |
| MEDIUM | picomatch POSIX bracket | picomatch | `frontend` build chain | closed upstream | same transitive refresh as the ReDoS row |
| MEDIUM | ip-address parsing | ip-address | `frontend` transitive | closed upstream | package no longer in the dependency tree (verified 2026-07-22) |
| MEDIUM | brace-expansion DoS via zero step | brace-expansion | `frontend` ESLint config parsing | **fixed (bump)** | both copies bumped to fixed versions 1.1.16 / 5.0.7 (2026-07-22); the bump also covers the newer CVE-2026-13149 (HIGH) on the same package |
| LOW (x3) | rand unsoundness with custom logger | rand (Rust) | backend image ChromaDB native bridge | accept | we do not use rand with a custom logger |

### Internal audit (multi-agent review 2026-05-18)

| Severity | Finding | Surface | Disposition | Current mitigation |
|---|---|---|---|---|
| P0 | MCP transport has no auth layer | `mcp_server/server.py` (FastMCP SSE) | **fixed (PR1)**, enablement path repaired 2026-09-22 | opt-in `MCP_AUTH_TOKEN` bearer middleware in front of the SSE app; default off so docker-compose-internal usage is unchanged. The middleware shipped in PR1, but compose forwarded the variable to neither service and the agent's client sent no header, so the gate could not be enabled until the 2026-09-22 row below |
| P1 | `nmap_parse_xml` has no size cap on input | `mcp_server/tools/nmap.py` | **fixed (PR1)** | 20MB input cap + 1000-host iteration cap, both enforced at the tool entry |
| P1 | `attack_mapping` `cwe_ids` list is unbounded | `mcp_server/tools/attack.py` | **fixed (PR1)** | 200-entry list cap + 40-char per-entry cap; oversize input raises `InvalidCweInputError` before lookup |
| P1 | NVD reference URLs not marked untrusted in output | `mcp_server/tools/cve.py`, `tools/patch.py` | **fixed (PR1)** | docstring + Pydantic `Field(description=...)` mark `references` as untrusted on `CVEDetail` and `PatchAvailability`; agent system prompt repeats the contract |
| P1 | SSE transport is legacy (Streamable HTTP is the post-2025-06-18 recommendation) | `mcp_server/server.py` | open, tracked (deprecation watch) | SDK still supports SSE; no breaking change forced yet |
| P1 | `epss_score` silently returns empty score on upstream CVE-id mismatch | `mcp_server/tools/epss.py` | **fixed (S1)** | explicit `EpssScore.status` enum (`found` / `not_found` / `upstream_error`); a CVE-id mismatch returns `upstream_error`, surfaced in the report `signal_coverage` |
| P1 | `path.write_bytes` blocks the event loop during 5-20MB cache refresh | `mcp_server/tools/exploits.py`, `tools/kev.py` | **fixed (drift-sweep-scorecard)** | `await asyncio.to_thread(path.write_bytes, ...)` in both refresh paths; the loop keeps serving tool calls during a 5-20 MB refresh, which still runs at most once per cache TTL |
| P1 | `asyncio.gather` paired with bare `create_task` leaves orphaned tasks on failure | `mcp_server/tools/exploits.py`, `tools/kev.py` | **fixed (#243)** | `AsyncClient` context exit cancels in-flight tasks; window is narrow |

---

### Internal audit (multi-agent review 2026-09-22)

| Severity | Finding | Surface | Disposition | Current mitigation |
|---|---|---|---|---|
| P0 | SSVC verdict on the agent path was computed from the model's own CVE fields: deterministic, but not independent of the model, and a suppressed lookup left no trace | `agent/ssvc.py`, `api/stream.py` | **fixed (ssvc-from-evidence)** | signals read from the typed tool returns in the run's trajectory through the shared `agent/evidence.py` index; a signal with no usable evidence falls back to the report and is stamped `basis: mixed` with the fallback named in `unverified_signals`; no trajectory is stamped `basis: report`. The gate path was already evidence-driven. |
| P1 | MCP bearer auth could not be enabled in the shipped topology: compose forwarded `MCP_AUTH_TOKEN` to neither service and the agent's `MCPToolset` sent no header, while the docs said "no extra configuration" and ":8001 not published" (compose publishes it on loopback); binding `0.0.0.0` also left FastMCP's DNS-rebinding protection off | `docker-compose.yml`, `agent/triage.py`, `mcp_server/server.py`, `docs/running.md`, `.env.example` | **fixed (mcp-auth-end-to-end)** | token forwarded to both services and presented by the agent's client; end-to-end test serves the real app on an ephemeral socket (authenticated tool listing passes, unauthenticated client gets 401); DNS-rebinding protection enabled explicitly with a `MCP_ALLOWED_HOSTS` allowlist (foreign `Host` gets 421, any browser `Origin` gets 403); compose drift test pins the wiring; docs corrected |
| P1 | Denial-of-wallet rail failed open on client disconnect: cost was recorded only after the `final` event, and the cancellation raised by the SSE layer bypasses `except Exception`; the same path sealed aborted runs as `success` with an empty report hash and recorded the deployment model instead of a per-request override; the only per-run bound was the round count | `api/stream.py`, `api/budget.py` | **fixed (triage-run-accounting)** | cost and outcome settled in the generator's `finally` through a synchronous record (an awaited one never lands inside a cancelled scope); `outcome=cancelled` for disconnects, `incomplete` until the final event is on the wire; audit `model` resolved from the request; `tool_calls_limit`, `total_tokens_limit` and a wall-clock deadline added next to the round cap, all operator-tunable in compose |
| P1 | `exploit_check` GitHub arm failed open (403 / non-200 / transport / bad body all returned `[]`, indistinguishable from "no PoC") and its positive-evidence test accepted any repository whose name contains the CVE id: one GitHub account, two minutes, and `exploits_public` flips a verdict to Attend, on the LLM path and in the no-LLM gate alike; file URLs also carried attacker-chosen path text to the model unfenced | `mcp_server/tools/exploits.py`, `mcp_server/models.py` | **fixed (exploit-check-per-arm)** | per-source status (`found` / `not_found` / `error` / `skipped`) on `ExploitCheck`, arms settled independently with `gather(return_exceptions=True)`; an errored arm is "unknown" for SSVC (fallback named as unverified), grounding (positive claims degrade to unverifiable, no mismatch) and the gate (coverage `error`); GitHub hits corroborated against repository metadata (5 stars or 30 days) and returned as repository URLs; unverified candidates counted, not hidden |
| P1 | Untrusted-content fence forgeable: `fence_untrusted` wrapped once with fixed literal markers and did not neutralize the same markers inside the payload, so upstream text containing `</UNTRUSTED_CONTENT>` closed the fence early; the case study called that "defeated structurally" and the cited test only pinned string concatenation; the system prompt never named the markers | `mcp_server/security.py`, `agent/prompts.py` | **fixed (fence-nonce-prompt-budgets-caching)** | per-process random id on both markers, named in the prompt as the only boundary; marker-shaped tokens escaped before wrapping; payload truncated after neutralization so caps hold; sizing contract test over every fenced field |
| P1 | `nmap_parse_xml` output fields unbounded: `product` / `version` fenced but uncapped, `service` / `protocol` / `state` / address / hostnames uncapped and unfenced, while `security.py` claimed hostnames were length-capped; a 20 MB scan could push megabytes of attacker prose into the model context | `mcp_server/models.py`, `mcp_server/tools/nmap.py` | **fixed (fence-nonce-prompt-budgets-caching)** | banners fenced with a 200-char budget, identifiers capped (64 / 253), hostnames capped per item; `CVEDetail.description` capped too |

## Detailed triage

### Frontend npm findings (5)

**Reconciliation 2026-07-22**: the picomatch and ip-address alerts closed upstream
(transitive refreshes; ip-address left the tree entirely), brace-expansion was bumped
to fixed versions in the lockfile (also covering the newer CVE-2026-13149 HIGH on the
same package), and sharp was forced to 0.35.0 with a package.json `overrides` entry.
Of the original set only the postcss disposition remains open: `next` pins its own
nested 8.4.31 copy, unchanged by the top-level bump to 8.5.20. The chain analysis
below is kept for the record.

All five findings live in `frontend/node_modules/` and reach the image because the Next.js build needs them at compile time. None of them are loaded at runtime by the user-facing Next.js server.

**Dependency chain** (from `npm ls`):

- **picomatch** -> transitive of `eslint-import-resolver-typescript` -> `tinyglobby` -> `fdir` and of `tailwindcss` -> `chokidar` / `micromatch`. Used during `next build` to walk source files; never at request time.
- **postcss** -> transitive of `next` (own pinned version), `tailwindcss`, `autoprefixer`, `postcss-import`. Runs once at build to produce static CSS. The cited XSS (`</style>` injection in stringify output) requires attacker-controlled CSS input, which we do not have.
- **ip-address** -> transitive of one of the test / lint chains. Not invoked from any runtime code path.
- **brace-expansion** -> transitive of `minimatch` -> ESLint and TypeScript-ESLint config-file parsing. The DoS requires a pattern like `{0..N..0}` with a zero step; our patterns come from `.eslintignore` and `tsconfig.json` (developer-controlled).

**Why we cannot bump them**: `npm audit fix --force` would downgrade `next` to 9.3.3 (the only Next version with a fixed transitive `postcss`) - a breaking change with no benefit. The same forced fix does not touch the picomatch / brace-expansion / ip-address chain because their transitive parents themselves have not bumped.

**What would change the disposition**:

- Next.js publishes a 15.x patch that bumps the transitive postcss.
- The Next.js / Tailwind / ESLint chain refreshes picomatch to a fixed version.
- We migrate the frontend off Next 15 (currently out of scope; tracked separately in the Dependabot ignore list for `next` major bumps).

### npm bundled node-tar gzip-bomb DoS (CVE-2026-59873, CRITICAL, fixed structurally)

Surfaced 2026-07-22: the `scan frontend` CRITICAL gate started failing on every PR,
including a Python-only dependency bump, which is the signature of a fresh advisory
against the base image rather than a change under review. Trivy flagged `tar` 7.5.11
(fixed in 7.5.19) at `usr/local/lib/node_modules/npm/node_modules/tar/` - node-tar as
vendored by the npm that `node:22-alpine` bundles, not a dependency of this project
(`frontend/package-lock.json` has no `tar` entry).

**Reachability**: the vulnerable path is tar extraction of a crafted gzip archive,
exercised when npm installs packages. The runtime stage runs `node server.js` and a
curl healthcheck; npm is never invoked after image build. Not exploitable in the
running container - the exposure was gate noise, not runtime risk.

**Fix (structural, this PR)**: the runtime stage now removes npm, corepack and yarn
outright (`frontend/Dockerfile`). Build stages keep them (`npm ci` / `npm run build`
happen there and never ship). This closes the whole class: future advisories against
package-manager vendored deps cannot fire on the final image because the packages are
no longer in it. Side effect: smaller image.

**Why not the alternatives**: a base-image bump was not available (the CVE is
same-day; node had not yet published images with npm bundling tar >= 7.5.19) and
would reopen at the next npm-vendored advisory; a `.trivyignore` entry would have
been justified (`not_affected`, vulnerable code not in execute path) but keeps dead
weight in the image and needs manual expiry.

### pip-vendored msgpack and setuptools in the backend image (2 HIGH + 1 MEDIUM, fixed structurally)

Trivy flagged `msgpack` 1.1.2 (GHSA-6v7p-g79w-8964, HIGH) and `setuptools` 70.3.0 (CVE-2025-47273 HIGH, CVE-2026-59890 MEDIUM) in the backend image, open since 2026-08-08. Neither package is in `uv.lock`, and a streamed scan of the two published layers that carry Python packages (the base image's Python install and the copied venv) finds no `dist-info` for either. They are the copies pip vendors inside itself. `pip/_vendor/vendor.txt` at pip 26.2.1, the version the `python:3.14-slim` base ships, pins exactly `msgpack==1.1.2` and `setuptools==70.3.0`.

**Why it could not be bumped**: a dependency that lives in no lockfile has no bump. Dependabot never saw it (no alert on that side), and the fix versions only arrive when pip re-vendors and the base image picks that pip up.

**Fix**: the runtime stage uninstalls pip and removes the bundled ensurepip wheel (`Dockerfile`). Nothing there invokes pip: uv builds the venv in the builder stage and the runtime stage copies it. The ONNX model bake runs after the removal, importing chromadb and running one inference, so a venv that secretly depended on pip would fail the build instead of the deployment.

This is the same decision as the frontend's node-tar entry above, for the same reason: a package manager in a runtime image is attack surface twice over. Its vendored dependencies collect advisories nobody can patch, and it hands an install primitive to whoever lands code execution in the container. The read-only root filesystem already blunts the second point; removing the tool removes it.

### Backend Rust findings (3 × rand LOW)

Three identical findings in `app/.../bridge/Cargo.lock` inside the backend image (`python:3.14-slim` + ChromaDB Python wheel). The vulnerability is `rand::rng()` being unsound when used with a custom logger - a narrow API contract violation in the Rust `rand` crate.

The Cargo.lock comes from a pre-compiled native bridge bundled inside ChromaDB's wheel (likely the ONNX runtime bridge that backs the local embedder). We do not call `rand::rng()` directly, and the wheel does not expose a logger configuration knob to its Python callers.

**Why we cannot bump it**: the dependency tree is frozen at ChromaDB build time and shipped as a binary wheel. Bumping requires ChromaDB to publish a new wheel built against a newer `rand`, which is upstream's responsibility.

**What would change the disposition**: a new ChromaDB release that pins `rand >= <fixed-version>`. Dependabot will surface the Python-side bump when it lands.

### ChromaDB pre-auth code injection (CVE-2026-45829, CRITICAL, no upstream fix)

Dependabot flagged `chromadb` 1.5.9 for **CVE-2026-45829 / GHSA-f4j7-r4q5-qw2c**, a pre-authentication code-injection vulnerability. The advisory range is `>= 1.0.0 <= 1.5.9` with **no patched version published**, so there is nothing to bump to.

**Reachability analysis (why the product is `not_affected`)**: the vulnerable path is pre-authentication code injection reached through ChromaDB's HTTP endpoint. This deployment never starts that endpoint. ChromaDB is used as an embedded, file-backed store: `mcp_server/tools/cve_search.py` builds a `chromadb.PersistentClient` inside the MCP server process, and `docker-compose.yml` declares no ChromaDB service (`mcp-server`, `agent-api`, `seed-job`, `frontend`, `jaeger`). The vulnerable code ships inside the installed package but sits outside every execution path, so the OpenVEX justification is `vulnerable_code_not_in_execute_path`.

Version 1 of the attestation (2026-07-11) claimed instead that "ChromaDB runs only as an internal service on the compose network" and rested on network unreachability plus the S4 egress allowlist, with justification `vulnerable_code_cannot_be_controlled_by_adversary`. That described the deployment inaccurately - there is no ChromaDB service and no endpoint to reach - and it understated the case, since an argument about who can reach a listener is weaker than one about a listener that does not exist. Corrected in version 2 (2026-08-03); the document `@id` changed with the content, as its content-hash construction requires.

**Machine-readable attestation**: `security/vex/chromadb_cve_2026_45829.openvex.json` (OpenVEX v0.2.0, `status: not_affected`), authored directly rather than through `export/openvex.py` because that renderer emits `affected` only by design (automated triage never asserts reachability); the VEX reuses the tool's `@context`, `@id` namespace, and canonicalization so the artifact stays consistent with the ones the export path produces.

**Trivy gate interaction (forward-looking)**: the container `scan backend` job did not flag this CVE (Trivy's DB has not picked up the 2026 advisory yet). When it does, the `ci-docker-scan.yml` CRITICAL gate would fail the weekly build; wire the VEX into the scan (`trivy --vex`) or add a scoped `.trivyignore` entry at that point, citing this section.

**Alert disposition**: the Dependabot alert is dismissed as `not_used`, citing this section and the attestation. Earlier the alert was deliberately left open and attested, on the reasoning that a security portfolio triages visibly rather than hiding findings. That reasoning survives - the triage is still public, in this document and in a machine-readable VEX - but an alert that can never close (no patched release exists, and none may ever ship) is a permanently red signal that trains the reader to ignore the alert list. The dismissal reason carries the meaning; the analysis lives here.

**What would change the disposition**: a patched `chromadb` release (`> 1.5.9`) - Dependabot reopens on a new advisory match and will surface the bump. Revisit the VEX and drop it once bumped.

### ChromaDB authorization and code-injection advisories (CVE-2026-45830, -45831, -45833, no upstream fix)

Three further `chromadb` 1.5.9 advisories landed on 2026-08-24, all with **no patched version published**. They share the deployment fact established above (embedded `PersistentClient`, no ChromaDB service, no `chroma_server_*` setting anywhere in `src/`, compose, or the Dockerfile), but they do not share a justification, and the difference is the point of this entry.

**CVE-2026-45830 (HIGH, missing cross-tenant authorization)** and **CVE-2026-45831 (HIGH, `SimpleRBACAuthorizationProvider` ignores resource scope)** are flaws in the HTTP server's authorization layer. Both need an authenticated remote user and a multi-tenant server to act across. `SimpleRBACAuthorizationProvider` is instantiated only when `chroma_server_authz_provider` is configured; it never is. The only caller of the store is this repository's own code in the same process, which is not subject to ChromaDB authorization at all. Justification: `vulnerable_code_not_in_execute_path`, the same as CVE-2026-45829.

**CVE-2026-45833 (CRITICAL, code injection through `trust_remote_code`)** cannot reuse that justification, because here it would be false. The advisory's entry point is the authenticated collection-update endpoint, which does not exist in this deployment. The sink, however, is the instantiation of an embedding function from a persisted collection configuration (`chromadb/api/collection_configuration.py`, `known_embedding_functions[name].build_from_config(...)`), and that code runs in embedded mode every time the collection is opened. Claiming it sits outside every execution path would repeat the mistake version 1 of the 45829 attestation made: describing the deployment as more convenient than it is. The accurate justification is `vulnerable_code_cannot_be_controlled_by_adversary`, on two independent grounds:

- **No adversary-reachable writer.** The collection configuration is written by exactly one caller, `get_or_create_collection` in `mcp_server/tools/cve_search.py`, and it names `DefaultEmbeddingFunction` (the bundled ONNX model, no kwargs). No tool argument, NVD field, or agent output flows into it.
- **The loader the payload needs is absent.** The embedding functions that forward kwargs such as `trust_remote_code` to a Hugging Face loader import `sentence_transformers` or `transformers` at construction. Neither is in `uv.lock`, and the backend image installs exactly that lock (`uv sync --frozen --no-dev`). A planted configuration raises at import instead of loading remote code.

**Residual, stated rather than hidden**: an attacker who can already write to the Chroma persist volume could alter the stored configuration. That is a different trust boundary from the advisory's (local write access to a volume mounted into containers running with a read-only root filesystem), and it still hits the missing loader. The second ground is also the fragile one: adding `sentence-transformers` or `transformers` to the dependency tree invalidates it and requires revisiting the statement. The VEX says so in its impact statement.

**Machine-readable attestations**: `security/vex/chromadb_cve_2026_45830.openvex.json`, `..._45831.openvex.json`, `..._45833.openvex.json`. One document per CVE, authored directly for the reason given above, with the same content-hashed `@id` construction.

**Alert disposition**: 45830 and 45831 are dismissed as `not_used`. 45833 is dismissed as `tolerable_risk`, not `not_used`: the vulnerable sink is used, what is missing is an adversary who controls its input, and the dismissal reason should not claim more than the analysis does.

**What would change the disposition**: a patched `chromadb` release; a ChromaDB server or authorization provider entering the deployment; any second writer of the collection configuration; or a Hugging Face loader entering `uv.lock`.

---

## Detailed triage - internal audit findings

These come from the periodic multi-agent audit (last run 2026-05-18). Unlike supply-chain findings (which we accept and document because the fix sits upstream), internal findings are ours to fix and are tracked toward concrete PRs.

### P0 - MCP transport has no auth layer (fixed)

`mcp_server/server.py` started FastMCP with the SSE transport on `:8001` without any bearer / API-key / token check. The agent-api process enforces opt-in API-key auth (`api/stream.py`), but the MCP server, which is the more powerful surface (direct tool access, no agent guardrails), enforced none.

**Previous mitigation**: the `docker-compose.yml` did NOT publish `:8001` to the host. The port was reachable only via the compose-internal network, where the only client is `agent-api`. Anyone who re-ran the container with `-p 8001:8001` or deployed outside the compose perimeter lost this mitigation.

**Fix landed**: opt-in `MCP_AUTH_TOKEN` env var. When set, every HTTP request to the MCP server must carry `Authorization: Bearer <token>`; comparison is constant-time. When unset (default), behavior is unchanged so docker-compose-internal usage stays frictionless. Plain ASGI middleware (`mcp_server/auth.py`); lifespan and non-HTTP scopes pass through.

**Correction (2026-09-22)**: the "not published" statement above went stale: `docker-compose.yml` publishes `:8001` on the host loopback (`127.0.0.1:8001`) for the dev path and manual smoke. And the fix as landed was server-side only: compose forwarded `MCP_AUTH_TOKEN` to neither service and the agent's MCP client sent no header, so setting the variable either did nothing (container) or took the stack down with 401s (host). Repaired end to end in the entry below.

### P1 - Unbounded inputs on `nmap_parse_xml` and `attack_mapping` (fixed)

`nmap_parse_xml` previously accepted `xml_content: str` with no upper bound; while `defusedxml(forbid_dtd=True)` neutralized XXE and entity expansion, a multi-hundred-MB well-formed `<port>` tree was fully parsed in-process. Per-host caps were present, per-document host count was not.

`attack_mapping` previously accepted `cwe_ids: list[str]` with no length limit; the existing `cwe[:10]` truncation only affected the span attribute, not the iteration cost.

**Previous mitigation**: both tools were reachable only by the agent (single trusted client), and the rate-limit middleware on `agent-api` capped request frequency from the client side. Direct MCP-transport callers would have bypassed that, see the P0 above for the related transport-auth gap.

**Fix landed**: `Annotated[str, Field(max_length=20_000_000)]` on `nmap_parse_xml.xml_content` + a `[:1000]` cap on the `<host>` iteration; a 20MB pre-flight check also runs at the tool entry to bound direct callers. `Annotated[list[str], Field(max_length=200)]` with per-item `Field(max_length=40)` on `attack_mapping.cwe_ids` + runtime checks that raise `InvalidCweInputError` before any lookup. Contract tests pin the new caps.

### P1 - NVD reference URLs reach the agent without an "untrusted" marker (fixed)

`tools/cve.py` and `tools/patch.py` returned URLs extracted from NVD `references` as typed `HttpUrl` fields without an explicit "treat as data, not as instruction" marker in the output model. The agent prompt and the absence of a URL-fetching downstream tool both kept this dormant; the latent risk was that any future tool following a reference URL would have inherited an SSRF-by-reference vector.

**Previous mitigation**: agent system prompt treated tool output as data; no MCP tool dereferenced a reference URL.

**Fix landed**: `CVEDetail.references` and `PatchAvailability.references` carry an `UNTRUSTED` contract in both the class docstring and the Pydantic `Field(description=...)`. Tool docstrings on `cve_lookup` and `patch_lookup` repeat the contract, and the agent system prompt has an explicit clause forbidding fact-claims based on reference content. No boolean flag is added to the data shape: the constant-True flag would have been rumor in every payload, where a documentation contract is louder.

### P1 - SSE transport is on the legacy side of the MCP spec line

The MCP spec revision dated 2025-06-18 introduces Streamable HTTP as the recommended bidirectional surface; SSE is marked legacy in several SDK releases. The server still uses SSE in `mcp_server/server.py`.

**Current mitigation**: the SDK pin used here still supports SSE; no breaking change forced yet.

**Planned fix**: migrate to `transport="streamable-http"` once the SDK floor allows. Deferred until the SDK explicitly deprecates, no rush.

### P1 - `epss_score` silent fallback on upstream CVE-id mismatch (fixed)

`tools/epss.py` used to return an empty `EpssScore(cve_id=cve_id)` after a `log.warning` when the FIRST.org response carried a different CVE-id than the one queried. The agent had no way to distinguish "CVE not in EPSS" (legitimate empty result) from "EPSS API misbehaved" (system fault), so a misbehavior could read as a "zero exploit probability" signal.

**Fix landed (S1)**: `EpssScore.status` disambiguates the three states at the tool boundary (`found` / `not_found` / `upstream_error`); a mismatched upstream CVE-id returns `status=upstream_error` (span attribute `epss.status`), and `TriageReport.signal_coverage` carries the per-feed state so the agent and the UI see the fault explicitly. Hard request failures still raise a typed `EpssError`.

### P1 - `exploit_check` GitHub search counted CVE-database mirrors as public exploits (fixed)

`tools/exploits.py` treated any GitHub Code Search hit for `"<CVE-id>" in:file` as evidence of a public exploit, guarded only by a six-entry denylist of known aggregators. GitHub hosts dozens of vulnerability-database mirrors and distro security trackers (`canonical/ubuntu-security-notices`, `microsoft/azurelinux`, `anchore/nvd-data-overrides`, `alpinelinux/aports`, `Tabll/gemnasium-db`, `nomi-sec/NVD-Database`, ...) that carry a data-file entry for essentially every CVE. With `GITHUB_TOKEN` set, four unrelated benign CVEs (CVE-2024-35195 requests, CVE-2024-45491 libexpat, CVE-2024-52046 Apache MINA, plus others) all read `has_public_exploit=True` purely from mirror entries. Because the SSVC ladder escalates on `exploits_public` (`public-exploit` / `public-exploit+high-epss` rules), the whole system over-escalated: low-risk CVEs with EPSS well under 1% and no real PoC were pushed to Attend/Act, and the exploit signal lost its discriminating power. This is a data-quality / integrity defect, not a code-execution one, but it degrades every downstream verdict (triage reports, the SBOM gate, and the demo gallery).

**Fix landed**: the denylist is demoted to a query-side noise reducer plus a cheap backstop; the authority is now a positive-evidence filter (`_looks_like_poc`). A GitHub hit counts only when the artifact is organized around the exploit: the repository is named after the CVE (the dominant PoC-publishing convention; a mirror carries thousands of CVEs and never names its repo after one), or an explicit marker token (`exploit` / `poc` / `payload` / `metasploit` / `0day`) appears in the repo name or file path. Markers are matched against delimiter-split tokens, never raw substrings, so `source` / `resource` cannot trip an `rce`-like token. Contract tests pin the observed false-positive corpus (unlisted mirrors, a CVE-named data file inside a generic catalog repo) as rejected and genuine PoCs (repo named after the CVE, a metasploit-module path) as accepted. No schema change, so the record-replay staleness gate is untouched. NOTE: the committed replay cassettes were recorded before this fix and may carry pre-fix (inflated) exploit returns; replay stays valid because it recomputes verdicts from each cassette's own frozen tool outputs, and the values self-correct on the next re-record.

### P1 - Event-loop blocking on cache refresh write (fixed)

`tools/exploits.py` and `tools/kev.py` call sync `path.write_bytes(bytes(buffer))` on 5-20MB blobs inside their async cache-refresh paths. Each refresh momentarily blocks the asyncio event loop.

**Fix landed (2026-09-22)**: both refresh paths hand the write to a worker thread (`await asyncio.to_thread(path.write_bytes, bytes(buffer))`), so the loop keeps serving other tool calls during a 5-20 MB refresh. The refresh still runs at most once per TTL (7d Exploit-DB index, 24h KEV catalog).

### P1 - Orphaned tasks on `asyncio.gather` failure (fixed)

`tools/exploits.py` and `tools/kev.py` pair `asyncio.create_task(...)` with `asyncio.gather`. If one task raises, the other is not cancelled and continues running until the `AsyncClient` context exits.

**Fix landed (#243, 2026-09-22)**: `exploit_check` awaits `asyncio.gather(coro_a, coro_b, return_exceptions=True)` on the coroutines directly, so each arm settles on its own, nothing is left un-awaited, and a failing source is reported as an errored arm on the result instead of taking the other arm's answer down with it. `kev_check` has a single download path and no fan-out.

---

### P0 - SSVC verdict fed by model-authored signal fields (fixed)

**Finding.** `api/stream.py` stamped the verdict as `assess_ssvc(report.cves)`, and `agent/ssvc.py` read `in_kev_catalog`, `exploits_public`, `epss_*` and `severity` off the model's own `CVEReference` entries. The decision function was pure and the verdict reproducible from the same report, but every input traversed the model: an injection, or plain transcription drift, that flipped `in_kev_catalog` in the report flipped Act to Track. The grounding verifier flagged an inflated positive claim after the fact, but by its claim policy it does not judge a negative claim without evidence, so the cheapest attack (talk the model out of calling `kev_check`, report `false`) produced a Track verdict next to a `grounded` badge, sealed into the audit chain and exported to SARIF. The SBOM gate never had this gap: `gate/runner.py` builds `SsvcSignals` from typed `KevCheck` / `EpssScore` / `ExploitCheck` results.

**Fix.** The evidence index the grounding verifier already built from the trajectory moved into `agent/evidence.py` and now feeds both stamps. `assess_ssvc(cves, invocations)` reads each signal from the tool returns; where several returns exist for a CVE the most urgent reading wins; an EPSS `not_found` answer and a CVE record without a CVSS score count as evidence-backed absences. A signal with no usable evidence (feed never called, failed, or unparseable) falls back to the report for that signal and the fallback is named on the verdict: `SsvcAssessment.basis` is `evidence`, `mixed` or `report`, and `unverified_signals` lists each `<CVE-ID>:<kev|exploit|epss|severity>` taken on the model's word. The rationale text carries the same caveat so SARIF and OpenVEX notes travel with it, and the frontend renders it on the verdict card. Replaying the eleven committed cassettes through the new code reproduces every recorded decision and rule with `basis: evidence`, so no legitimate verdict moved; only the model's route to it closed.

**Residual.** The fallback still takes the report's value for a signal nobody checked, visibly. The alternative, treating an unchecked signal as absent, would silently drop a real signal the model may have carried from a fenced description and make the verdict disagree with the CVE card the operator is reading. Visibility over suppression is the chosen trade; a consumer that wants the strict form can refuse any verdict whose basis is not `evidence`.

### P1 - MCP bearer auth not wired end to end, DNS-rebinding protection off under 0.0.0.0 (fixed)

**Finding.** The bearer middleware from PR1 was real, but the path to enable it was broken in three places: `docker-compose.yml` did not pass `MCP_AUTH_TOKEN` to the `mcp-server` container (a value in `.env` drives compose substitution, not container environment, so the documented enablement was a no-op in the shipped deployment); `agent/triage.py` built `MCPToolset` with no headers, so with the gate on the primary client 401s on the SSE handshake and the whole stack goes down; and `docs/running.md` said the agent "needs no extra configuration" over an "in-process" client while the transport is HTTP+SSE across two containers. `docs/running.md` and `.env.example` also said `:8001` is not published to the host while compose publishes `127.0.0.1:8001`. Separately, FastMCP switches DNS-rebinding protection on by itself only for loopback binds; compose binds `0.0.0.0` so the other container can reach the server, which silently left it off: a web page rebinding its own domain to `127.0.0.1` could read the SSE `endpoint` event from a visitor's browser and drive tool calls on the published port (bounded by the read-only tool set, but enough to burn the shared NVD and GitHub quotas).

**Fix.** compose forwards `MCP_AUTH_TOKEN` to both services; `agent/triage.py::_mcp_toolset` presents it as `Authorization: Bearer <token>` when set (blank means off, matching the server). `tests/mcp_server/test_auth.py` now serves the real `build_app()` on an ephemeral loopback port and drives a tool listing through the same client class the agent uses: with the token it lists the tools, without it the SDK surfaces the 401. `mcp_server/server.py` passes explicit `TransportSecuritySettings`: protection on, `Host` allowlist from `MCP_ALLOWED_HOSTS` (default loopback in both IP families plus the `mcp-server` service name, any port; blank means the default so an empty variable cannot lock every client out), and an empty Origin allowlist so any browser-originated request is refused. Live tests assert 421 on a foreign `Host` and 403 on an `Origin` even with a valid token. `tests/test_deploy_config.py` pins the compose wiring and the `.env.example` wording. Docs corrected.

**Residual.** A single shared static secret with no rotation, as `auth.py` states; production sits the server behind an OAuth2 proxy or mTLS. The default still runs open on loopback, which is a deliberate dev-experience trade documented in `.env.example`.

### P1 - Denial-of-wallet rail bypassed by disconnect, aborted runs sealed as success (fixed)

**Finding.** `api/stream.py` charged a run to the budget window only after the `final` SSE event was yielded. sse-starlette cancels the generator's task group on `http.disconnect`, and the resulting `CancelledError` is a `BaseException`, so it bypassed the `except Exception` arm entirely: an attacker who aborted the connection one round before completion was billed by the provider in full while the rolling window recorded nothing, repeatable indefinitely. The control's whole threat model is the adversary that bypasses it, and it was defeated by the cheapest possible client behaviour. The same path left `outcome="success"` (initialised before the run, never reached by the error arm) so a cancelled run sealed into the hash chain as a success with an empty report hash, and the audit row recorded `settings.llm_model` even when the request had overridden the model. The only per-run bound was `request_limit`; Anthropic models batch tool calls per turn, so rounds bounded neither tool calls nor tokens, and nothing bounded wall-clock time. Conditional in practice: the rail is opt-in and the default binding is loopback, so the shipped default was not exposed. It became live the moment `DENIAL_OF_WALLET_USD_PER_DAY` was set behind a proxy, which is exactly the deployment the rail advertises.

**Fix.** The generator settles cost and outcome in its `finally`, on every exit path. The charge goes through `BudgetTracker.record_now`, a synchronous form of `record`: inside a cancelled anyio scope every `await` re-raises `CancelledError`, so an awaited record would never land. `outcome` starts as `incomplete`, becomes `success` only once the `final` event is on the wire, and `cancelled` on `CancelledError` / `GeneratorExit` (re-raised, so the framework's cleanup is untouched). The audit row's `model` is resolved from the request, the same value the cost estimate uses. `UsageLimits` now carries `tool_calls_limit` and `total_tokens_limit` next to the round cap, and an `asyncio.timeout` around the run enforces a wall-clock deadline that surfaces as its own error class; all four are settings forwarded by compose. Tests drive the generator directly and close it mid-stream (the disconnect), fail it mid-stream, and time it out, asserting in each case that the window grew and the audit sealed the honest outcome.

**Residual.** The window stays in-process (documented; multiple replicas need a shared counter), and N concurrent runs can overshoot the ceiling by N times a run's cost, now bounded by the token limit rather than the round count alone. An admission charge reconciled at completion is the next refinement if the overshoot matters.

### P1 - `exploit_check` GitHub arm failed open and accepted attacker-registrable evidence (fixed)

**Finding.** The GitHub arm returned `[]` on a 403 (rate limit), on any non-200 status, on a transport error and on an unusable body, so a flooded or throttled search read exactly like "no public exploit". `has_public_exploit` drove the SSVC ladder (Attend on its own, Act with high EPSS) on both the LLM path and the no-LLM SBOM gate, so a signal-suppression attack survived the deterministic verdict precisely because the verdict was deterministic. In the other direction, the positive-evidence filter accepted any repository whose name contains the CVE id: creating `owner/CVE-2026-0001-poc` with one file flips the signal for every consumer, a denial-of-merge primitive against a gate run with `--fail-on attend`, and the counterexample to the case study's "corrupting a signal means compromising a feed". The accepted file URL also carried the repository name and path, attacker-chosen English, into the model context unfenced inside a validated `HttpUrl`. The fresh cassette recording of 2026-09-22 showed the ambiguity live: `xz-utils-backdoor` moved from Act to Attend because the arm returned no hit where July had ten, and nothing on the return could say whether that was the mirror filter or a fail-open.

**Fix.** `ExploitCheck` carries a status per source (`exploit_db`, `github`: `found`, `not_found`, `error`, `skipped`), the arms settle independently (`asyncio.gather(..., return_exceptions=True)`), and an Exploit-DB download failure no longer raises out of the tool: it is an errored arm next to whatever GitHub answered. Consumers honour the statuses: the SSVC authority reads a False with an errored arm as unknown and falls back to the report with `exploit` named in `unverified_signals`; the grounding verifier degrades a positive claim over an inconclusive return to `unverifiable` instead of `mismatch`; the gate marks coverage `error` (and `degraded` for a token-less skip). A GitHub candidate is accepted only when its repository is established, at least 5 stars or 30 days old, via one metadata call per candidate on the same host lock; candidates that fail the bar are counted in `github_unverified_hits`. Accepted hits are returned as repository URLs built from a shape-validated `owner/repo`, never file URLs. The tool docstring and the system prompt tell the model what an errored arm means.

**Residual.** Stars and age raise the cost of the attack from "register a name" to "farm stars or wait a month"; they are not proof of a working exploit, and Exploit-DB submissions are reviewed but not authenticated evidence either. The signal stays the softest rung of the ladder, which is where it sits.

### P1 - Untrusted-content fence forgeable, prompt never named the markers (fixed)

**Finding.** `fence_untrusted` wrapped a payload once in fixed literal markers and did not neutralize occurrences of those markers inside the payload. A CVE description, an OSV summary or a crafted Nmap banner containing `</UNTRUSTED_CONTENT>` therefore closed the fence early, and whatever followed read as out-of-fence text to a model parsing the flat string. The case study described this as "defeated structurally" and pointed at a test that only asserted the outer wrapper was applied once. The system prompt, meanwhile, defined the boundary in prose without ever naming the marker pair, so the hard boundary the server emitted and the soft boundary the model was given were not actually joined. Marker forgery was in the red-team battery only through the user query, which is never fenced; the one channel where the marker has meaning was untested.

**Fix.** Both markers carry a random id minted once per server process (`FENCE_NONCE`), and the prompt states that only a pair with matching ids is a boundary; the text's author cannot know the id. Before wrapping, every marker-shaped token in the payload (any case, any id, with or without a slash) has its `<` escaped to `&lt;`, so the literal tag cannot exist between the real markers. Caps on fenced fields are the payload budget plus `FENCE_OVERHEAD`, and `fence_untrusted(max_chars=...)` truncates after neutralization, so a payload stuffed with forged closers cannot overflow a field. Tests: neutralization across casings and ids, exactly one real marker of each kind in any output, a Hypothesis property that a budgeted fence never exceeds budget plus overhead, and a sizing contract over the inventory of fenced fields checked against the security module's docstring.

**Residual.** Semantic injection that never touches the markers is unchanged: fenced text is still data the model reads. The battery re-run on 2026-09-22 after this fix reads 17/18 (July: 15/18); the remaining miss is `marker-pseudo-xml-instructions`, delivered through the user query, which is the operator's own turn and is not fenced by design. The id is per process, not per run; rotating it per run would require threading it from the agent into every tool call and buys nothing against an author who cannot see either.

### P1 - Nmap output unbounded and only partly fenced (fixed)

**Finding.** `NmapPort.product` and `version` were fenced but carried no cap; `service`, `protocol`, `state`, the host address and the hostnames were neither capped nor fenced, and `security.py` asserted hostnames were "DNS charset, length-capped" as the reason they needed no fence. A 20 MB scan (the input cap) with 1000 hosts and 200 ports each could carry 100 KB attributes and return megabytes of attacker prose into the model context through fields the model reads as structured facts, an injection window orders of magnitude larger than the 500-2000 character windows every other tool enforces, and a context-cost amplifier from one tool call.

**Fix.** Banners are fenced with a 200-character budget (truncated after neutralization), identifiers are capped at 64 characters and hostnames at 253 per item with the existing 50-item cap, and the model declares every cap so the tool cannot drift back. `CVEDetail.description`, the one other fenced field with no cap, is capped at 4000 characters plus overhead. A contract test feeds 5000-character attributes through the parser and asserts every field's length.

## How to read the Security tab against this document

1. Open the [Code scanning alerts](https://github.com/Shurtug4l/sec-recon-agent/security/code-scanning) page.
2. Match each open alert against the table above.
3. If an alert is **not** in the table, it is new: assess it, decide, and update this file in the same PR that resolves (or accepts) it.
4. The Trivy workflow does not auto-dismiss alerts. The CRITICAL gate in `ci-docker-scan.yml` will fail the build outright on any CRITICAL; HIGH and below land in the Security tab as informational. The "fail on CRITICAL" line is the actual policy gate; this file is the discipline that prevents the HIGH/MEDIUM channel from becoming background noise.

---

## Out-of-scope by design

These findings will **never** be auto-dismissed even if a fix lands, because they touch code we do not invoke. Dismissing them would lose audit traceability:

- The 3 `rand` LOW findings (custom-logger unsoundness) live in a wheel we consume as a black box. A future ChromaDB upgrade may close the alert silently; this document will be updated in the same PR.

---

## Internal audit cadence and methodology

Periodic multi-agent review: spawn three specialized cold-review agents in parallel against the current `main` (`mcp-server-auditor`, `dependency-supply-chain-auditor`, `ai-governance-mapper`) plus one cross-check (`code-reviewer-strict`). Each agent operates in an isolated context and produces a prioritized P0-P3 report with file:line citations; findings are consolidated here, with mitigations and planned PRs.

The intent is **defense in depth via independent review**: the agents do not see each other's output, so a finding surfaced by three of them at once is a strong signal, and a finding surfaced by only one is still informative if the reasoning holds. The "what's solid" section in each agent report is also tracked separately (not in this document) to avoid backsliding on hardening that is already in place.

Cadence: ad-hoc, recommended every meaningful code addition to the MCP tool surface or the agent flow. Not a substitute for inline review, which catches issues before they land; the multi-agent pass is the periodic external check.

---

## Related

- [`.github/workflows/ci-docker-scan.yml`](../.github/workflows/ci-docker-scan.yml) - the scan workflow.
- [`docs/owasp_llm_top10.md::LLM03 Supply Chain`](owasp_llm_top10.md) - how supply-chain risk is layered against this project.
- [`docs/design.md::Residual risks`](design.md) - the architectural-level limitations these findings sit inside.
