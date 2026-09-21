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
| P0 | MCP transport has no auth layer | `mcp_server/server.py` (FastMCP SSE) | **fixed (PR1)** | opt-in `MCP_AUTH_TOKEN` bearer middleware in front of the SSE app; default off so docker-compose-internal usage is unchanged |
| P1 | `nmap_parse_xml` has no size cap on input | `mcp_server/tools/nmap.py` | **fixed (PR1)** | 20MB input cap + 1000-host iteration cap, both enforced at the tool entry |
| P1 | `attack_mapping` `cwe_ids` list is unbounded | `mcp_server/tools/attack.py` | **fixed (PR1)** | 200-entry list cap + 40-char per-entry cap; oversize input raises `InvalidCweInputError` before lookup |
| P1 | NVD reference URLs not marked untrusted in output | `mcp_server/tools/cve.py`, `tools/patch.py` | **fixed (PR1)** | docstring + Pydantic `Field(description=...)` mark `references` as untrusted on `CVEDetail` and `PatchAvailability`; agent system prompt repeats the contract |
| P1 | SSE transport is legacy (Streamable HTTP is the post-2025-06-18 recommendation) | `mcp_server/server.py` | open, tracked (deprecation watch) | SDK still supports SSE; no breaking change forced yet |
| P1 | `epss_score` silently returns empty score on upstream CVE-id mismatch | `mcp_server/tools/epss.py` | **fixed (S1)** | explicit `EpssScore.status` enum (`found` / `not_found` / `upstream_error`); a CVE-id mismatch returns `upstream_error`, surfaced in the report `signal_coverage` |
| P1 | `path.write_bytes` blocks the event loop during 5-20MB cache refresh | `mcp_server/tools/exploits.py`, `tools/kev.py` | open, tracked | refresh runs at most once per cache TTL (7d Exploit-DB, 24h KEV) |
| P1 | `asyncio.gather` paired with bare `create_task` leaves orphaned tasks on failure | `mcp_server/tools/exploits.py`, `tools/kev.py` | open, tracked | `AsyncClient` context exit cancels in-flight tasks; window is narrow |

---

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

### P1 - Event-loop blocking on cache refresh write

`tools/exploits.py` and `tools/kev.py` call sync `path.write_bytes(bytes(buffer))` on 5-20MB blobs inside their async cache-refresh paths. Each refresh momentarily blocks the asyncio event loop.

**Current mitigation**: cache refresh runs at most once per TTL (7d Exploit-DB index, 24h KEV catalog), so the blocking window is rare in practice.

**Planned fix**: `await asyncio.to_thread(path.write_bytes, bytes(buffer))`.

### P1 - Orphaned tasks on `asyncio.gather` failure

`tools/exploits.py` and `tools/kev.py` pair `asyncio.create_task(...)` with `asyncio.gather`. If one task raises, the other is not cancelled and continues running until the `AsyncClient` context exits.

**Current mitigation**: the `AsyncClient` context exit cancels in-flight tasks via httpx connection teardown; the leak window is narrow.

**Planned fix**: use `asyncio.gather(coro_a, coro_b)` directly (gather already manages the tasks), or `asyncio.TaskGroup` (Python 3.11+) which cancels siblings on first failure.

---

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
