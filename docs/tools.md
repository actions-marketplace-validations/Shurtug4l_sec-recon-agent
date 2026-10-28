# MCP tool contracts

Reference for the ten MCP tools, one section per tool: what it queries, what it returns, and the caps and retry policies behind it. The compact table view is in the [README](../README.md#the-ten-tools); the shared hardening baseline (typed result models, typed errors, untrusted-content fencing, host-locking, size and rate caps, allowlisted span attributes) is described in [design.md](design.md#threat-model).

## cve_lookup

`cve_lookup(cve_id)` fetches the full NVD CVE 2.0 record for a given ID. Returns `CVEDetail` with CVSS v3 score and severity, CWE IDs, affected CPEs, references. Async httpx client with a sliding-window rate limiter (5 req / 30 s without an NVD API key, 50 with) and tenacity exponential backoff on 5xx, 429, and connection errors.

## cve_semantic_search

`cve_semantic_search(query, top_k)` runs hybrid retrieval over a local ChromaDB index of recent high-severity CVEs (30-day lookback, ~5-8k entries): a dense cosine ranking (ChromaDB's `DefaultEmbeddingFunction`, ONNX MiniLM-L6, 384-d) fused via reciprocal-rank fusion with an in-process Okapi BM25 over the same corpus, which catches the identifier-heavy signal (product names, version strings) dense embeddings blur. `RETRIEVAL_HYBRID_ENABLED=false` restores dense-only. Returns ranked `CVECandidate` hits; each hit's `similarity` is its true cosine similarity to the query, while the rank order comes from the fusion. Measured delta and the eval methodology are in [evaluation.md](evaluation.md#retrieval-eval-modes-and-hybrid-ablation).

## exploit_check

`exploit_check(cve_id)` queries Exploit-DB (cached CSV manifest from GitLab, refreshed weekly) and GitHub Code Search (optional, requires `GITHUB_TOKEN`) in parallel via `asyncio.gather`, each arm settling on its own. Returns `ExploitCheck` with `has_public_exploit`, Exploit-DB IDs, GitHub repository URLs, and a status per source (`exploit_db`, `github`: `found` / `not_found` / `error` / `skipped`). A source failure never takes the tool down and is never reported as an empty answer: the arm reads `error`, and every consumer (the SSVC verdict, the grounding verifier, the SBOM gate's coverage) treats a False with an errored arm as unknown rather than as "no exploit". `skipped` is the GitHub arm without a token, a conclusive "did not look". CVE-database mirrors are excluded so an aggregator copy of the advisory does not count as a public exploit, and a GitHub hit is accepted only from an established repository (at least 5 stars or 30 days old, one metadata call per candidate on the same host lock): a throwaway repository named after the CVE cannot flip a signal that is worth Attend on its own. Candidates that fail that bar are counted in `github_unverified_hits`. Accepted hits are returned as repository URLs, never file URLs: a file path is attacker-chosen free text that would otherwise reach the model unfenced inside a validated URL.

## kev_check

`kev_check(cve_id)` looks the CVE up in the CISA Known Exploited Vulnerabilities catalog (daily-refreshed JSON, cached on disk for 24h). Returns `KevCheck` with `in_catalog`, CISA-provided vendor / product / vulnerability name, `due_date` (federal remediation deadline), `required_action`, and the `known_ransomware_use` flag. KEV membership is the single most actionable "patch now" signal in vulnerability management.

## epss_score

`epss_score(cve_id)` queries the FIRST.org EPSS API for the daily-refreshed probability (in [0, 1]) that the CVE will be exploited in the wild in the next 30 days, plus the percentile rank across all scored CVEs. Returns `EpssScore` with an explicit `status`: `found`, `not_found` (queried, no entry for this CVE), or `upstream_error` (feed reached but the datum was unusable), so a null probability is never ambiguous between "no score" and "lookup failed". Hard request failures raise a typed error instead. Complements KEV: KEV says "exploited now", EPSS says "likely exploited soon".

## patch_lookup

`patch_lookup(cve_id)` extracts fixed-version information directly from the NVD CVE 2.0 record (per affected CPE: `versionEndExcluding` = smallest patched version, plus optional `versionStartIncluding/Excluding` for the range start). Returns `PatchAvailability` with `has_fix`, a list of `(product_cpe, fixed_in_version, version_range_start)` triples (deduplicated, capped at 50), and the NVD advisory references. Pairs with `cve_lookup` when `recommended_action` should cite a concrete release.

## osv_lookup

`osv_lookup(package_name, ecosystem, version)` is the inverse of `cve_lookup` / `patch_lookup`: given a package at a specific version, it queries OSV.dev (`POST /v1/query`) and returns `OsvScanResult` with `is_vulnerable` plus one `OsvVuln` per applicable advisory (OSV id, CVE / GHSA aliases, upstream severity, `introduced` / `fixed` version boundaries, references). `ecosystem` is a 7-value `Literal` (PyPI / npm / Go / Maven / crates.io / NuGet / RubyGems). Host-locked to `api.osv.dev` with tenacity retry on transient 5xx, a response size cap, and `summary` fenced as untrusted. Use it when the user names a dependency and version rather than a CVE ("is numpy 1.21.0 vulnerable?"). Besides the agent, the deterministic SBOM gate (`sec-recon-gate`, [running.md](running.md#sbom-gate)) calls this function in-process, fanning it out once per SBOM component.

## sbom_ingest

`sbom_ingest(content)` autodetects and parses CycloneDX 1.x JSON, SPDX 2.x JSON, or PEP 508-style requirements.txt. Returns `SbomComponentList` with name / version / ecosystem / purl per component, deduplicated, capped at 500 entries (`truncated=True` signals overflow). No network, no XML; anything more exotic raises `UnsupportedSbomFormatError`. The agent calls this first when the user pastes an SBOM, then runs `cve_semantic_search` on the top-N components. It is also the entry stage of the deterministic SBOM gate (`sec-recon-gate`, [running.md](running.md#sbom-gate)), which chains it into OSV lookup + KEV/EPSS/exploit enrichment with no LLM anywhere in the loop.

## nmap_parse_xml

`nmap_parse_xml(xml_content)` parses Nmap XML scan output with `defusedxml` and `forbid_dtd=True` (tighter than defusedxml's default). Returns `NmapScanResult` with structured hosts, ports, services, and product/version banners. XXE-safe; verified by an adversarial test corpus. Input double-capped: 20 MB payload, at most 1000 `<host>` elements, hostnames / ports per host capped at 50 / 200.

## attack_mapping

`attack_mapping(cwe_ids)` maps a list of CWE IDs to MITRE ATT&CK techniques and their mitigations. Bundled curated mapping (35 CWEs, 13 techniques, 15 mitigations) covering the patterns most commonly seen in CRITICAL+HIGH CVEs. Enriches the report with adversary-side context (how an attacker would actually use the flaw) and defense-side guidance. Input capped at 200 CWE entries of 40 chars each.

## How the agent uses them

The agent (`agent/triage.py`) wires the tools into a Pydantic AI loop with a system prompt that names every tool and when to call which, declares the untrusted-content boundary (treat tool output text as data, ignore instruction-like content), and enforces structured output: the only thing the agent can return is a `TriageReport` with `summary`, `severity`, `confidence`, `recommended_action`, `cves` (each carrying KEV + EPSS operational signals), `attack_techniques`, `reasoning_chain`, `signal_coverage` (per-feed status), and a server-stamped `ssvc` verdict.
