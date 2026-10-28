# Scorecard

Single reproducible measurement of the system across security posture, detection quality, retrieval, efficiency, and reliability. Regenerate with `make scorecard` (see [Reproduce](#reproduce)). Live metrics are populated from the eval / retrieval / red-team result JSONs; a _pending live run_ marker means that run has not been captured yet.

- **Model**: `sonnet`
- **Date**: 2026-09-22
- **Commit**: `feea11f`
- **Token pricing**: Anthropic published rates as of 2026-06-24

## Security posture (red-team resistance)

Prompt-injection battery: **18 payloads** across 6 categories, each mapped to MITRE ATLAS techniques. Resistance = the agent held the boundary on every falsifiable check for the payload.

**Resistance: 17/18 (94%)**

| ATLAS technique | Payloads | Resisted |
|---|---:|---:|
| AML.T0051.000 (LLM Prompt Injection: Direct) | 10 | 9/10 (90%) |
| AML.T0051.001 (LLM Prompt Injection: Indirect) | 3 | 3/3 (100%) |
| AML.T0054 (LLM Jailbreak) | 2 | 2/2 (100%) |
| AML.T0056 (Extract LLM System Prompt) | 2 | 2/2 (100%) |
| AML.T0057 (LLM Data Leakage) | 1 | 1/1 (100%) |

_A payload can exercise more than one technique, so the payload column sums past the battery size._

## Detection quality (golden set)

Golden set: **11 curated cases** (7 expect a CISA KEV hit, 1 verified KEV-absent so a KEV flag there is scored as fabrication, 1 expect a ransomware flag; KEV = CISA's Known Exploited Vulnerabilities catalog, CVEs observed exploited in the wild). Soft assertions: severity within +-1 step, expected CVE recall >= 50%, KEV tri-state (require / forbid / skip), ransomware honored when asked.

- **Pass rate**: 11/11 (100%)
- **Severity within +-1 step**: 11/11
- **Mean CVE recall**: 1.00

## Retrieval quality (cve_semantic_search)

Measured by sampling the seeded ChromaDB index and querying with a truncated description; the corpus is a moving window, so numbers depend on the seed. Hybrid retrieval: dense MiniLM-L6 fused with lexical BM25 (reciprocal-rank fusion); no cross-encoder reranker (yet). Ablation vs dense-only in docs/evaluation.md.

- **Sampled**: 500 CVEs (top_k=10)
- **MRR**: 0.790
- **hit-rate@1 / @3 / @5**: 77% / 81% / 82%

_MRR = mean reciprocal rank of the expected CVE (1.0 = always ranked first); hit-rate@k = share of samples whose expected CVE appears in the top k results._

## Efficiency (cost & latency)

- **Latency p50 / p95**: 40.4s / 69.6s
- **Mean tokens (in / out)**: 57254 / 2438 (input is the total pydantic-ai reports, prompt-cache reads and writes included; the cost line prices cache traffic at its multipliers)
- **Cost**: total $0.8630, mean $0.0785/triage

## Reliability (conformance & calibration)

- **Structured-output conformance**: 11/11 well-formed reports
- **Confidence calibration (ECE)**: 0.155 (0 = perfectly calibrated; over the scored cases)

## Grounding (deterministic claim verification)

Every triage is stamped with a grounding verdict: the server re-checks each tool-derived claim in the report (CVSS, KEV, EPSS, exploit flags, ATT&CK ids) against the tool returns captured from the run's own message history. The numbers below aggregate the committed replay cassettes (`tests/cassettes/`): frozen real trajectories that CI replays through the current deterministic pipeline on every PR, hard-failing when the system prompt or a tool schema drifts from what the recorded model saw.

- **Cassettes**: 11 (model `claude-sonnet-4-6`, recorded 2026-09-22, surface `2882c021c561`)
- **Reports grounded**: 11/11
- **Claims checked**: 161 (supported 161, unbacked 0, mismatched 0, unverifiable 0)

## Prioritization (deterministic SSVC)

The SSVC verdict (Stakeholder-Specific Vulnerability Categorization, CISA's remediation-urgency methodology) is computed server-side from the collected signals, not by the LLM, so it is reproducible from the same inputs. EPSS below is FIRST.org's predicted probability of exploitation in the next 30 days. Decision rules, most-urgent first:

| Signal | Decision |
|---|---|
| known ransomware association | **Act** |
| on CISA KEV (active exploitation) | **Act** |
| public exploit AND EPSS >= 0.5 | **Act** |
| public exploit (no high-EPSS) | **Attend** |
| EPSS >= 0.5 or percentile >= 0.95 | **Attend** |
| EPSS >= 0.1 (elevated) | **Track\*** |
| High/Critical CVSS, no exploitation signal | **Track\*** |
| none of the above | **Track** |

_SSVC-informed, not the full CISA tree: the Automatable and Mission & Well-being decision points are approximated (EPSS as a likelihood proxy; deployment-specific asset criticality is out of scope for a stateless tool)._

## Reproduce

```bash
make up          # start the stack
make seed        # seed the CVE index (once)
mkdir -p data/scorecard
make eval     EVAL_ARGS='--json-output data/scorecard/eval.json --model sonnet'
make eval     EVAL_ARGS='--retrieval --retrieval-sample 500 --json-output data/scorecard/retrieval.json'
make redteam  REDTEAM_ARGS='--json-output data/scorecard/redteam.json --model sonnet'
make record-cassettes RECORD_ARGS='--model sonnet'  # replay cassettes (recorder defaults to sonnet)
make scorecard   # regenerate this file from whatever JSONs exist
```

The eval and red-team runs require a live stack and bill the LLM; they are out of CI by design. The deterministic coverage sections regenerate offline.
