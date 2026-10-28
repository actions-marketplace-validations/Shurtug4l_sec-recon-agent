"""One-command scorecard generator for the whole system.

Renders `SCORECARD.md` from two kinds of input:

- **Deterministic coverage** (always available, no live stack): the golden-set
  composition, the red-team battery's per-ATLAS-technique payload coverage, and
  the SSVC decision table + thresholds. Computed by importing the modules that
  own those facts, so the scorecard cannot drift from the code.
- **Live metrics** (filled when the corresponding results JSON exists, else
  marked "pending live run"): golden pass rate + severity/recall, retrieval
  hit-rate@k / MRR, latency p50/p95, tokens, $/triage, structured-output
  conformance, confidence calibration (ECE), and red-team resistance.

The pre-mortem for this sprint is explicit: a scorecard with fabricated numbers
backfires. So the generator NEVER invents a live number -- a missing results
file yields an honest "pending" marker plus the exact command to produce it. The
document is stamped with model / date / commit so any number is traceable to a
run, and the "Reproduce" section is the single source of truth for regenerating
it.

`build_scorecard` and the metric parsers are pure and unit-tested; `main` is the
thin CLI shell that loads files, stamps, and writes.
"""

import argparse
import json
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sec_recon_agent.eval.cassette import (
    DEFAULT_CASSETTES_DIR,
    Cassette,
    load_all_cassettes,
)
from sec_recon_agent.eval.cost import PRICING_SOURCE_DATE
from sec_recon_agent.eval.golden_set import GOLDEN_SET
from sec_recon_agent.eval.metrics import (
    confidence_to_probability,
    expected_calibration_error,
    percentile,
)
from sec_recon_agent.redteam.atlas import ATLAS_TECHNIQUES
from sec_recon_agent.redteam.payloads import PAYLOADS

DEFAULT_OUTPUT = "SCORECARD.md"
DEFAULT_RESULTS_DIR = "data/scorecard"
_PENDING = "_pending live run_"


# --- deterministic coverage (no live stack) -------------------------------


@dataclass(frozen=True)
class GoldenCoverage:
    total: int
    kev_cases: int
    kev_forbid_cases: int
    ransomware_cases: int
    tag_counts: dict[str, int]


@dataclass(frozen=True)
class RedteamCoverage:
    total_payloads: int
    category_counts: dict[str, int]
    technique_payload_counts: dict[str, int]


def golden_coverage() -> GoldenCoverage:
    tags: Counter[str] = Counter()
    for case in GOLDEN_SET:
        tags.update(case.tags)
    return GoldenCoverage(
        total=len(GOLDEN_SET),
        kev_cases=sum(1 for c in GOLDEN_SET if c.expected_in_kev is True),
        kev_forbid_cases=sum(1 for c in GOLDEN_SET if c.expected_in_kev is False),
        ransomware_cases=sum(1 for c in GOLDEN_SET if c.expected_ransomware),
        tag_counts=dict(sorted(tags.items())),
    )


def redteam_coverage() -> RedteamCoverage:
    categories: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    for payload in PAYLOADS:
        categories.update([payload.category])
        techniques.update(payload.atlas_techniques)
    return RedteamCoverage(
        total_payloads=len(PAYLOADS),
        category_counts=dict(sorted(categories.items())),
        technique_payload_counts=dict(sorted(techniques.items())),
    )


# --- live metrics (parsed from results JSON) ------------------------------


@dataclass(frozen=True)
class EvalMetrics:
    model: str
    cases: int
    passed: int
    severity_ok: int
    mean_cve_recall: float | None
    latency_p50: float | None
    latency_p95: float | None
    mean_input_tokens: float | None
    mean_output_tokens: float | None
    total_cost_usd: float | None
    conformant: int
    scored: int
    calibration_ece: float | None


def eval_metrics_from_records(
    records: list[dict[str, Any]], model_fallback: str
) -> EvalMetrics | None:
    """Recompute aggregate golden-set metrics from a `sec-recon-eval
    --json-output` single-model record list (the same shape the CLI writes)."""
    if not records:
        return None
    scored = [r for r in records if isinstance(r.get("verdict"), dict)]
    latencies = [
        float(r["elapsed_seconds"])
        for r in records
        if isinstance(r.get("elapsed_seconds"), int | float)
    ]

    def _usage_ints(key: str) -> list[int]:
        out: list[int] = []
        for r in records:
            usage = r.get("usage")
            if isinstance(usage, dict) and isinstance(usage.get(key), int):
                out.append(usage[key])
        return out

    costs = [
        float(usage["cost_usd"])
        for r in records
        if isinstance((usage := r.get("usage")), dict)
        and isinstance(usage.get("cost_usd"), int | float)
    ]
    cve_recalls = [
        float(r["verdict"]["cve_recall"])
        for r in scored
        if isinstance(r["verdict"].get("cve_recall"), int | float)
    ]
    calib: list[tuple[float, bool]] = []
    for r in scored:
        report = r.get("report")
        if isinstance(report, dict) and isinstance(report.get("confidence"), str):
            calib.append(
                (confidence_to_probability(report["confidence"]), bool(r["verdict"].get("passed"))),
            )

    in_tokens = _usage_ints("input_tokens")
    out_tokens = _usage_ints("output_tokens")
    model = records[0].get("model") if isinstance(records[0].get("model"), str) else model_fallback

    return EvalMetrics(
        model=model or model_fallback,
        cases=len(records),
        passed=sum(1 for r in scored if r["verdict"].get("passed")),
        severity_ok=sum(1 for r in scored if r["verdict"].get("severity_ok")),
        mean_cve_recall=(sum(cve_recalls) / len(cve_recalls)) if cve_recalls else None,
        latency_p50=percentile(latencies, 50),
        latency_p95=percentile(latencies, 95),
        mean_input_tokens=(sum(in_tokens) / len(in_tokens)) if in_tokens else None,
        mean_output_tokens=(sum(out_tokens) / len(out_tokens)) if out_tokens else None,
        total_cost_usd=sum(costs) if costs else None,
        conformant=sum(1 for r in scored if r.get("conformant")),
        scored=len(scored),
        calibration_ece=expected_calibration_error(calib),
    )


@dataclass(frozen=True)
class RetrievalMetrics:
    sampled: int
    top_k: int
    mrr: float | None
    hit_rate_at_1: float | None
    hit_rate_at_3: float | None
    hit_rate_at_5: float | None


def retrieval_metrics_from_json(data: dict[str, Any]) -> RetrievalMetrics | None:
    """Parse a `sec-recon-eval --retrieval --json-output` RetrievalReport dump."""
    if not isinstance(data, dict) or not data.get("sampled"):
        return None

    def _f(key: str) -> float | None:
        value = data.get(key)
        return float(value) if isinstance(value, int | float) else None

    return RetrievalMetrics(
        sampled=int(data["sampled"]),
        top_k=int(data.get("top_k", 0)),
        mrr=_f("mrr"),
        hit_rate_at_1=_f("hit_rate_at_1"),
        hit_rate_at_3=_f("hit_rate_at_3"),
        hit_rate_at_5=_f("hit_rate_at_5"),
    )


@dataclass(frozen=True)
class RedteamMetrics:
    total: int
    resisted: int
    resistance_rate: float
    atlas_breakdown: list[dict[str, Any]]


def redteam_metrics_from_json(data: dict[str, Any]) -> RedteamMetrics | None:
    """Parse a `sec-recon-redteam --json-output` dump."""
    summary = data.get("summary") if isinstance(data, dict) else None
    if not isinstance(summary, dict) or not summary.get("total"):
        return None
    breakdown = data.get("atlas_breakdown")
    return RedteamMetrics(
        total=int(summary["total"]),
        resisted=int(summary.get("resisted", 0)),
        resistance_rate=float(summary.get("resistance_rate", 0.0)),
        atlas_breakdown=breakdown if isinstance(breakdown, list) else [],
    )


@dataclass(frozen=True)
class GroundingMetrics:
    """Aggregate grounding outcomes over the committed replay cassettes."""

    cases: int
    model: str
    recorded_on: str
    surface_hash: str
    grounded: int
    claims_checked: int
    supported: int
    unbacked: int
    mismatched: int
    unverifiable: int


def grounding_metrics_from_cassettes(cassettes: list[Cassette]) -> GroundingMetrics | None:
    """Aggregate the recorded grounding assessments; None when no cassettes exist.

    Cassettes are frozen real trajectories that CI replays on every PR
    (tests/replay/), so these numbers are re-verified continuously, unlike
    the pending-marker live metrics.
    """
    if not cassettes:
        return None

    def _count(key: str) -> int:
        return sum(int(c.outcomes.grounding.get(key, 0)) for c in cassettes)

    models = {c.model for c in cassettes}
    hashes = {c.staleness_hash for c in cassettes}
    return GroundingMetrics(
        cases=len(cassettes),
        model=models.pop() if len(models) == 1 else "mixed",
        recorded_on=max(c.recorded_at for c in cassettes)[:10],
        surface_hash=hashes.pop()[:12] if len(hashes) == 1 else "mixed",
        grounded=sum(1 for c in cassettes if c.outcomes.grounding.get("status") == "grounded"),
        claims_checked=_count("claims_checked"),
        supported=_count("supported"),
        unbacked=_count("unbacked"),
        mismatched=_count("mismatched"),
        unverifiable=_count("unverifiable"),
    )


# --- markdown rendering (pure) --------------------------------------------


def _model_pin(model: str) -> str:
    """A ` --model <id>` fragment to append to the live eval / red-team commands,
    but only when `model` names a real backend model (a full allowlist identifier
    or a short alias). Pinning is what makes the Reproduce block actually reproduce
    the stamped numbers: without it a re-run silently falls back to the deployment
    default (haiku), which the sonnet baseline documents as a worse, different run.

    The deterministic-only stamp ("n/a (deterministic-only)") is not a real model,
    so it yields "" -- the offline scorecard never prints a --model that
    `resolve_model` would reject. Retrieval eval is embeddings-only (no LLM) and is
    deliberately left unpinned by the caller."""
    from sec_recon_agent.agent.triage import ALLOWED_MODELS, MODEL_ALIASES

    if model in ALLOWED_MODELS or model in MODEL_ALIASES:
        return f" --model {model}"
    return ""


def _atlas_label(technique: str) -> str:
    # Human name from the pinned ATLAS vocabulary, so the table reads without a
    # MITRE lookup and cannot drift from the official name of the ID.
    name = ATLAS_TECHNIQUES.get(technique)
    return f"{technique} ({name})" if name else technique


def _pct(value: float | None) -> str:
    return f"{value:.0%}" if value is not None else _PENDING


def _num(value: float | None, spec: str) -> str:
    return format(value, spec) if value is not None else _PENDING


def build_scorecard(
    *,
    model: str,
    date: str,
    commit: str,
    golden: GoldenCoverage,
    redteam_cov: RedteamCoverage,
    ssvc_thresholds: dict[str, float],
    eval_metrics: EvalMetrics | None,
    retrieval: RetrievalMetrics | None,
    redteam: RedteamMetrics | None,
    grounding: GroundingMetrics | None,
) -> str:
    """Render the scorecard markdown from coverage + optional live metrics.

    Pure: every input is passed in, nothing is read from disk or the clock, so
    the output is a deterministic function of its arguments and unit-testable.
    """
    lines: list[str] = []
    a = lines.append
    # Pin the stamped model onto the LLM-driven commands (eval golden set,
    # red-team) so they reproduce these numbers; empty in deterministic-only mode.
    pin = _model_pin(model)

    a("# Scorecard")
    a("")
    a(
        "Single reproducible measurement of the system across security posture, "
        "detection quality, retrieval, efficiency, and reliability. Regenerate "
        "with `make scorecard` (see [Reproduce](#reproduce)). Live metrics are "
        "populated from the eval / retrieval / red-team result JSONs; a "
        f"{_PENDING} marker means that run has not been captured yet.",
    )
    a("")
    a(f"- **Model**: `{model}`")
    a(f"- **Date**: {date}")
    a(f"- **Commit**: `{commit}`")
    a(f"- **Token pricing**: Anthropic published rates as of {PRICING_SOURCE_DATE}")
    a("")

    # --- security posture ---
    a("## Security posture (red-team resistance)")
    a("")
    a(
        f"Prompt-injection battery: **{redteam_cov.total_payloads} payloads** across "
        f"{len(redteam_cov.category_counts)} categories, each mapped to MITRE ATLAS "
        "techniques. Resistance = the agent held the boundary on every falsifiable "
        "check for the payload.",
    )
    a("")
    if redteam is not None:
        a(f"**Resistance: {redteam.resisted}/{redteam.total} ({redteam.resistance_rate:.0%})**")
    else:
        rt_cmd = f"--json-output {DEFAULT_RESULTS_DIR}/redteam.json{pin}"
        a(f"**Resistance: {_PENDING}** (run `make redteam REDTEAM_ARGS='{rt_cmd}'`)")
    a("")
    a("| ATLAS technique | Payloads | Resisted |")
    a("|---|---:|---:|")
    live_by_tech = {b["technique"]: b for b in (redteam.atlas_breakdown if redteam else [])}
    for technique, payload_count in redteam_cov.technique_payload_counts.items():
        cell = _PENDING
        if technique in live_by_tech:
            b = live_by_tech[technique]
            cell = f"{b.get('resisted', 0)}/{b.get('total', 0)} ({float(b.get('rate', 0.0)):.0%})"
        a(f"| {_atlas_label(technique)} | {payload_count} | {cell} |")
    a("")
    a(
        "_A payload can exercise more than one technique, so the payload column "
        "sums past the battery size._",
    )
    a("")

    # --- detection quality ---
    a("## Detection quality (golden set)")
    a("")
    a(
        f"Golden set: **{golden.total} curated cases** "
        f"({golden.kev_cases} expect a CISA KEV hit, {golden.kev_forbid_cases} verified "
        f"KEV-absent so a KEV flag there is scored as fabrication, "
        f"{golden.ransomware_cases} expect "
        "a ransomware flag; KEV = CISA's Known Exploited Vulnerabilities catalog, "
        "CVEs observed exploited in the wild). Soft assertions: severity within "
        "+-1 step, expected CVE recall >= 50%, KEV tri-state (require / forbid / "
        "skip), ransomware honored when asked.",
    )
    a("")
    if eval_metrics is not None:
        em = eval_metrics
        a(
            f"- **Pass rate**: {em.passed}/{em.cases} ({em.passed / em.cases:.0%})"
            if em.cases
            else "- **Pass rate**: n/a"
        )
        a(f"- **Severity within +-1 step**: {em.severity_ok}/{em.scored}")
        a(f"- **Mean CVE recall**: {_num(em.mean_cve_recall, '.2f')}")
    else:
        a(
            f"- **Pass rate / severity / recall**: {_PENDING} "
            f"(run `make eval EVAL_ARGS='--json-output {DEFAULT_RESULTS_DIR}/eval.json{pin}'`)",
        )
    a("")

    # --- retrieval ---
    a("## Retrieval quality (cve_semantic_search)")
    a("")
    a(
        "Measured by sampling the seeded ChromaDB index and querying with a "
        "truncated description; the corpus is a moving window, so numbers depend "
        "on the seed. Hybrid retrieval: dense MiniLM-L6 fused with lexical BM25 "
        "(reciprocal-rank fusion); no cross-encoder reranker (yet). Ablation vs "
        "dense-only in docs/evaluation.md.",
    )
    a("")
    if retrieval is not None:
        r = retrieval
        hits = f"{_pct(r.hit_rate_at_1)} / {_pct(r.hit_rate_at_3)} / {_pct(r.hit_rate_at_5)}"
        a(f"- **Sampled**: {r.sampled} CVEs (top_k={r.top_k})")
        a(f"- **MRR**: {_num(r.mrr, '.3f')}")
        a(f"- **hit-rate@1 / @3 / @5**: {hits}")
    else:
        cmd = (
            f"--retrieval --retrieval-sample 500 --json-output {DEFAULT_RESULTS_DIR}/retrieval.json"
        )
        a(f"- **MRR / hit-rate@k**: {_PENDING} (run `make eval EVAL_ARGS='{cmd}'`)")
    a("")
    a(
        "_MRR = mean reciprocal rank of the expected CVE (1.0 = always ranked "
        "first); hit-rate@k = share of samples whose expected CVE appears in the "
        "top k results._",
    )
    a("")

    # --- efficiency ---
    a("## Efficiency (cost & latency)")
    a("")
    if eval_metrics is not None:
        em = eval_metrics
        p50, p95 = _num(em.latency_p50, ".1f"), _num(em.latency_p95, ".1f")
        toks_in, toks_out = _num(em.mean_input_tokens, ".0f"), _num(em.mean_output_tokens, ".0f")
        a(f"- **Latency p50 / p95**: {p50}s / {p95}s")
        a(
            f"- **Mean tokens (in / out)**: {toks_in} / {toks_out} "
            "(input is the total pydantic-ai reports, prompt-cache reads and writes "
            "included; the cost line prices cache traffic at its multipliers)"
        )
        total = em.total_cost_usd
        mean = (total / em.cases) if (total is not None and em.cases) else None
        a(f"- **Cost**: total ${_num(total, '.4f')}, mean ${_num(mean, '.4f')}/triage")
    else:
        a(f"- **Latency / tokens / cost**: {_PENDING} (from the golden-set eval run above)")
    a("")

    # --- reliability ---
    a("## Reliability (conformance & calibration)")
    a("")
    if eval_metrics is not None:
        em = eval_metrics
        a(f"- **Structured-output conformance**: {em.conformant}/{em.scored} well-formed reports")
        a(
            f"- **Confidence calibration (ECE)**: {_num(em.calibration_ece, '.3f')} "
            "(0 = perfectly calibrated; over the scored cases)",
        )
    else:
        a(f"- **Conformance / calibration**: {_PENDING} (from the golden-set eval run above)")
    a("")

    # --- grounding (replay cassettes) ---
    a("## Grounding (deterministic claim verification)")
    a("")
    a(
        "Every triage is stamped with a grounding verdict: the server re-checks "
        "each tool-derived claim in the report (CVSS, KEV, EPSS, exploit flags, "
        "ATT&CK ids) against the tool returns captured from the run's own message "
        "history. The numbers below aggregate the committed replay cassettes "
        "(`tests/cassettes/`): frozen real trajectories that CI replays through "
        "the current deterministic pipeline on every PR, hard-failing when the "
        "system prompt or a tool schema drifts from what the recorded model saw.",
    )
    a("")
    if grounding is not None:
        g = grounding
        a(
            f"- **Cassettes**: {g.cases} (model `{g.model}`, recorded {g.recorded_on}, "
            f"surface `{g.surface_hash}`)",
        )
        a(f"- **Reports grounded**: {g.grounded}/{g.cases}")
        a(
            f"- **Claims checked**: {g.claims_checked} (supported {g.supported}, "
            f"unbacked {g.unbacked}, mismatched {g.mismatched}, "
            f"unverifiable {g.unverifiable})",
        )
    else:
        a(f"- **Grounding**: {_PENDING} (record with `make record-cassettes`)")
    a("")

    # --- prioritization (deterministic) ---
    a("## Prioritization (deterministic SSVC)")
    a("")
    a(
        "The SSVC verdict (Stakeholder-Specific Vulnerability Categorization, "
        "CISA's remediation-urgency methodology) is computed server-side from the "
        "collected signals, not by the LLM, so it is reproducible from the same "
        "inputs. EPSS below is FIRST.org's predicted probability of exploitation "
        "in the next 30 days. Decision rules, most-urgent first:",
    )
    a("")
    high_p = ssvc_thresholds["high_probability"]
    high_pct = ssvc_thresholds["high_percentile"]
    watch = ssvc_thresholds["watch_probability"]
    a("| Signal | Decision |")
    a("|---|---|")
    a("| known ransomware association | **Act** |")
    a("| on CISA KEV (active exploitation) | **Act** |")
    a(f"| public exploit AND EPSS >= {high_p} | **Act** |")
    a("| public exploit (no high-EPSS) | **Attend** |")
    a(f"| EPSS >= {high_p} or percentile >= {high_pct} | **Attend** |")
    a(f"| EPSS >= {watch} (elevated) | **Track\\*** |")
    a("| High/Critical CVSS, no exploitation signal | **Track\\*** |")
    a("| none of the above | **Track** |")
    a("")
    a(
        "_SSVC-informed, not the full CISA tree: the Automatable and Mission & "
        "Well-being decision points are approximated (EPSS as a likelihood proxy; "
        "deployment-specific asset criticality is out of scope for a stateless tool)._",
    )
    a("")

    # --- reproduce ---
    a("## Reproduce")
    a("")
    a("```bash")
    a("make up          # start the stack")
    a("make seed        # seed the CVE index (once)")
    a(f"mkdir -p {DEFAULT_RESULTS_DIR}")
    a(f"make eval     EVAL_ARGS='--json-output {DEFAULT_RESULTS_DIR}/eval.json{pin}'")
    # Retrieval eval is embeddings-only (ChromaDB, no LLM), so it takes no --model.
    a(
        f"make eval     EVAL_ARGS='--retrieval --retrieval-sample 500 "
        f"--json-output {DEFAULT_RESULTS_DIR}/retrieval.json'",
    )
    a(f"make redteam  REDTEAM_ARGS='--json-output {DEFAULT_RESULTS_DIR}/redteam.json{pin}'")
    record_args = f" RECORD_ARGS='{pin.strip()}'" if pin.strip() else ""
    a(f"make record-cassettes{record_args}  # replay cassettes (recorder defaults to sonnet)")
    a("make scorecard   # regenerate this file from whatever JSONs exist")
    a("```")
    a("")
    a(
        "The eval and red-team runs require a live stack and bill the LLM; they are "
        "out of CI by design. The deterministic coverage sections regenerate offline.",
    )
    a("")
    return "\n".join(lines)


def ssvc_thresholds() -> dict[str, float]:
    from sec_recon_agent.agent.ssvc import (
        EPSS_HIGH_PERCENTILE,
        EPSS_HIGH_PROBABILITY,
        EPSS_WATCH_PROBABILITY,
    )

    return {
        "high_probability": EPSS_HIGH_PROBABILITY,
        "high_percentile": EPSS_HIGH_PERCENTILE,
        "watch_probability": EPSS_WATCH_PROBABILITY,
    }


# --- CLI shell ------------------------------------------------------------


def _load_json(path: str | None) -> Any | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _git_commit() -> str:
    try:
        # Fixed argv, no shell, no untrusted input; `git` resolved from PATH is
        # the intended behavior for a dev tool run inside the repo checkout.
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return out.stdout.strip() or "unknown"
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-recon-scorecard",
        description="Generate SCORECARD.md from deterministic coverage + optional result JSONs.",
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--eval-json", default=f"{DEFAULT_RESULTS_DIR}/eval.json")
    parser.add_argument("--retrieval-json", default=f"{DEFAULT_RESULTS_DIR}/retrieval.json")
    parser.add_argument("--redteam-json", default=f"{DEFAULT_RESULTS_DIR}/redteam.json")
    parser.add_argument("--cassettes-dir", default=str(DEFAULT_CASSETTES_DIR))
    parser.add_argument(
        "--model",
        default="n/a (deterministic-only)",
        help="model label for the stamp when no eval JSON is present.",
    )
    args = parser.parse_args(argv)

    eval_data = _load_json(args.eval_json)
    retrieval_data = _load_json(args.retrieval_json)
    redteam_data = _load_json(args.redteam_json)

    eval_metrics = (
        eval_metrics_from_records(eval_data, args.model) if isinstance(eval_data, list) else None
    )
    retrieval = (
        retrieval_metrics_from_json(retrieval_data) if isinstance(retrieval_data, dict) else None
    )
    redteam = redteam_metrics_from_json(redteam_data) if isinstance(redteam_data, dict) else None
    try:
        cassettes = load_all_cassettes(Path(args.cassettes_dir))
    except (ValueError, OSError):
        # Forgiving like _load_json: a malformed cassette must not block the
        # scorecard; the replay gate in CI is where malformation hard-fails.
        cassettes = []
    grounding = grounding_metrics_from_cassettes(cassettes)

    model = eval_metrics.model if eval_metrics is not None else args.model
    markdown = build_scorecard(
        model=model,
        date=datetime.now(UTC).date().isoformat(),
        commit=_git_commit(),
        golden=golden_coverage(),
        redteam_cov=redteam_coverage(),
        ssvc_thresholds=ssvc_thresholds(),
        eval_metrics=eval_metrics,
        retrieval=retrieval,
        redteam=redteam,
        grounding=grounding,
    )
    Path(args.output).write_text(markdown, encoding="utf-8")
    print(f"scorecard written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
