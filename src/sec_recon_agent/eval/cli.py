"""`sec-recon-eval` entry point.

Run the curated golden set against a live agent API and print a
human-readable summary plus an optional JSON dump for archival.
"""

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

from sec_recon_agent.eval.cost import PRICING_SOURCE_DATE, estimate_cost_usd
from sec_recon_agent.eval.golden_set import GOLDEN_SET, GoldenCase
from sec_recon_agent.eval.metrics import (
    confidence_to_probability,
    expected_calibration_error,
    is_conformant,
    percentile,
)
from sec_recon_agent.eval.runner import (
    DEFAULT_API_URL,
    DEFAULT_TIMEOUT_SECONDS,
    CaseResult,
    health_check,
    run_case,
)
from sec_recon_agent.eval.scorer import CaseVerdict, score


def _filter_cases(filter_expr: str | None) -> tuple[GoldenCase, ...]:
    if not filter_expr:
        return GOLDEN_SET
    tokens = {t.strip() for t in filter_expr.split(",") if t.strip()}
    return tuple(c for c in GOLDEN_SET if c.id in tokens or set(c.tags) & tokens)


def _format_row(case: GoldenCase, verdict: CaseVerdict, elapsed: float) -> str:
    badge = "PASS" if verdict.passed else "FAIL"
    note = f" | {'; '.join(verdict.notes)}" if verdict.notes else ""
    return (
        f"  [{badge}] {case.id:<30} "
        f"sev={'ok' if verdict.severity_ok else 'no':>3}  "
        f"cve_recall={verdict.cve_recall:.2f}  "
        f"kev={'ok' if verdict.kev_ok else 'no':>3}  "
        f"rw={'ok' if verdict.ransomware_ok else 'no':>3}  "
        f"{elapsed:5.1f}s{note}"
    )


def _fmt(value: float | None, spec: str, na: str = "n/a") -> str:
    return format(value, spec) if value is not None else na


def _print_efficiency_and_quality(
    results: list[CaseResult],
    verdicts: list[CaseVerdict | None],
    model_label: str,
) -> None:
    """Print the scorecard axes the golden set alone did not measure:
    latency p50/p95, tokens, $/triage, structured-output conformance, and
    confidence calibration."""
    if not results:
        return

    latencies = [r.elapsed_seconds for r in results]
    reported = [r for r in results if r.report is not None]

    in_tokens = [r.input_tokens for r in results if r.input_tokens is not None]
    out_tokens = [r.output_tokens for r in results if r.output_tokens is not None]
    per_case_costs = [
        c
        for r in results
        if (
            c := estimate_cost_usd(
                model_label,
                r.input_tokens,
                r.output_tokens,
                cache_read_tokens=r.cache_read_tokens,
                cache_write_tokens=r.cache_write_tokens,
            )
        )
        is not None
    ]
    total_cost = sum(per_case_costs) if per_case_costs else None

    conformant = sum(1 for r in reported if is_conformant(r.report))
    calib_samples = [
        (confidence_to_probability(r.report.confidence), v.passed)
        for r, v in zip(results, verdicts, strict=True)
        if r.report is not None and v is not None
    ]
    ece = expected_calibration_error(calib_samples)

    print("\n  --- efficiency & quality ---")
    print(
        f"  latency:      p50={_fmt(percentile(latencies, 50), '.1f')}s  "
        f"p95={_fmt(percentile(latencies, 95), '.1f')}s",
    )
    if in_tokens or out_tokens:
        mean_in = sum(in_tokens) / len(in_tokens) if in_tokens else None
        mean_out = sum(out_tokens) / len(out_tokens) if out_tokens else None
        print(
            f"  tokens/case:  in={_fmt(mean_in, '.0f')}  out={_fmt(mean_out, '.0f')}  "
            f"(usage on {len(in_tokens)}/{len(results)} cases)",
        )
        cost_line = f"  cost:         total=${_fmt(total_cost, '.4f')}"
        if total_cost is not None and per_case_costs:
            cost_line += f"  mean=${total_cost / len(per_case_costs):.4f}/triage"
        print(f"{cost_line}  (pricing @ {PRICING_SOURCE_DATE})")
    else:
        print("  tokens/case:  n/a (no usage events; API did not emit token counts)")
    print(
        f"  conformance:  {conformant}/{len(reported)} well-formed reports"
        if reported
        else "  conformance:  n/a (no reports returned)",
    )
    print(
        f"  calibration:  ECE={_fmt(ece, '.3f')}  "
        f"(over {len(calib_samples)} scored cases; 0 = perfectly calibrated)",
    )


def _run_retrieval(args: argparse.Namespace) -> int:
    """Evaluate cve_semantic_search retrieval quality against the local index."""
    from sec_recon_agent.eval.retrieval import run_retrieval

    mode = "hard" if args.retrieval_hard else "default"
    print(
        f"evaluating cve_semantic_search retrieval "
        f"(sample<= {args.retrieval_sample}, top_k={args.retrieval_top_k}, mode={mode}) ...",
    )
    report = run_retrieval(
        sample_size=args.retrieval_sample,
        top_k=args.retrieval_top_k,
        hard=args.retrieval_hard,
    )
    if report.sampled == 0:
        print(
            "no documents in the ChromaDB index; run `sec-recon-seed` first.",
            file=sys.stderr,
        )
        return 2
    print(
        f"\n  retrieval over {report.sampled} sampled CVEs "
        f"(top_k={report.top_k}, mode={report.mode}, query_chars={report.query_chars}):",
    )
    print(f"  MRR:          {_fmt(report.mrr, '.3f')}")
    print(f"  hit-rate@1:   {_fmt(report.hit_rate_at_1, '.2%')}")
    print(f"  hit-rate@3:   {_fmt(report.hit_rate_at_3, '.2%')}")
    print(f"  hit-rate@5:   {_fmt(report.hit_rate_at_5, '.2%')}")
    print(f"  p95 top-1 similarity: {_fmt(report.p95_similarity_top1, '.3f')}")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, default=str)
        print(f"json report written to {args.json_output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-recon-eval",
        description=(
            "Run the curated golden set against the live agent API and "
            "produce a soft-assertion regression report."
        ),
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"agent API base URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--filter",
        default=None,
        help=(
            "comma-separated list of case IDs or tags to run "
            "(e.g. 'kev,by-id,heartbleed'). Default: all cases."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-case timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS:.0f})",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="optional path to dump structured results as JSON",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "override LLM model for this run (haiku / sonnet / opus or a "
            "full identifier on the backend allowlist). Default: deployment "
            "default."
        ),
    )
    parser.add_argument(
        "--models",
        default=None,
        help=(
            "comma-separated list of models to compare (e.g. 'haiku,sonnet,opus'). "
            "Runs the full golden set against each and prints a side-by-side "
            "table. Mutually exclusive with --model."
        ),
    )
    parser.add_argument(
        "--retrieval",
        action="store_true",
        help=(
            "evaluate cve_semantic_search retrieval quality (hit-rate@k + MRR) "
            "against the local ChromaDB index instead of running the golden set. "
            "Requires a seeded index (`sec-recon-seed`); no live API needed."
        ),
    )
    parser.add_argument(
        "--retrieval-sample",
        type=int,
        default=100,
        help="max CVEs to sample from the index for retrieval eval (default: 100)",
    )
    parser.add_argument(
        "--retrieval-top-k",
        type=int,
        default=10,
        help="top_k passed to cve_semantic_search during retrieval eval (default: 10)",
    )
    parser.add_argument(
        "--retrieval-hard",
        action="store_true",
        help=(
            "hard mode: ~80-char keyword-style queries (stopwords and CVE "
            "boilerplate stripped) instead of the 160-char description prefix. "
            "Harder, closer to how an analyst queries; use it to compare "
            "retriever variants once the default mode saturates."
        ),
    )
    args = parser.parse_args(argv)

    if args.retrieval:
        return _run_retrieval(args)

    if args.model and args.models:
        print("--model and --models are mutually exclusive", file=sys.stderr)
        return 2

    cases = _filter_cases(args.filter)
    if not cases:
        print(f"no cases matched filter {args.filter!r}", file=sys.stderr)
        return 2

    if not health_check(args.api_url):
        print(
            f"agent API at {args.api_url} is not responding on /v1/health. Did you `make up`?",
            file=sys.stderr,
        )
        return 2

    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
        return _run_comparison(cases, args, models)
    return _run_single(cases, args, args.model)


def _run_single(
    cases: tuple[GoldenCase, ...],
    args: argparse.Namespace,
    model: str | None,
) -> int:
    label = model or "default"
    print(f"running {len(cases)} case(s) against {args.api_url} (model={label}) ...")
    json_payload: list[dict[str, Any]] = []
    all_results: list[CaseResult] = []
    all_verdicts: list[CaseVerdict | None] = []
    passed = 0
    for case in cases:
        result = run_case(
            case,
            api_url=args.api_url,
            timeout_seconds=args.timeout,
            model=model,
        )
        all_results.append(result)
        usage = {
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "cache_read_tokens": result.cache_read_tokens,
            "cache_write_tokens": result.cache_write_tokens,
            "cost_usd": estimate_cost_usd(
                label,
                result.input_tokens,
                result.output_tokens,
                cache_read_tokens=result.cache_read_tokens,
                cache_write_tokens=result.cache_write_tokens,
            ),
        }
        if result.report is None:
            all_verdicts.append(None)
            print(
                f"  [ERR ] {case.id:<30} {result.error}  {result.elapsed_seconds:5.1f}s",
            )
            json_payload.append(
                {
                    "case": asdict(case),
                    "model": label,
                    "error": result.error,
                    "elapsed_seconds": result.elapsed_seconds,
                    "usage": usage,
                },
            )
            continue
        verdict = score(case, result.report)
        all_verdicts.append(verdict)
        passed += int(verdict.passed)
        print(_format_row(case, verdict, result.elapsed_seconds))
        json_payload.append(
            {
                "case": asdict(case),
                "model": label,
                "verdict": asdict(verdict),
                "report": result.report.model_dump(mode="json"),
                "elapsed_seconds": result.elapsed_seconds,
                "usage": usage,
                "conformant": is_conformant(result.report),
            },
        )

    total = len(cases)
    rate = passed / total if total else 0.0
    print(f"\nresult: {passed}/{total} cases passed ({rate:.0%})")
    _print_efficiency_and_quality(all_results, all_verdicts, label)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2, default=str)
        print(f"json report written to {args.json_output}")

    # Exit code: 0 if all passed, 1 otherwise (handy for CI gating once
    # the suite is stable enough to be a blocking signal).
    return 0 if passed == total else 1


def _run_comparison(
    cases: tuple[GoldenCase, ...],
    args: argparse.Namespace,
    models: list[str],
) -> int:
    """Run the same case set against each model and print a side-by-side table."""
    per_model: dict[str, list[dict[str, Any]]] = {}
    per_model_pass: dict[str, int] = {}

    for model in models:
        print(f"\n=== model: {model} ===")
        rows: list[dict[str, Any]] = []
        model_results: list[CaseResult] = []
        model_verdicts: list[CaseVerdict | None] = []
        passed = 0
        for case in cases:
            result = run_case(
                case,
                api_url=args.api_url,
                timeout_seconds=args.timeout,
                model=model,
            )
            model_results.append(result)
            cost = estimate_cost_usd(
                model,
                result.input_tokens,
                result.output_tokens,
                cache_read_tokens=result.cache_read_tokens,
                cache_write_tokens=result.cache_write_tokens,
            )
            if result.report is None:
                model_verdicts.append(None)
                rows.append(
                    {
                        "case_id": case.id,
                        "passed": False,
                        "cve_recall": 0.0,
                        "elapsed_seconds": result.elapsed_seconds,
                        "input_tokens": result.input_tokens,
                        "output_tokens": result.output_tokens,
                        "cost_usd": cost,
                        "error": result.error,
                    },
                )
                print(f"  [ERR ] {case.id:<30} {result.error}")
                continue
            verdict = score(case, result.report)
            model_verdicts.append(verdict)
            passed += int(verdict.passed)
            rows.append(
                {
                    "case_id": case.id,
                    "passed": verdict.passed,
                    "cve_recall": verdict.cve_recall,
                    "severity_ok": verdict.severity_ok,
                    "elapsed_seconds": result.elapsed_seconds,
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "cost_usd": cost,
                    "conformant": is_conformant(result.report),
                },
            )
            print(_format_row(case, verdict, result.elapsed_seconds))
        per_model[model] = rows
        per_model_pass[model] = passed
        print(
            f"  -> {passed}/{len(cases)} passed ({passed / max(len(cases), 1):.0%})",
        )
        _print_efficiency_and_quality(model_results, model_verdicts, model)

    # Side-by-side summary
    print("\n=== comparison summary ===")
    header = f"  {'case':<30} " + "  ".join(f"{m:>10}" for m in models)
    print(header)
    for i, case in enumerate(cases):
        cells = []
        for model in models:
            row = per_model[model][i]
            cells.append("PASS" if row.get("passed") else "FAIL")
        print(f"  {case.id:<30} " + "  ".join(f"{c:>10}" for c in cells))
    print()
    for model in models:
        total = len(cases)
        rate = per_model_pass[model] / total if total else 0.0
        print(f"  {model:<20} {per_model_pass[model]}/{total} ({rate:.0%})")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(
                {model: per_model[model] for model in models},
                f,
                indent=2,
                default=str,
            )
        print(f"json report written to {args.json_output}")

    all_pass = all(per_model_pass[m] == len(cases) for m in models)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
