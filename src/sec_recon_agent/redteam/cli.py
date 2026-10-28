"""`sec-recon-redteam`: prompt-injection regression battery.

Runs the curated payload set in `payloads.py` against a live agent API
and prints a per-payload verdict plus an aggregate resistance rate.
Out of CI by design (requires `make up`, bills the LLM).
"""

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import asdict
from typing import Any

from sec_recon_agent.eval.golden_set import GoldenCase
from sec_recon_agent.eval.runner import (
    DEFAULT_API_URL,
    DEFAULT_TIMEOUT_SECONDS,
    health_check,
    run_case,
)
from sec_recon_agent.redteam.payloads import (
    PAYLOADS,
    InjectionPayload,
)
from sec_recon_agent.redteam.scorer import (
    PayloadVerdict,
    aggregate_by_atlas_technique,
    score_payload,
    summarize,
)


def _filter_payloads(filter_expr: str | None) -> tuple[InjectionPayload, ...]:
    if not filter_expr:
        return PAYLOADS
    tokens = {t.strip() for t in filter_expr.split(",") if t.strip()}
    return tuple(
        p
        for p in PAYLOADS
        if (
            p.id in tokens
            or p.category in tokens
            or set(p.tags) & tokens
            or set(p.atlas_techniques) & tokens
        )
    )


def _payload_as_case(payload: InjectionPayload) -> GoldenCase:
    """Reuse the eval runner by adapting the payload to a GoldenCase."""
    from sec_recon_agent.agent.schema import Severity

    return GoldenCase(
        id=payload.id,
        query=payload.query,
        expected_severity=Severity.HIGH,  # unused in red-team scoring
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-recon-redteam",
        description=(
            "Run the prompt-injection battery against the live agent API "
            "and report per-category resistance rate."
        ),
    )
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument(
        "--filter",
        default=None,
        help=(
            "comma-separated list of payload ids, categories, tags, or "
            "MITRE ATLAS technique IDs (e.g. 'AML.T0051.001,direct'). "
            "Default: all."
        ),
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--model",
        default=None,
        help="optional per-call model override (haiku / sonnet / opus or full id).",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="optional path for a structured JSON report.",
    )
    args = parser.parse_args(argv)

    payloads = _filter_payloads(args.filter)
    if not payloads:
        print(f"no payloads matched filter {args.filter!r}", file=sys.stderr)
        return 2

    if not health_check(args.api_url):
        print(
            f"agent API at {args.api_url} is not responding on /v1/health. Did you `make up`?",
            file=sys.stderr,
        )
        return 2

    label = args.model or "default"
    print(
        f"running {len(payloads)} payload(s) against {args.api_url} (model={label}) ...",
    )
    verdicts: list[PayloadVerdict] = []
    json_records: list[dict[str, Any]] = []
    for payload in payloads:
        result = run_case(
            _payload_as_case(payload),
            api_url=args.api_url,
            timeout_seconds=args.timeout,
            model=args.model,
        )
        if result.report is None:
            # An error from the API is itself a form of resistance — the
            # agent refused to produce a report. We flag it separately
            # rather than counting it as a clean pass: an outage masquerading
            # as resistance would be a false positive.
            print(
                f"  [ERR ] {payload.id:<32} {result.error}  {result.elapsed_seconds:5.1f}s",
            )
            json_records.append(
                {
                    "payload": asdict(payload),
                    "error": result.error,
                    "elapsed_seconds": result.elapsed_seconds,
                },
            )
            continue
        verdict = score_payload(payload, result.report)
        verdicts.append(verdict)
        badge = "RESIST" if verdict.resisted else "CEDED "
        notes = " | " + "; ".join(verdict.failed_checks) if verdict.failed_checks else ""
        print(
            f"  [{badge}] {payload.id:<32} cat={payload.category:<14} "
            f"{result.elapsed_seconds:5.1f}s{notes}",
        )
        json_records.append(
            {
                "payload": asdict(payload),
                "verdict": asdict(verdict),
                "report": result.report.model_dump(mode="json"),
                "elapsed_seconds": result.elapsed_seconds,
            },
        )

    summary = summarize(verdicts)
    print(
        f"\nresistance: {summary['resisted']}/{summary['total']} "
        f"({float(summary['resistance_rate']):.0%})",
    )

    # Per-category breakdown
    by_cat: dict[str, list[PayloadVerdict]] = defaultdict(list)
    for v in verdicts:
        by_cat[v.category].append(v)
    if by_cat:
        print("\nper category:")
        for cat in sorted(by_cat):
            cat_verdicts = by_cat[cat]
            cat_resisted = sum(1 for v in cat_verdicts if v.resisted)
            cat_total = len(cat_verdicts)
            rate = cat_resisted / cat_total if cat_total else 0.0
            print(f"  {cat:<16} {cat_resisted}/{cat_total} ({rate:.0%})")

    # Per-MITRE-ATLAS-technique breakdown
    atlas_aggregates = aggregate_by_atlas_technique(verdicts)
    if atlas_aggregates:
        print("\nper MITRE ATLAS technique:")
        for agg in atlas_aggregates:
            print(
                f"  {agg.technique:<14} {agg.resisted}/{agg.total} ({agg.rate:.0%})",
            )

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "summary": summary,
                    "records": json_records,
                    "atlas_breakdown": [
                        {
                            "technique": a.technique,
                            "total": a.total,
                            "resisted": a.resisted,
                            "rate": a.rate,
                        }
                        for a in atlas_aggregates
                    ],
                },
                f,
                indent=2,
                default=str,
            )
        print(f"\njson report written to {args.json_output}")

    # Exit 0 only when every payload was resisted. Useful as a gate for
    # release-candidate checks after a prompt change.
    return 0 if summary["resisted"] == summary["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
