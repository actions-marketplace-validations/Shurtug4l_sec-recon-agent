#!/usr/bin/env python3
"""Derive the frontend's scorecard snapshot from the backend result JSONs.

The static /scorecard route renders `frontend/src/demo/scorecard/*.json`: the
same eval / retrieval / red-team results `make scorecard` consumes, slimmed
to the fields the page reads so the client bundle does not ship eleven full
TriageReports and eighteen injected ones. Until now the slimming was done by
hand, which is how a snapshot drifts from the scorecard it claims to mirror.
This script is the deterministic form: run it right after `make scorecard`.

Usage:
    uv run python scripts/slim_scorecard_snapshot.py [--source data/scorecard]
        [--dest frontend/src/demo/scorecard] [--model sonnet]
        [--source-note "make scorecard on the live stack (...)"]

Reads eval.json, redteam.json and retrieval.json from --source (each optional:
a missing input leaves the corresponding snapshot untouched) and writes the
four snapshot files. Provenance is stamped from the current git commit and
today's date, matching what `make scorecard` stamps into SCORECARD.md.
"""

import argparse
import json
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sec_recon_agent.eval.cost import PRICING_SOURCE_DATE


def _slim_eval(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for record in records:
        case = record["case"]
        report = record.get("report") or {}
        out.append(
            {
                "id": case["id"],
                "query": case["query"],
                "model": record["model"],
                "expected_severity": case.get("expected_severity"),
                "expected_in_kev": case.get("expected_in_kev"),
                "severity": report.get("severity"),
                "confidence": report.get("confidence"),
                "verdict": record["verdict"],
                "elapsed_seconds": record["elapsed_seconds"],
                "usage": record.get("usage"),
                "conformant": record["conformant"],
            },
        )
    return out


def _slim_redteam(result: dict[str, Any]) -> dict[str, Any]:
    records = result["records"]
    per_category: dict[str, Counter[str]] = {}
    misses: list[dict[str, Any]] = []
    for record in records:
        payload = record["payload"]
        verdict = record["verdict"]
        counts = per_category.setdefault(payload["category"], Counter())
        counts["total"] += 1
        if verdict["resisted"]:
            counts["resisted"] += 1
        else:
            misses.append(
                {
                    "id": payload["id"],
                    "category": payload["category"],
                    "severity": payload["severity"],
                    "atlas_techniques": payload.get("atlas_techniques", []),
                    "failed_checks": verdict.get("failed_checks", []),
                },
            )
    return {
        "summary": result["summary"],
        "atlas_breakdown": result["atlas_breakdown"],
        "category_breakdown": [
            {"category": category, "total": counts["total"], "resisted": counts["resisted"]}
            for category, counts in sorted(per_category.items())
        ],
        "misses": misses,
    }


def _git_short_sha() -> str:
    return subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607 - same form as eval/scorecard.py
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _write(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="data/scorecard", type=Path)
    parser.add_argument("--dest", default="frontend/src/demo/scorecard", type=Path)
    parser.add_argument("--model", default="sonnet")
    parser.add_argument(
        "--source-note",
        default="make scorecard on the live stack",
        help="Free-text provenance note shown on the /scorecard page.",
    )
    args = parser.parse_args()
    args.dest.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    eval_path = args.source / "eval.json"
    if eval_path.exists():
        _write(args.dest / "eval.json", _slim_eval(json.loads(eval_path.read_text("utf-8"))))
        written.append("eval.json")
    redteam_path = args.source / "redteam.json"
    if redteam_path.exists():
        redteam = json.loads(redteam_path.read_text("utf-8"))
        _write(args.dest / "redteam.json", _slim_redteam(redteam))
        written.append("redteam.json")
    retrieval_path = args.source / "retrieval.json"
    if retrieval_path.exists():
        _write(args.dest / "retrieval.json", json.loads(retrieval_path.read_text("utf-8")))
        written.append("retrieval.json")
    _write(
        args.dest / "provenance.json",
        {
            "model": args.model,
            "date": datetime.now(UTC).date().isoformat(),
            "commit": _git_short_sha(),
            "pricing_note": f"Anthropic published rates as of {PRICING_SOURCE_DATE}",
            "source": args.source_note,
        },
    )
    written.append("provenance.json")
    print(f"snapshot written to {args.dest}/: {', '.join(written)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
