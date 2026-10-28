#!/usr/bin/env python3
"""Record golden-set trajectories as replay cassettes. Bills the LLM.

Runs each golden case through the triage agent DIRECTLY (build_agent
against the live MCP server, no API container in between: the server-side
stamps are recomputed at replay by the same pure functions, so nothing is
lost) and freezes the full message history + raw report + deterministic
outcomes into tests/cassettes/<case_id>.json.

Requires: MCP server up (`make up` or the MCP container alone) and
ANTHROPIC_API_KEY in the environment / .env.

Usage:
    uv run python scripts/record_cassettes.py [--model sonnet]
        [--only case-id ...] [--out-dir tests/cassettes] [--allow-failing]

A case whose fresh run fails the golden scorer is NOT written by default
(LLM variance: re-run it), so a failing baseline cannot be baked into the
gate silently. --allow-failing overrides, for conscious debugging only.
"""

import argparse
import asyncio
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from pydantic_ai.messages import ModelMessagesTypeAdapter
from pydantic_ai.usage import UsageLimits

from sec_recon_agent.agent.grounding import verify_grounding
from sec_recon_agent.agent.ssvc import assess_ssvc
from sec_recon_agent.agent.trajectory import extract_tool_invocations
from sec_recon_agent.agent.triage import (
    build_agent,
    export_anthropic_api_key_to_env,
    resolve_model,
)
from sec_recon_agent.config import settings
from sec_recon_agent.eval.cassette import (
    Cassette,
    RecordedOutcomes,
    save_cassette,
    staleness_hash,
)
from sec_recon_agent.eval.golden_set import GOLDEN_SET, GoldenCase
from sec_recon_agent.eval.scorer import score

# A cassette larger than this is a smell (runaway tool output), not a hard
# error: warn so the recording gets a second look before committing.
SIZE_WARN_BYTES = 2_000_000


async def record_case(case: GoldenCase, model_alias: str, surface_hash: str) -> Cassette:
    agent = build_agent(model_override=model_alias)
    limits = UsageLimits(request_limit=settings.agent_request_limit)
    started = time.monotonic()
    async with agent.iter(case.query, usage_limits=limits) as run:
        async for _node in run:
            pass
        result = run.result
    elapsed = time.monotonic() - started
    assert result is not None  # iter completed without raising

    report = result.output
    messages = result.all_messages()
    invocations = extract_tool_invocations(messages)
    ssvc = assess_ssvc(report.cves, invocations)
    grounding = verify_grounding(report, invocations)
    stamped = report.model_copy(update={"ssvc": ssvc, "grounding": grounding})
    verdict = score(case, stamped)

    usage = result.usage()
    return Cassette(
        case_id=case.id,
        model=resolve_model(model_alias),
        recorded_at=datetime.now(UTC).isoformat(timespec="seconds"),
        staleness_hash=surface_hash,
        elapsed_seconds=round(elapsed, 3),
        usage={
            "input_tokens": getattr(usage, "input_tokens", None),
            "output_tokens": getattr(usage, "output_tokens", None),
            "requests": getattr(usage, "requests", None),
            "cache_read_tokens": getattr(usage, "cache_read_tokens", None),
            "cache_write_tokens": getattr(usage, "cache_write_tokens", None),
        },
        messages=ModelMessagesTypeAdapter.dump_python(messages, mode="json"),
        report=report.model_dump(mode="json"),
        outcomes=RecordedOutcomes(
            ssvc=ssvc.model_dump(mode="json"),
            grounding=grounding.model_dump(mode="json"),
            golden_passed=verdict.passed,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="sonnet", help="Model alias or full id (allowlisted).")
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="CASE_ID",
        help="Record only this case id (repeatable). Default: all golden cases.",
    )
    parser.add_argument("--out-dir", default="tests/cassettes", type=Path)
    parser.add_argument(
        "--allow-failing",
        action="store_true",
        help="Write cassettes even when the fresh run fails the golden scorer.",
    )
    args = parser.parse_args()

    export_anthropic_api_key_to_env()
    cases = [c for c in GOLDEN_SET if args.only is None or c.id in args.only]
    if args.only:
        unknown = set(args.only) - {c.id for c in GOLDEN_SET}
        if unknown:
            print(f"unknown case ids: {sorted(unknown)}", file=sys.stderr)
            return 2

    surface_hash = staleness_hash()
    print(f"surface hash {surface_hash[:16]}...  model {args.model}  cases {len(cases)}")

    secret = settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else None
    failures: list[str] = []
    for case in cases:
        print(f"[{case.id}] running...", flush=True)
        try:
            cassette = asyncio.run(record_case(case, args.model, surface_hash))
        except Exception as exc:
            print(f"[{case.id}] RUN ERROR: {exc}", file=sys.stderr)
            failures.append(case.id)
            continue

        payload = cassette.model_dump_json()
        if secret and secret in payload:
            print(f"[{case.id}] REFUSED: API key material in serialized cassette", file=sys.stderr)
            failures.append(case.id)
            continue
        if not cassette.outcomes.golden_passed and not args.allow_failing:
            print(
                f"[{case.id}] NOT WRITTEN: fresh run fails the golden scorer "
                "(LLM variance? re-run; --allow-failing to force)",
                file=sys.stderr,
            )
            failures.append(case.id)
            continue

        path = save_cassette(cassette, args.out_dir)
        size = path.stat().st_size
        note = "  SIZE WARNING" if size > SIZE_WARN_BYTES else ""
        grounding_status = cassette.outcomes.grounding.get("status")
        ssvc_decision = cassette.outcomes.ssvc.get("decision")
        print(
            f"[{case.id}] ok  {cassette.elapsed_seconds:.1f}s  ssvc={ssvc_decision}  "
            f"grounding={grounding_status}  golden={cassette.outcomes.golden_passed}  "
            f"{size / 1024:.0f}KB{note}",
        )

    if failures:
        print(f"\n{len(failures)} case(s) not recorded: {failures}", file=sys.stderr)
        return 1
    print(f"\nall {len(cases)} cassettes written to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
