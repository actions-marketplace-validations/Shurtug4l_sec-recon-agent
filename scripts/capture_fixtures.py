#!/usr/bin/env python3
"""Capture a real /v1/triage SSE stream into a demo replay fixture.

Records every SSE frame with its arrival offset (ms from run start) and
writes the exact shape the frontend consumes (frontend/src/demo/fixtures/
*.json, typed as DemoFixture in frontend/src/demo/fixtures.ts): gallery
metadata at the top level, the byte-faithful frame sequence under `frames`.
The SSVC decision is read from the captured `final` frame, never hand-typed.

A capture that streams an `error` event or never reaches `final` is refused:
the demo gallery replays real successful runs only.

Usage (stack up via `make up`, ANTHROPIC_API_KEY set on the backend):
    python scripts/capture_fixtures.py \
        --query "Assess CVE-2014-0160 (Heartbleed) ..." \
        --slug heartbleed --cve CVE-2014-0160 \
        --title Heartbleed --subtitle "OpenSSL heartbeat memory disclosure"
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
import urllib.request
from typing import Any

API = "http://localhost:8000/v1/triage"
DEFAULT_OUT = "frontend/src/demo/fixtures"


def capture_frames(query: str, model: str | None) -> tuple[list[dict[str, Any]], int]:
    body: dict[str, Any] = {"query": query}
    if model:
        body["model"] = model
    req = urllib.request.Request(
        API,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
        method="POST",
    )
    frames: list[dict[str, Any]] = []
    start = time.monotonic()
    with urllib.request.urlopen(req, timeout=300) as resp:
        buf = ""
        for chunk in resp:
            buf += chunk.decode("utf-8", errors="replace")
            buf = buf.replace("\r\n", "\n")
            while "\n\n" in buf:
                frame, buf = buf.split("\n\n", 1)
                event_type = None
                data_line = None
                for line in frame.split("\n"):
                    if line.startswith("event:"):
                        event_type = line[len("event:") :].strip()
                    elif line.startswith("data:"):
                        data_line = line[len("data:") :].lstrip()
                if event_type is None or data_line is None:
                    continue
                at_ms = int((time.monotonic() - start) * 1000)
                try:
                    parsed = json.loads(data_line)
                except json.JSONDecodeError:
                    parsed = data_line
                frames.append({"event": event_type, "data": parsed, "at_ms": at_ms})
                # Live progress to stderr.
                tag = event_type
                if event_type == "node":
                    tag = f"node:{parsed.get('node')}"
                elif event_type == "final":
                    ssvc = parsed.get("ssvc") or {}
                    grounding = parsed.get("grounding") or {}
                    tag = (
                        f"final sev={parsed.get('severity')} "
                        f"ssvc={ssvc.get('decision')} rule={ssvc.get('rule')} "
                        f"grounding={grounding.get('status')} "
                        f"({grounding.get('supported')}/{grounding.get('claims_checked')}) "
                        f"cov={len(parsed.get('signal_coverage') or [])}"
                    )
                print(f"  [{at_ms:>6}ms] {tag}", file=sys.stderr)
    duration_ms = int((time.monotonic() - start) * 1000)
    return frames, duration_ms


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", required=True)
    ap.add_argument("--slug", required=True)
    ap.add_argument("--cve", required=True, help="Canonical CVE id shown in the gallery")
    ap.add_argument("--title", required=True, help="Gallery card title")
    ap.add_argument("--subtitle", required=True, help="Gallery card subtitle")
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    frames, duration_ms = capture_frames(args.query, args.model)

    error = next((f for f in frames if f["event"] == "error"), None)
    if error:
        print(f"!! refused: stream emitted an error event: {error['data']}", file=sys.stderr)
        return 1
    final = next((f for f in frames if f["event"] == "final"), None)
    if final is None:
        print("!! refused: stream ended without a final report", file=sys.stderr)
        return 1
    final_report = final["data"] if isinstance(final["data"], dict) else {}
    decision = (final_report.get("ssvc") or {}).get("decision")
    if decision is None:
        print("!! refused: final report carries no SSVC decision", file=sys.stderr)
        return 1

    fixture = {
        "slug": args.slug,
        "cve": args.cve,
        "title": args.title,
        "subtitle": args.subtitle,
        "query": args.query,
        "model": args.model,
        "capturedAt": datetime.datetime.now(tz=datetime.UTC).date().isoformat(),
        "decision": decision,
        "durationMs": duration_ms,
        "frames": frames,
    }
    path = f"{args.out}/{args.slug}.json"
    with open(path, "w") as f:
        json.dump(fixture, f, indent=2)
        f.write("\n")
    print(
        f"-> wrote {path} ({duration_ms}ms, {len(frames)} frames, decision={decision})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
