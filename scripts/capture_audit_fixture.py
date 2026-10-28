#!/usr/bin/env python3
"""Generate the keyless demo's audit-trail fixture from the committed SSE captures.

The demo (GitHub Pages) has no backend, so the /v1/audit view needs a static
snapshot the way the transparency tab uses demo/meta.json. This builds an
AUTHENTIC one: it reads the seven committed demo fixtures
(frontend/src/demo/fixtures/*.json), takes the real TriageReport from each
`final` frame, derives the audit signals with the production
`summarize_for_audit`, and seals a real hash chain through the actual
`AuditStore`. Only the per-row timestamp is synthesized (the demo fixtures
record a capture DATE, not a time), and that is stated in the row shape.

The output (frontend/src/demo/audit.json) mirrors the /v1/audit response shape
byte-for-byte (digest-only rows, most-recent-first), so the frontend loader
treats demo and live identically.

Run from the repo root:  uv run python scripts/capture_audit_fixture.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from sec_recon_agent.audit.models import (
    GENESIS_HASH,
    TriageEvent,
    sha256_hex,
    summarize_for_audit,
)
from sec_recon_agent.audit.store import AuditStore

ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT / "frontend" / "src" / "demo" / "fixtures"
OUT_FILE = ROOT / "frontend" / "src" / "demo" / "audit.json"

# Digest-only projection: matches AuditRow in api/stream.py (no plaintext).
_ROW_FIELDS = (
    "event_id",
    "ts",
    "query_sha256",
    "query_length",
    "report_sha256",
    "severity",
    "confidence",
    "cves_count",
    "attack_techniques_count",
    "kev_hits",
    "ransomware_hits",
    "high_epss_hits",
    "ssvc_decision",
    "grounding_status",
    "model",
    "duration_ms",
    "outcome",
    "error_class",
    "prev_event_hash",
    "this_event_hash",
)


def _final_report(fixture: dict[str, Any]) -> dict[str, Any]:
    for frame in fixture.get("frames", []):
        if frame.get("event") == "final":
            data = frame["data"]
            report = json.loads(data) if isinstance(data, str) else data
            if not isinstance(report, dict):
                raise ValueError(f"fixture {fixture.get('slug')} final frame is not an object")
            return report
    raise ValueError(f"fixture {fixture.get('slug')} has no final frame")


def _load_fixtures() -> list[dict[str, Any]]:
    fixtures = [json.loads(p.read_text()) for p in sorted(FIXTURES_DIR.glob("*.json"))]
    # Chronological chain order: by capture date, then slug for a stable tiebreak.
    fixtures.sort(key=lambda f: (str(f.get("capturedAt", "")), str(f.get("slug", ""))))
    return fixtures


def _event_for(fixture: dict[str, Any], seq: int) -> TriageEvent:
    report = _final_report(fixture)
    result_json = json.dumps(report, separators=(",", ":"), sort_keys=True)
    summary = summarize_for_audit(report)
    query = str(fixture["query"])
    # Capture date is real; the time is synthesized (see module docstring),
    # spaced one minute apart so the rows are distinct and ordered.
    date = str(fixture.get("capturedAt", "2026-07-08"))[:10]
    ts = f"{date}T{9 + seq // 60:02d}:{seq % 60:02d}:00+00:00"
    return TriageEvent(
        event_id=f"demo-{fixture['slug']}",
        ts=ts,
        query_sha256=sha256_hex(query),
        query_length=len(query),
        report_sha256=sha256_hex(result_json),
        severity=summary["severity"] if isinstance(summary["severity"], str) else None,
        confidence=summary["confidence"] if isinstance(summary["confidence"], str) else None,
        cves_count=int(summary["cves_count"] or 0),
        attack_techniques_count=int(summary["attack_techniques_count"] or 0),
        kev_hits=int(summary["kev_hits"] or 0),
        ransomware_hits=int(summary["ransomware_hits"] or 0),
        high_epss_hits=int(summary["high_epss_hits"] or 0),
        ssvc_decision=summary["ssvc_decision"]
        if isinstance(summary["ssvc_decision"], str)
        else None,
        grounding_status=(
            summary["grounding_status"] if isinstance(summary["grounding_status"], str) else None
        ),
        model=f"anthropic:{fixture.get('model', 'sonnet')}",
        duration_ms=int(fixture.get("durationMs", 0)),
        outcome="success",
        prev_event_hash=GENESIS_HASH,  # AuditStore.append seals the real chain
    )


def main() -> None:
    fixtures = _load_fixtures()
    with tempfile.TemporaryDirectory() as tmp:
        store = AuditStore(Path(tmp) / "audit.db")
        for seq, fixture in enumerate(fixtures):
            store.append(_event_for(fixture, seq))
        verified = store.verify()  # proves the generated chain is valid
        count = store.count()
        rows = [
            {f: getattr(event, f) for f in _ROW_FIELDS}
            for event in store.tail(count)  # most-recent-first, like /v1/audit
        ]
        store.close()

    payload = {
        "enabled": True,
        "count": count,
        "verification": {"ok": True, "verified_count": verified, "broken_event_id": None},
        "events": rows,
    }
    OUT_FILE.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {count} audit rows (chain verified {verified}/{count}) -> {OUT_FILE}")


if __name__ == "__main__":
    main()
