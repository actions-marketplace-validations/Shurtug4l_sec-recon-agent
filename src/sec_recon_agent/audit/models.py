"""Pydantic models + hash-chain helpers for the audit trail."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

# Sentinel used when there is no predecessor (genesis row).
GENESIS_HASH = "0" * 64


# Fields introduced after schema_version 1, keyed by the version that added
# them. `_canonical_payload` drops fields newer than a row's own
# schema_version when (re)computing its hash, so a v1 chain stays valid after
# the code learns about v2 fields. See _canonical_payload for the rationale.
_FIELD_MIN_VERSION: dict[str, int] = {
    "ssvc_decision": 2,
    "grounding_status": 3,
}


class TriageEvent(BaseModel):
    """One row of the append-only triage audit log.

    Field SET matters for the hash (`_canonical_payload` serializes with
    sorted keys, so declaration order is cosmetic, but adding or removing a
    field changes the signed byte payload). Evolve the schema additively:
    bump `schema_version`, register the new field in `_FIELD_MIN_VERSION`,
    and add the column via an additive migration in the store. Never remove
    or repurpose an existing field.
    """

    schema_version: int = 3

    # Identity / timing ----------------------------------------------------
    event_id: str = Field(min_length=4, max_length=64)
    ts: str  # ISO 8601 UTC, e.g. 2026-05-18T13:55:11.123456+00:00

    # Query side -----------------------------------------------------------
    query_sha256: str = Field(min_length=64, max_length=64)
    query_length: int = Field(ge=0)
    query_plain: str | None = None  # opt-in via AUDIT_INCLUDE_QUERY

    # Report aggregate signals (no free text) ------------------------------
    report_sha256: str = Field(min_length=64, max_length=64)
    severity: str | None = None
    confidence: str | None = None
    cves_count: int = Field(default=0, ge=0)
    attack_techniques_count: int = Field(default=0, ge=0)
    kev_hits: int = Field(default=0, ge=0)
    ransomware_hits: int = Field(default=0, ge=0)
    high_epss_hits: int = Field(default=0, ge=0)
    # SSVC prioritization verdict (Act / Attend / Track* / Track), stamped
    # deterministically onto the report before hashing. schema_version 2+.
    ssvc_decision: str | None = None
    # Grounding verification outcome (grounded / suspect / not_evaluated),
    # stamped deterministically onto the report before hashing. schema_version 3+.
    grounding_status: str | None = None
    report_summary_plain: str | None = None  # opt-in via AUDIT_INCLUDE_SUMMARY

    # Execution context ----------------------------------------------------
    model: str
    duration_ms: int = Field(ge=0)
    outcome: str  # "success" | "error" | "cancelled" (client gone) | "incomplete"
    error_class: str | None = None  # only when outcome != "success"

    # Chain ---------------------------------------------------------------
    prev_event_hash: str = Field(min_length=64, max_length=64)
    this_event_hash: str = Field(default="", max_length=64)


def utcnow_iso() -> str:
    """Return an ISO 8601 UTC timestamp with microsecond precision."""
    return datetime.now(UTC).isoformat(timespec="microseconds")


def sha256_hex(payload: str | bytes) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_payload(event: TriageEvent) -> str:
    """Build the deterministic byte payload that this_event_hash signs.

    Excludes `this_event_hash` itself (we are computing it) and uses JSON
    with sorted keys + compact separators for byte-stability across Python
    versions and platforms.

    Version-aware by design: fields introduced in a later schema_version are
    dropped when hashing a row of an earlier version, so a chain written under
    schema_version 1 still verifies after the code has learned about v2 fields.
    Without this, loading an old row would populate the new field with its
    default and the recomputed hash would diverge from the stored one, raising
    a false tamper alarm.
    """
    data = event.model_dump(exclude={"this_event_hash"})
    version = event.schema_version
    data = {k: v for k, v in data.items() if _FIELD_MIN_VERSION.get(k, 1) <= version}
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_event_hash(event: TriageEvent) -> str:
    return sha256_hex(_canonical_payload(event))


def seal_event(event: TriageEvent) -> TriageEvent:
    """Return a copy of `event` with `this_event_hash` populated."""
    digest = compute_event_hash(event)
    return event.model_copy(update={"this_event_hash": digest})


def verify_link(prev: TriageEvent | None, current: TriageEvent) -> tuple[bool, str | None]:
    """Verify a single link in the hash chain.

    Returns (ok, reason_if_broken).
    """
    expected_prev_hash = prev.this_event_hash if prev is not None else GENESIS_HASH
    if current.prev_event_hash != expected_prev_hash:
        return False, (
            f"prev_event_hash mismatch: expected {expected_prev_hash[:16]}..., "
            f"got {current.prev_event_hash[:16]}..."
        )
    recomputed = compute_event_hash(current)
    if recomputed != current.this_event_hash:
        return False, (
            f"this_event_hash mismatch: stored={current.this_event_hash[:16]}..., "
            f"recomputed={recomputed[:16]}..."
        )
    return True, None


def summarize_for_audit(report_dict: dict[str, Any]) -> dict[str, int | str | None]:
    """Extract aggregate counts from a TriageReport-shaped dict.

    Defensive: returns zero counts when fields are missing or malformed
    rather than raising — audit logging is best-effort.
    """
    cves = report_dict.get("cves") or []
    cves = [c for c in cves if isinstance(c, dict)]
    techniques = report_dict.get("attack_techniques") or []
    techniques = [t for t in techniques if isinstance(t, dict)]
    kev_hits = sum(1 for c in cves if c.get("in_kev_catalog") is True)
    ransomware_hits = sum(1 for c in cves if c.get("known_ransomware_use") is True)
    high_epss_hits = sum(
        1
        for c in cves
        if isinstance(c.get("epss_probability"), int | float)
        and c.get("epss_probability") is not None
        and float(c["epss_probability"]) >= 0.5
    )
    severity_val = report_dict.get("severity")
    confidence_val = report_dict.get("confidence")
    ssvc = report_dict.get("ssvc")
    ssvc_decision = None
    if isinstance(ssvc, dict):
        decision_val = ssvc.get("decision")
        ssvc_decision = decision_val if isinstance(decision_val, str) else None
    grounding = report_dict.get("grounding")
    grounding_status = None
    if isinstance(grounding, dict):
        status_val = grounding.get("status")
        grounding_status = status_val if isinstance(status_val, str) else None
    return {
        "severity": severity_val if isinstance(severity_val, str) else None,
        "confidence": confidence_val if isinstance(confidence_val, str) else None,
        "cves_count": len(cves),
        "attack_techniques_count": len(techniques),
        "kev_hits": kev_hits,
        "ransomware_hits": ransomware_hits,
        "high_epss_hits": high_epss_hits,
        "ssvc_decision": ssvc_decision,
        "grounding_status": grounding_status,
    }
