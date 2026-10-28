"""Patch availability lookup.

Extracts fixed-version information directly from the NVD CVE 2.0 record
without introducing a new external dependency. NVD encodes the affected
range as a list of `cpeMatch` entries with optional `versionEndExcluding`
(the smallest version where the fix landed) and `versionEndIncluding`
(the largest version still affected). This tool projects that onto a
typed `PatchAvailability` shape so the agent can answer "is a fix out
yet, and which version do I move to".

Why not OSV.dev: OSV indexes by its own IDs and by package, not by raw
CVE; bridging requires a separate `vulns?q=` query path that landed
relatively late in the OSV API surface. NVD already covers the common
case where the vendor published a fixed version, and the agent already
hits NVD via the shared rate-limited client, so we stay on one source.
"""

from typing import Any

import httpx
import structlog

from sec_recon_agent.mcp_server.effects import declared_tool
from sec_recon_agent.mcp_server.errors import (
    CveNotFoundError,
    MalformedNvdPayloadError,
)
from sec_recon_agent.mcp_server.models import (
    CveIdStr,
    PatchAvailability,
    PatchEntry,
)
from sec_recon_agent.mcp_server.nvd_client import HTTP_TIMEOUT_SECONDS, nvd_get
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

MAX_PATCH_ENTRIES_RETURNED = 50
MAX_REFERENCES_RETURNED = 20


def _extract_patch_entries(cve: dict[str, Any]) -> list[PatchEntry]:
    """Walk NVD configurations -> nodes -> cpeMatch and emit one
    PatchEntry per match that carries an end-excluding version.

    `versionEndExcluding` is the small-print fix marker in NVD:
    "affected: < X". So `X` is the smallest fixed version.
    """
    entries: list[PatchEntry] = []
    seen: set[tuple[str, str]] = set()
    for config in cve.get("configurations", []) or []:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []) or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []) or []:
                if not isinstance(match, dict):
                    continue
                cpe = match.get("criteria")
                fixed = match.get("versionEndExcluding")
                if not isinstance(cpe, str) or not isinstance(fixed, str):
                    continue
                fixed = fixed.strip()
                if not fixed:
                    continue
                key = (cpe[:400], fixed[:100])
                if key in seen:
                    continue
                seen.add(key)
                start: str | None = None
                start_inc = match.get("versionStartIncluding")
                start_exc = match.get("versionStartExcluding")
                if isinstance(start_inc, str) and start_inc.strip():
                    start = start_inc.strip()[:100]
                elif isinstance(start_exc, str) and start_exc.strip():
                    start = start_exc.strip()[:100]
                entries.append(
                    PatchEntry(
                        product_cpe=cpe[:400],
                        fixed_in_version=fixed[:100],
                        version_range_start=start,
                    ),
                )
                if len(entries) >= MAX_PATCH_ENTRIES_RETURNED:
                    return entries
    return entries


def _extract_references(cve: dict[str, Any]) -> list[str]:
    """Return advisory URLs the NVD record lists. Caller binds them to
    HttpUrl via the Pydantic model."""
    refs: list[str] = []
    seen: set[str] = set()
    for ref in cve.get("references", []) or []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not isinstance(url, str):
            continue
        if url in seen:
            continue
        seen.add(url)
        refs.append(url)
        if len(refs) >= MAX_REFERENCES_RETURNED:
            break
    return refs


@declared_tool()
async def patch_lookup(cve_id: CveIdStr) -> PatchAvailability:
    """Return the list of fixed versions for a CVE as declared by NVD.

    `has_fix` is True when at least one CPE-match entry has a
    `versionEndExcluding` value (the smallest patched version). When
    NVD has no CPE configuration for the CVE the result is
    `has_fix=False` with empty `fixed_entries`. The references list
    carries the upstream advisory URLs from the same NVD record.

    The `references` field of the result contains UNTRUSTED vendor URLs:
    do not auto-fetch them server-side. They are an analyst audit trail.
    """
    with _tracer.start_as_current_span("tool.patch_lookup") as span:
        span.set_attribute("tool.name", "patch_lookup")
        span.set_attribute("cve.id", cve_id)
        log.info("patch_lookup_start", cve_id=cve_id)

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                payload = await nvd_get(client, params={"cveId": cve_id})
        except Exception as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise

        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            raise CveNotFoundError(cve_id)
        cve = vulns[0].get("cve")
        if not isinstance(cve, dict):
            raise MalformedNvdPayloadError(f"NVD payload missing 'cve' object for {cve_id}")

        entries = _extract_patch_entries(cve)
        refs = _extract_references(cve)
        has_fix = bool(entries)

        result = PatchAvailability(
            cve_id=cve_id,
            has_fix=has_fix,
            fixed_entries=entries,
            references=refs,
        )
        span.set_attribute("tool.success", True)
        span.set_attribute("patch.has_fix", has_fix)
        span.set_attribute("patch.entries_count", len(entries))
        log.info(
            "patch_lookup_done",
            cve_id=cve_id,
            has_fix=has_fix,
            entries=len(entries),
        )
        return result
