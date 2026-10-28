"""CISA Known Exploited Vulnerabilities (KEV) catalog lookup.

CISA publishes a JSON catalog of CVEs that are known to be actively
exploited in the wild. Federal civilian agencies are bound by BOD 22-01
to remediate listed CVEs by a per-entry due date. For the agent this is
the strongest "patch now" operational signal available.

The catalog is fetched once per process, cached on disk for 24h, and
parsed into an in-memory CVE -> entry map. Same hardening pattern as
ExploitDB: host-locked redirects, hard size cap, typed errors.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.effects import declared_tool
from sec_recon_agent.mcp_server.errors import (
    KevDownloadError,
    MalformedKevPayloadError,
)
from sec_recon_agent.mcp_server.models import (
    KEV_NOTES_CHARS,
    KEV_REQUIRED_ACTION_CHARS,
    KEV_VULNERABILITY_NAME_CHARS,
    CveIdStr,
    KevCheck,
)
from sec_recon_agent.mcp_server.security import fence_untrusted
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_TRUSTED_HOST = "cisa.gov"
KEV_CACHE_FILENAME = "cisa_kev_catalog.json"
KEV_CACHE_MAX_AGE_SECONDS = 24 * 3600
KEV_FETCH_TIMEOUT_SECONDS = 60.0
# Current catalog is ~2 MB; cap well above to absorb growth and below the
# point where a hostile payload could exhaust memory.
KEV_MAX_BYTES = 50 * 1024 * 1024

_kev_index: dict[str, dict[str, Any]] | None = None
_kev_init_lock = asyncio.Lock()


def _cache_path() -> Path:
    return settings.chroma_persist_dir.parent / KEV_CACHE_FILENAME


def _is_cache_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < KEV_CACHE_MAX_AGE_SECONDS


async def _download_kev_catalog(path: Path) -> None:
    log.info("kev_catalog_download_start", url=KEV_CATALOG_URL)
    buffer = bytearray()
    try:
        async with httpx.AsyncClient(timeout=KEV_FETCH_TIMEOUT_SECONDS) as client:
            async with client.stream(
                "GET",
                KEV_CATALOG_URL,
                follow_redirects=True,
            ) as resp:
                final_host = resp.url.host or ""
                is_trusted = final_host == KEV_TRUSTED_HOST or final_host.endswith(
                    "." + KEV_TRUSTED_HOST,
                )
                if not is_trusted:
                    raise KevDownloadError(
                        f"KEV catalog redirect landed on unexpected host: {final_host}",
                    )
                if resp.status_code != 200:
                    raise KevDownloadError(
                        f"KEV catalog download returned HTTP {resp.status_code}",
                    )
                async for chunk in resp.aiter_bytes(8192):
                    buffer.extend(chunk)
                    if len(buffer) > KEV_MAX_BYTES:
                        raise KevDownloadError(
                            f"KEV catalog exceeded {KEV_MAX_BYTES} byte limit",
                        )
    except httpx.TransportError as exc:
        raise KevDownloadError(f"Transport error fetching KEV catalog: {exc}") from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    # The catalog is 5-20 MB: hand the write to a thread so the event loop
    # keeps serving other tool calls during a refresh.
    await asyncio.to_thread(path.write_bytes, bytes(buffer))
    log.info("kev_catalog_download_done", bytes=len(buffer), path=str(path))


def _parse_catalog_into_index(path: Path) -> dict[str, dict[str, Any]]:
    """Build a cveID -> entry map from the CISA KEV JSON catalog."""
    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise MalformedKevPayloadError(f"Failed to parse KEV JSON: {exc}") from exc

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise MalformedKevPayloadError(
            "KEV payload missing top-level 'vulnerabilities' list",
        )

    index: dict[str, dict[str, Any]] = {}
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cveID")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            index[cve_id] = entry
    return index


async def _ensure_kev_index() -> dict[str, dict[str, Any]]:
    global _kev_index
    if _kev_index is not None:
        return _kev_index
    async with _kev_init_lock:
        if _kev_index is not None:
            return _kev_index
        path = _cache_path()
        if not _is_cache_fresh(path):
            await _download_kev_catalog(path)
        _kev_index = _parse_catalog_into_index(path)
        log.info("kev_index_loaded", catalog_size=len(_kev_index))
        return _kev_index


def _reset_kev_index() -> None:
    """Test-only: drop the in-memory index cache."""
    global _kev_index
    _kev_index = None


def _coerce_str(value: Any, max_len: int) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return stripped[:max_len]


def _coerce_ransomware_flag(value: Any) -> bool | None:
    """CISA encodes this as one of: 'Known', 'Unknown', missing."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized == "known":
        return True
    if normalized == "unknown":
        return False
    return None


@declared_tool()
async def kev_check(cve_id: CveIdStr) -> KevCheck:
    """Check whether a CVE is on the CISA Known Exploited Vulnerabilities catalog.

    Returns KevCheck with `in_catalog=True` and CISA-provided metadata
    (vendor, product, due date, required action, ransomware association)
    when the CVE is listed. Returns `in_catalog=False` with metadata
    fields unset otherwise. KEV membership is the single most actionable
    "patch now" signal in vulnerability management.
    """
    with _tracer.start_as_current_span("tool.kev_check") as span:
        span.set_attribute("tool.name", "kev_check")
        span.set_attribute("cve.id", cve_id)
        log.info("kev_check_start", cve_id=cve_id)

        try:
            index = await _ensure_kev_index()
        except Exception as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise

        entry = index.get(cve_id)
        if entry is None:
            result = KevCheck(cve_id=cve_id, in_catalog=False)
            span.set_attribute("tool.success", True)
            span.set_attribute("kev.in_catalog", False)
            log.info("kev_check_done", cve_id=cve_id, in_catalog=False)
            return result

        # vendor_project / product / *_date are short structured identifiers;
        # vulnerability_name / required_action / notes are free-text fields
        # authored upstream by vendors and researchers. Fence the free-text
        # set so any instruction-like content reaches the LLM inside the
        # untrusted-content boundary (same pattern as cve_lookup with NVD
        # descriptions).
        result = KevCheck(
            cve_id=cve_id,
            in_catalog=True,
            vendor_project=_coerce_str(entry.get("vendorProject"), 200),
            product=_coerce_str(entry.get("product"), 200),
            vulnerability_name=fence_untrusted(
                _coerce_str(entry.get("vulnerabilityName"), KEV_VULNERABILITY_NAME_CHARS),
                max_chars=KEV_VULNERABILITY_NAME_CHARS,
            ),
            date_added=_coerce_str(entry.get("dateAdded"), 32),
            due_date=_coerce_str(entry.get("dueDate"), 32),
            required_action=fence_untrusted(
                _coerce_str(entry.get("requiredAction"), KEV_REQUIRED_ACTION_CHARS),
                max_chars=KEV_REQUIRED_ACTION_CHARS,
            ),
            known_ransomware_use=_coerce_ransomware_flag(entry.get("knownRansomwareCampaignUse")),
            notes=fence_untrusted(
                _coerce_str(entry.get("notes"), KEV_NOTES_CHARS), max_chars=KEV_NOTES_CHARS
            ),
        )
        span.set_attribute("tool.success", True)
        span.set_attribute("kev.in_catalog", True)
        span.set_attribute("kev.known_ransomware", bool(result.known_ransomware_use))
        log.info("kev_check_done", cve_id=cve_id, in_catalog=True)
        return result
