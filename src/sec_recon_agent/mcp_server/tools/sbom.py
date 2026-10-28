"""SBOM ingestion: normalize CycloneDX / SPDX / requirements.txt into a
typed component list.

Deterministic, no network. The downstream agent uses the component list
to fan out per-component CVE searches via the existing tools — keeping
that fan-out in the agent loop (and not inside this tool) preserves the
single responsibility of each tool and lets the user see each
component's triage in `reasoning_chain`.

Supported formats and the fields we extract:
- CycloneDX 1.x JSON  -> bom.components[].{name, version, purl}
- SPDX 2.x JSON       -> packages[].{name, versionInfo, externalRefs purl}
- requirements.txt    -> line per package, `name==version` or `name>=version`

Anything more exotic (CycloneDX XML, SPDX tag-value, lockfiles) raises
UnsupportedSbomFormatError. The caller can convert and retry.
"""

import json
import re
from typing import Annotated, Any

import structlog
from pydantic import Field

from sec_recon_agent.mcp_server.effects import declared_tool
from sec_recon_agent.mcp_server.errors import (
    MalformedSbomPayloadError,
    UnsupportedSbomFormatError,
)
from sec_recon_agent.mcp_server.models import (
    SbomComponent,
    SbomComponentList,
)
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

SBOM_MAX_CONTENT_BYTES = 5 * 1024 * 1024  # 5 MB
SBOM_MAX_COMPONENTS = 500
# Heuristic regex for a requirements.txt line. Intentionally strict: a
# stray free-text line should not become a phantom component.
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?"  # optional extras
    r"\s*(?:(==|>=|<=|>|<|~=|!=)\s*([A-Za-z0-9][A-Za-z0-9._+\-]*))?"
    r"\s*(?:;.*)?$",
)
_PURL_ECOSYSTEM = re.compile(r"^pkg:([a-z]+)/")
# purl type (https://github.com/package-url/purl-spec) -> OSV ecosystem
# spelling (https://ossf.github.io/osv-schema/#affectedpackage-field). The two
# vocabularies diverge (purl is lowercase, OSV is cased), so a raw purl type
# fed to osv_lookup would be rejected by its OsvEcosystem Literal for six of the
# seven ecosystems we support. Map here so ecosystem is OSV-query-ready.
_PURL_TYPE_TO_OSV = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "maven": "Maven",
}


def _detect_format(content: str) -> str:
    """Return 'cyclonedx', 'spdx', 'requirements', or raise."""
    stripped = content.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise MalformedSbomPayloadError(f"JSON-shaped SBOM failed to parse: {exc}") from exc
        if not isinstance(payload, dict):
            raise UnsupportedSbomFormatError("SBOM root must be a JSON object")
        if "bomFormat" in payload or "components" in payload:
            return "cyclonedx"
        if "spdxVersion" in payload or "packages" in payload:
            return "spdx"
        raise UnsupportedSbomFormatError(
            "JSON SBOM did not match CycloneDX or SPDX shape",
        )
    # Not JSON: try requirements.txt heuristic. We require >= 1 line to
    # match the regex; pure prose blobs are rejected.
    lines = [ln for ln in stripped.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        raise UnsupportedSbomFormatError("empty SBOM payload")
    if any(_REQ_LINE.match(ln) for ln in lines[:50]):
        return "requirements"
    raise UnsupportedSbomFormatError(
        "non-JSON SBOM did not match requirements.txt heuristic",
    )


def _ecosystem_from_purl(purl: str | None) -> str | None:
    """Return the OSV ecosystem spelling for a purl, or None.

    For the seven ecosystems osv_lookup supports, this yields the exact OSV
    Literal value so the hint can be passed straight to osv_lookup. For any
    other purl type we return the raw lowercase type (still a useful hint, but
    not an osv_lookup ecosystem).
    """
    if not purl:
        return None
    m = _PURL_ECOSYSTEM.match(purl)
    if not m:
        return None
    purl_type = m.group(1)
    return _PURL_TYPE_TO_OSV.get(purl_type, purl_type)


def _parse_cyclonedx(payload: dict[str, Any]) -> list[SbomComponent]:
    raw = payload.get("components") or []
    if not isinstance(raw, list):
        raise MalformedSbomPayloadError("CycloneDX 'components' must be a list")
    out: list[SbomComponent] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        version = entry.get("version") if isinstance(entry.get("version"), str) else None
        purl = entry.get("purl") if isinstance(entry.get("purl"), str) else None
        out.append(
            SbomComponent(
                name=name.strip()[:200],
                version=((version.strip()[:100] or None) if version else None),
                ecosystem=_ecosystem_from_purl(purl),
                purl=(purl[:500] if purl else None),
            ),
        )
    return out


def _parse_spdx(payload: dict[str, Any]) -> list[SbomComponent]:
    raw = payload.get("packages") or []
    if not isinstance(raw, list):
        raise MalformedSbomPayloadError("SPDX 'packages' must be a list")
    out: list[SbomComponent] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        version = entry.get("versionInfo") if isinstance(entry.get("versionInfo"), str) else None
        purl: str | None = None
        for ref in entry.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            if ref.get("referenceType") == "purl" and isinstance(ref.get("referenceLocator"), str):
                purl = ref["referenceLocator"]
                break
        out.append(
            SbomComponent(
                name=name.strip()[:200],
                version=((version.strip()[:100] or None) if version else None),
                ecosystem=_ecosystem_from_purl(purl),
                purl=(purl[:500] if purl else None),
            ),
        )
    return out


def _parse_requirements(content: str) -> list[SbomComponent]:
    out: list[SbomComponent] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _REQ_LINE.match(stripped)
        if not m:
            continue
        name = m.group(1)
        version = m.group(3)
        out.append(
            SbomComponent(
                name=name[:200],
                version=(version[:100] if version else None),
                ecosystem="PyPI",
                purl=None,
            ),
        )
    return out


def _dedupe(components: list[SbomComponent]) -> list[SbomComponent]:
    """Drop exact duplicates while preserving input order."""
    seen: set[tuple[str, str | None, str | None]] = set()
    out: list[SbomComponent] = []
    for c in components:
        key = (c.name.lower(), c.version, c.ecosystem)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


@declared_tool()
def sbom_ingest(
    content: Annotated[
        str,
        Field(min_length=1, max_length=SBOM_MAX_CONTENT_BYTES),
    ],
) -> SbomComponentList:
    """Parse a CycloneDX / SPDX / requirements.txt SBOM into a typed,
    deduplicated component list.

    Format is autodetected from the payload shape. Returns at most
    SBOM_MAX_COMPONENTS components; `truncated=True` signals that the
    source had more.
    """
    with _tracer.start_as_current_span("tool.sbom_ingest") as span:
        span.set_attribute("tool.name", "sbom_ingest")
        span.set_attribute("sbom.content_length", len(content))
        log.info("sbom_ingest_start", content_length=len(content))

        try:
            fmt = _detect_format(content)
            if fmt == "cyclonedx":
                payload = json.loads(content)
                components = _parse_cyclonedx(payload)
            elif fmt == "spdx":
                payload = json.loads(content)
                components = _parse_spdx(payload)
            elif fmt == "requirements":
                components = _parse_requirements(content)
            else:  # pragma: no cover -- _detect_format raises on unknowns
                raise UnsupportedSbomFormatError(f"unhandled format: {fmt}")
        except Exception as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise

        deduped = _dedupe(components)
        truncated = len(deduped) > SBOM_MAX_COMPONENTS
        deduped = deduped[:SBOM_MAX_COMPONENTS]
        result = SbomComponentList(
            format=fmt,
            component_count=len(deduped),
            components=deduped,
            truncated=truncated,
        )
        span.set_attribute("tool.success", True)
        span.set_attribute("sbom.format", fmt)
        span.set_attribute("sbom.component_count", len(deduped))
        span.set_attribute("sbom.truncated", truncated)
        log.info(
            "sbom_ingest_done",
            format=fmt,
            count=len(deduped),
            truncated=truncated,
        )
        return result
