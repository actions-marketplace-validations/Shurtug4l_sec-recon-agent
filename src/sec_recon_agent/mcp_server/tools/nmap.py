"""Nmap XML parser.

Pure sync parser, no I/O. Uses defusedxml to refuse XXE / DTD / external
entity expansion. Untrusted scan XML often comes from third parties, so
the parser is deliberately conservative.
"""

# defusedxml does not re-export the Element class on every Python version
# (3.13 lost the re-export; 3.14 may still have it). Use the stdlib type
# for type hints, it is the actual runtime class returned by
# defusedxml's fromstring(), defusedxml only swaps the parser.
from typing import Annotated
from xml.etree.ElementTree import Element as XmlElement

import structlog
from defusedxml import ElementTree as ET  # noqa: N817  # ET is the conventional alias
from defusedxml.common import DefusedXmlException
from pydantic import Field

from sec_recon_agent.mcp_server.effects import declared_tool
from sec_recon_agent.mcp_server.errors import MalformedNmapXmlError
from sec_recon_agent.mcp_server.models import (
    NMAP_BANNER_CHARS,
    NMAP_HOSTNAME_CHARS,
    NMAP_HOSTNAMES_MAX,
    NMAP_NAME_CHARS,
    NmapHost,
    NmapPort,
    NmapScanResult,
)
from sec_recon_agent.mcp_server.security import fence_untrusted
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

# Hard cap on the raw XML payload. Real Nmap scans rarely exceed a few MB;
# 20MB leaves headroom for very large enterprise scans while preventing a
# crafted multi-GB document from being parsed in-process. Pydantic enforces
# the cap on the tool boundary before any XML touches defusedxml.
_NMAP_XML_MAX_BYTES = 20_000_000

# Cap on the number of <host> children processed per scan. Independent
# from the per-host caps already enforced inside `_parse_host` (hostnames
# 50, ports 200). Bounds the total returned payload regardless of input
# shape: 1000 hosts * 200 ports = 200k port entries upper bound.
_NMAP_HOST_CAP = 1000

NmapXmlStr = Annotated[str, Field(max_length=_NMAP_XML_MAX_BYTES)]


def _parse_port(port_el: XmlElement) -> NmapPort | None:
    portid_raw = port_el.get("portid")
    protocol = port_el.get("protocol")
    if portid_raw is None or protocol is None:
        return None
    try:
        portid = int(portid_raw)
    except ValueError:
        return None

    state_el = port_el.find("state")
    state = state_el.get("state", "unknown") if state_el is not None else "unknown"

    service_el = port_el.find("service")
    service = service_el.get("name") if service_el is not None else None
    product = service_el.get("product") if service_el is not None else None
    version = service_el.get("version") if service_el is not None else None

    # Every attribute is attacker-controlled: the scan XML is caller input.
    # Names are truncated to short identifiers; banners are fenced free text
    # with their own budget (truncated after marker neutralization).
    return NmapPort(
        portid=portid,
        protocol=protocol[:NMAP_NAME_CHARS],
        state=state[:NMAP_NAME_CHARS],
        service=service[:NMAP_NAME_CHARS] if service is not None else None,
        product=fence_untrusted(product, max_chars=NMAP_BANNER_CHARS),
        version=fence_untrusted(version, max_chars=NMAP_BANNER_CHARS),
    )


def _parse_host(host_el: XmlElement) -> NmapHost | None:
    ip: str | None = None
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") in ("ipv4", "ipv6"):
            candidate = addr_el.get("addr")
            if candidate:
                ip = candidate
                break
    if not ip:
        return None

    # Cap hostnames and ports per host: a crafted Nmap XML with thousands
    # of <hostname> or <port> children should not be able to inflate the
    # returned payload arbitrarily.
    hostnames = [
        name[:NMAP_HOSTNAME_CHARS]
        for hn in host_el.findall(".//hostname")
        if (name := hn.get("name"))
    ][:NMAP_HOSTNAMES_MAX]
    ports: list[NmapPort] = []
    for port_el in host_el.findall(".//port")[:200]:
        parsed = _parse_port(port_el)
        if parsed is not None:
            ports.append(parsed)

    return NmapHost(ip=ip[:NMAP_NAME_CHARS], hostnames=hostnames, ports=ports)


@declared_tool()
def nmap_parse_xml(xml_content: NmapXmlStr) -> NmapScanResult:
    """Parse Nmap XML output into a typed scan result.

    XML is parsed with defusedxml: DTDs, external entities, and entity
    expansion are refused, so untrusted scan output cannot trigger XXE.
    Input is capped at 20MB and at most 1000 <host> elements are processed
    per scan to bound the returned payload.
    """
    with _tracer.start_as_current_span("tool.nmap_parse_xml") as span:
        span.set_attribute("tool.name", "nmap_parse_xml")
        span.set_attribute("xml.size_bytes", len(xml_content))
        # Belt-and-suspenders: the Annotated[Field(max_length=...)] on the
        # parameter is enforced by the MCP layer, but direct callers
        # (tests, internal helpers) bypass that path, so the cap is also
        # checked here before any XML hits defusedxml.
        if len(xml_content) > _NMAP_XML_MAX_BYTES:
            span.set_attribute("tool.success", False)
            raise MalformedNmapXmlError(
                f"Nmap XML payload too large: {len(xml_content)} bytes > "
                f"{_NMAP_XML_MAX_BYTES} byte cap",
            )
        try:
            # forbid_dtd=True is tighter than defusedxml's default (which
            # only blocks entity expansion and external fetches but allows
            # DTD declarations). Real Nmap XML output has no DTD.
            root = ET.fromstring(xml_content, forbid_dtd=True)
        except (ET.ParseError, DefusedXmlException) as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise MalformedNmapXmlError(f"Nmap XML parse failed: {exc}") from exc

        if root.tag != "nmaprun":
            span.set_attribute("tool.success", False)
            raise MalformedNmapXmlError(
                f"Expected root element 'nmaprun', got '{root.tag}'",
            )

        scan_start = root.get("start")
        host_elements = root.findall("host")
        hosts_truncated = len(host_elements) > _NMAP_HOST_CAP
        hosts = [
            parsed for host_el in host_elements[:_NMAP_HOST_CAP] if (parsed := _parse_host(host_el))
        ]

        span.set_attribute("tool.success", True)
        span.set_attribute("hosts.count", len(hosts))
        span.set_attribute("hosts.count_raw", len(host_elements))
        span.set_attribute("hosts.truncated", hosts_truncated)
        span.set_attribute("ports.count_total", sum(len(h.ports) for h in hosts))
        log.info(
            "nmap_parse_done",
            hosts=len(hosts),
            hosts_raw=len(host_elements),
            truncated=hosts_truncated,
            ports=sum(len(h.ports) for h in hosts),
        )
        return NmapScanResult(scan_start=scan_start, hosts=hosts)
