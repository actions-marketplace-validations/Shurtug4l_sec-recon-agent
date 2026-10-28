"""Contract tests for the nmap_parse_xml MCP tool. Pure sync; no HTTP."""

import pytest

from sec_recon_agent.mcp_server.errors import MalformedNmapXmlError
from sec_recon_agent.mcp_server.security import UNTRUSTED_END, UNTRUSTED_START
from sec_recon_agent.mcp_server.tools.nmap import nmap_parse_xml

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun start="1730000000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
    <hostnames>
      <hostname name="target.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_extracts_host_and_ports() -> None:
    result = nmap_parse_xml(SAMPLE_NMAP_XML)

    assert result.scan_start == "1730000000"
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "10.0.0.5"
    assert host.hostnames == ["target.local"]
    assert len(host.ports) == 3

    apache = next(p for p in host.ports if p.portid == 80)
    assert apache.protocol == "tcp"
    assert apache.state == "open"
    assert apache.service == "http"
    # product and version are free-text vendor banners; they must be fenced
    # with untrusted-content markers before reaching the agent
    assert apache.product is not None
    assert apache.version is not None
    assert apache.product.startswith(UNTRUSTED_START)
    assert apache.product.endswith(UNTRUSTED_END)
    assert "Apache httpd" in apache.product
    assert "2.4.49" in apache.version

    closed = next(p for p in host.ports if p.portid == 443)
    assert closed.state == "closed"
    assert closed.service is None


def test_parse_raises_on_invalid_xml() -> None:
    with pytest.raises(MalformedNmapXmlError):
        nmap_parse_xml("not valid xml")


def test_parse_raises_on_wrong_root_element() -> None:
    with pytest.raises(MalformedNmapXmlError):
        nmap_parse_xml("<otherroot><host/></otherroot>")


def test_parse_blocks_xxe_external_entity() -> None:
    """XXE attempt should be refused by defusedxml, not parsed."""
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun start="0">
  <host>
    <address addr="&xxe;" addrtype="ipv4"/>
  </host>
</nmaprun>"""

    with pytest.raises(MalformedNmapXmlError):
        nmap_parse_xml(xxe_payload)


def test_parse_skips_host_without_ip() -> None:
    xml = """<?xml version="1.0"?>
<nmaprun start="0">
  <host>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
  </host>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>"""

    result = nmap_parse_xml(xml)
    assert len(result.hosts) == 1
    assert result.hosts[0].ip == "10.0.0.1"


def test_parse_rejects_oversized_payload() -> None:
    """Inputs above the 20MB cap must be refused before defusedxml runs."""
    from sec_recon_agent.mcp_server.tools.nmap import _NMAP_XML_MAX_BYTES

    oversized = "<nmaprun>" + ("a" * (_NMAP_XML_MAX_BYTES + 1)) + "</nmaprun>"
    with pytest.raises(MalformedNmapXmlError, match="too large"):
        nmap_parse_xml(oversized)


def test_parse_caps_host_count() -> None:
    """At most _NMAP_HOST_CAP <host> elements are processed, regardless of input size."""
    from sec_recon_agent.mcp_server.tools.nmap import _NMAP_HOST_CAP

    host_template = (
        '<host><status state="up"/><address addr="10.{octet}.0.1" addrtype="ipv4"/></host>'
    )
    # Build _NMAP_HOST_CAP + 50 distinct hosts so the cap kicks in.
    bodies = "".join(host_template.format(octet=i % 256) for i in range(_NMAP_HOST_CAP + 50))
    xml = f'<?xml version="1.0"?><nmaprun start="0">{bodies}</nmaprun>'

    result = nmap_parse_xml(xml)
    assert len(result.hosts) == _NMAP_HOST_CAP


def test_every_attacker_controlled_string_is_capped() -> None:
    """The scan XML is caller input. A 20 MB document may carry 100 KB
    attributes; none of them may reach the model uncapped, and the banners
    are fenced with their own budget."""
    from sec_recon_agent.mcp_server.models import (
        NMAP_BANNER_CHARS,
        NMAP_HOSTNAME_CHARS,
        NMAP_NAME_CHARS,
    )
    from sec_recon_agent.mcp_server.security import FENCE_OVERHEAD

    huge = "A" * 5000
    xml = f"""<?xml version="1.0"?>
<nmaprun start="1730000000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="{huge}" addrtype="ipv4"/>
    <hostnames><hostname name="{huge}" type="user"/></hostnames>
    <ports>
      <port protocol="{huge}" portid="80">
        <state state="{huge}" reason="syn-ack"/>
        <service name="{huge}" product="{huge}" version="{huge}"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    result = nmap_parse_xml(xml)
    host = result.hosts[0]
    port = host.ports[0]
    assert len(host.ip) == NMAP_NAME_CHARS
    assert len(host.hostnames[0]) == NMAP_HOSTNAME_CHARS
    assert len(port.protocol) == NMAP_NAME_CHARS
    assert len(port.state) == NMAP_NAME_CHARS
    assert port.service is not None and len(port.service) == NMAP_NAME_CHARS
    assert port.product is not None and len(port.product) == NMAP_BANNER_CHARS + FENCE_OVERHEAD
    assert port.version is not None and len(port.version) == NMAP_BANNER_CHARS + FENCE_OVERHEAD
    assert port.product.startswith(UNTRUSTED_START) and port.product.endswith(UNTRUSTED_END)
