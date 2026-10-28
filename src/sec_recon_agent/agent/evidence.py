"""Typed index of the tool returns captured from one agent run.

Shared by the grounding verifier (agent/grounding.py) and the SSVC
authority (agent/ssvc.py). Both need the same question answered, "what did
the tools actually return for this CVE", and neither may take the model's
word for it: a verdict computed from the report's own fields is reproducible
but not independent of the model, which is exactly the property a prompt
injection would exploit. One index, built from the trajectory, feeds both
stamps so they can never disagree about the evidence.

Only STRUCTURED fields of SUCCESSFUL returns are indexed. Fenced free text
is untrusted upstream prose and never becomes evidence. A successful return
that does not parse back into its typed model is kept in `unparsed` so the
consumers can degrade to "cannot tell" instead of "not backed".

This module is pure and imports nothing from pydantic-ai at runtime: it
consumes the ToolInvocation records produced by agent/trajectory.py, which
is the single module coupled to the framework's message classes.
"""

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pydantic import TypeAdapter, ValidationError

from sec_recon_agent.mcp_server.models import (
    AttackTechnique,
    CVECandidate,
    CVEDetail,
    EpssScore,
    ExploitCheck,
    KevCheck,
    OsvScanResult,
    PatchAvailability,
)

if TYPE_CHECKING:
    from sec_recon_agent.agent.trajectory import ToolInvocation

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_LIST_ATTACK = TypeAdapter(list[AttackTechnique])
_LIST_CANDIDATES = TypeAdapter(list[CVECandidate])


@dataclass
class Evidence:
    """Parsed tool returns keyed by upper-cased CVE id, built once per run."""

    cve_details: dict[str, list[CVEDetail]] = field(default_factory=dict)
    kev: dict[str, list[KevCheck]] = field(default_factory=dict)
    epss: dict[str, list[EpssScore]] = field(default_factory=dict)
    exploits: dict[str, list[ExploitCheck]] = field(default_factory=dict)
    attack_ids: set[str] = field(default_factory=set)
    mentioned_cve_ids: set[str] = field(default_factory=set)
    unparsed: dict[str, list["ToolInvocation"]] = field(default_factory=dict)


def scan_cve_ids(value: object) -> set[str]:
    """CVE ids appearing anywhere in a JSON-dumpable structure, normalized."""
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return {match.upper() for match in _CVE_ID_RE.findall(text)}


def mentions_cve(invocation: "ToolInvocation", cve_id: str) -> bool:
    return cve_id in scan_cve_ids(invocation.args) or cve_id in scan_cve_ids(
        invocation.content,
    )


def build_evidence(invocations: Sequence["ToolInvocation"]) -> Evidence:
    """Index every successful return; keep the unparseable ones aside."""
    evidence = Evidence()
    for invocation in invocations:
        if invocation.outcome != "success":
            continue
        # Tool args are model-authored structured data: a queried CVE id
        # counts as a mention even when the tool's answer was empty.
        evidence.mentioned_cve_ids |= scan_cve_ids(invocation.args)
        try:
            _index_content(evidence, invocation)
        except (ValidationError, TypeError, ValueError):
            evidence.unparsed.setdefault(invocation.tool_name, []).append(invocation)
    return evidence


def _index_content(evidence: Evidence, invocation: "ToolInvocation") -> None:
    """Parse one successful return into the typed index. Raises on mismatch."""
    content = invocation.content
    tool = invocation.tool_name
    if tool == "cve_lookup":
        detail = CVEDetail.model_validate(content)
        evidence.cve_details.setdefault(detail.cve_id.upper(), []).append(detail)
        evidence.mentioned_cve_ids.add(detail.cve_id.upper())
    elif tool == "kev_check":
        kev = KevCheck.model_validate(content)
        evidence.kev.setdefault(kev.cve_id.upper(), []).append(kev)
        evidence.mentioned_cve_ids.add(kev.cve_id.upper())
    elif tool == "epss_score":
        epss = EpssScore.model_validate(content)
        evidence.epss.setdefault(epss.cve_id.upper(), []).append(epss)
        evidence.mentioned_cve_ids.add(epss.cve_id.upper())
    elif tool == "exploit_check":
        exploit = ExploitCheck.model_validate(content)
        evidence.exploits.setdefault(exploit.cve_id.upper(), []).append(exploit)
        evidence.mentioned_cve_ids.add(exploit.cve_id.upper())
    elif tool == "patch_lookup":
        patch = PatchAvailability.model_validate(content)
        evidence.mentioned_cve_ids.add(patch.cve_id.upper())
    elif tool == "osv_lookup":
        osv = OsvScanResult.model_validate(content)
        for vuln in osv.vulnerabilities:
            evidence.mentioned_cve_ids |= scan_cve_ids(vuln.id)
            evidence.mentioned_cve_ids |= scan_cve_ids(vuln.aliases)
    elif tool == "attack_mapping":
        techniques = _LIST_ATTACK.validate_python(content)
        evidence.attack_ids |= {technique.id for technique in techniques}
    elif tool == "cve_semantic_search":
        candidates = _LIST_CANDIDATES.validate_python(content)
        evidence.mentioned_cve_ids |= {c.cve_id.upper() for c in candidates}
    # nmap_parse_xml / sbom_ingest carry no report-claim evidence: skip.
