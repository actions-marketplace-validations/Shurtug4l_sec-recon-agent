"""Tests for the pure grounding verifier.

All trajectories are synthetic ToolInvocation lists: no pydantic-ai imports.
Each claim-matrix row gets at least one test per direction (supported /
mismatch / unbacked), plus the policy edges: honest defaults produce no
claims, unparseable evidence degrades to unverifiable, fabricated CVE ids
short-circuit, and garbage input never raises.
"""

from typing import Any

from sec_recon_agent.agent.grounding import (
    CVSS_SCORE_TOLERANCE,
    EPSS_TOLERANCE,
    MAX_FINDINGS,
    verify_grounding,
)
from sec_recon_agent.agent.schema import (
    Confidence,
    CVEReference,
    GroundingClaimStatus,
    GroundingStatus,
    Severity,
    TriageReport,
)
from sec_recon_agent.agent.trajectory import ToolInvocation
from sec_recon_agent.mcp_server.models import AttackTechnique

CVE = "CVE-2021-44228"


def _invocation(
    tool: str,
    content: object,
    args: dict[str, Any] | None = None,
    outcome: str = "success",
    call_id: str = "c1",
) -> ToolInvocation:
    return ToolInvocation(
        tool_name=tool,
        tool_call_id=call_id,
        args=args if args is not None else {"cve_id": CVE},
        content=content,
        outcome=outcome,  # type: ignore[arg-type]
    )


def _report(
    cve: CVEReference | None = None,
    techniques: list[AttackTechnique] | None = None,
) -> TriageReport:
    return TriageReport(
        summary="Test report.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommended_action="Patch.",
        cves=[cve] if cve is not None else [],
        attack_techniques=techniques or [],
    )


def _cve(**overrides: Any) -> CVEReference:
    base: dict[str, Any] = {
        "cve_id": CVE,
        "summary": "Log4Shell RCE.",
        "severity": Severity.CRITICAL,
        "exploits_public": False,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{CVE}",
    }
    base.update(overrides)
    return CVEReference(**base)


def _kev_content(**overrides: Any) -> dict[str, Any]:
    content: dict[str, Any] = {"cve_id": CVE, "in_catalog": True}
    content.update(overrides)
    return content


def _epss_content(**overrides: Any) -> dict[str, Any]:
    content: dict[str, Any] = {
        "cve_id": CVE,
        "status": "found",
        "probability": 0.97,
        "percentile": 0.99,
    }
    content.update(overrides)
    return content


def _cve_detail_content(score: float | None = 10.0) -> dict[str, Any]:
    return {
        "cve_id": CVE,
        "description": "Remote code execution in Log4j.",
        "cvss_v3_score": score,
        "published": "2021-12-10",
        "last_modified": "2021-12-15",
    }


def _exploit_content(has_exploit: bool = True, *, github: str = "skipped") -> dict[str, Any]:
    return {
        "cve_id": CVE,
        "has_public_exploit": has_exploit,
        "exploit_db": "found" if has_exploit else "not_found",
        "github": github,
    }


def _statuses(report: TriageReport, invocations: list[ToolInvocation]) -> dict[str, str]:
    """Map field -> status for the non-supported findings."""
    assessment = verify_grounding(report, invocations)
    return {f.field: f.status.value for f in assessment.findings}


# --- overall status ---------------------------------------------------------


def test_none_invocations_is_not_evaluated() -> None:
    assessment = verify_grounding(_report(), None)
    assert assessment.status is GroundingStatus.NOT_EVALUATED
    assert assessment.claims_checked == 0
    assert assessment.findings == []


def test_empty_report_over_empty_trajectory_is_vacuously_grounded() -> None:
    assessment = verify_grounding(_report(), [])
    assert assessment.status is GroundingStatus.GROUNDED
    assert assessment.claims_checked == 0


def test_honest_defaults_check_only_identity() -> None:
    """False/None optionals are the schema defaults, not assertions: with the
    CVE mentioned in a tool call the only claim checked is identity."""
    invocations = [_invocation("cve_lookup", "not parseable")]
    assessment = verify_grounding(_report(_cve()), invocations)
    assert assessment.status is GroundingStatus.GROUNDED
    assert assessment.claims_checked == 1
    assert assessment.supported == 1


# --- cve_id identity --------------------------------------------------------


def test_fabricated_cve_id_short_circuits() -> None:
    """A CVE no tool was asked about and no tool returned yields exactly one
    unbacked identity finding, even when other positive claims exist."""
    invocations = [
        _invocation(
            "kev_check",
            _kev_content(cve_id="CVE-2014-0160"),
            args={"cve_id": "CVE-2014-0160"},
        ),
    ]
    report = _report(_cve(in_kev_catalog=True, exploits_public=True))
    assessment = verify_grounding(report, invocations)
    assert assessment.status is GroundingStatus.SUSPECT
    assert assessment.claims_checked == 1
    assert len(assessment.findings) == 1
    finding = assessment.findings[0]
    assert finding.field == "cve_id"
    assert finding.status is GroundingClaimStatus.UNBACKED


def test_cve_id_backed_by_tool_args_alone() -> None:
    """A queried id counts as a mention even when the tool answer was empty."""
    invocations = [_invocation("kev_check", "no entry", args={"cve_id": CVE})]
    assessment = verify_grounding(_report(_cve()), invocations)
    assert assessment.supported >= 1
    assert all(f.field != "cve_id" for f in assessment.findings)


def test_cve_id_in_unparsed_content_is_unverifiable() -> None:
    invocations = [
        _invocation("osv_lookup", f"raw text mentioning {CVE}", args={"package": "log4j"}),
    ]
    assert _statuses(_report(_cve()), invocations)["cve_id"] == "unverifiable"


# --- cvss_v3_score ----------------------------------------------------------


def test_cvss_supported_within_tolerance() -> None:
    # Deliberately inside the tolerance band, not at its exact edge: the
    # comparison is float abs-diff and 10.0 - 0.05 lands a hair above 0.05.
    invocations = [_invocation("cve_lookup", _cve_detail_content(score=10.0))]
    report = _report(_cve(cvss_v3_score=9.96))
    assert 10.0 - 9.96 < CVSS_SCORE_TOLERANCE
    assessment = verify_grounding(report, invocations)
    assert assessment.status is GroundingStatus.GROUNDED
    assert assessment.mismatched == 0


def test_cvss_mismatch_beyond_tolerance() -> None:
    invocations = [_invocation("cve_lookup", _cve_detail_content(score=7.5))]
    statuses = _statuses(_report(_cve(cvss_v3_score=9.8)), invocations)
    assert statuses["cvss_v3_score"] == "mismatch"


def test_cvss_unbacked_without_score_bearing_return() -> None:
    invocations = [_invocation("kev_check", _kev_content())]
    statuses = _statuses(_report(_cve(cvss_v3_score=9.8)), invocations)
    assert statuses["cvss_v3_score"] == "unbacked"


def test_cvss_unverifiable_when_cve_lookup_unparseable() -> None:
    invocations = [_invocation("cve_lookup", {"cve_id": CVE, "garbage": True})]
    statuses = _statuses(_report(_cve(cvss_v3_score=9.8)), invocations)
    assert statuses["cvss_v3_score"] == "unverifiable"


# --- exploits_public --------------------------------------------------------


def test_exploit_true_supported() -> None:
    invocations = [_invocation("exploit_check", _exploit_content(True))]
    assessment = verify_grounding(_report(_cve(exploits_public=True)), invocations)
    assert assessment.status is GroundingStatus.GROUNDED


def test_exploit_true_unbacked_without_evidence() -> None:
    invocations = [_invocation("kev_check", _kev_content())]
    statuses = _statuses(_report(_cve(exploits_public=True)), invocations)
    assert statuses["exploits_public"] == "unbacked"


def test_exploit_claim_contradicting_evidence_is_mismatch_both_directions() -> None:
    understated = _statuses(
        _report(_cve(exploits_public=False)),
        [_invocation("exploit_check", _exploit_content(True))],
    )
    assert understated["exploits_public"] == "mismatch"
    overstated = _statuses(
        _report(_cve(exploits_public=True)),
        [_invocation("exploit_check", _exploit_content(False))],
    )
    assert overstated["exploits_public"] == "mismatch"


def test_exploit_false_without_evidence_is_not_a_claim() -> None:
    invocations = [_invocation("kev_check", _kev_content())]
    assessment = verify_grounding(_report(_cve(exploits_public=False)), invocations)
    assert all(f.field != "exploits_public" for f in assessment.findings)


# --- in_kev_catalog / kev_due_date / known_ransomware_use --------------------


def test_kev_true_supported() -> None:
    invocations = [_invocation("kev_check", _kev_content())]
    assessment = verify_grounding(_report(_cve(in_kev_catalog=True)), invocations)
    assert assessment.status is GroundingStatus.GROUNDED


def test_kev_true_unbacked_without_evidence() -> None:
    invocations = [_invocation("cve_lookup", _cve_detail_content())]
    statuses = _statuses(_report(_cve(in_kev_catalog=True)), invocations)
    assert statuses["in_kev_catalog"] == "unbacked"


def test_kev_downplay_is_mismatch() -> None:
    """in_kev_catalog=False while kev_check said True contradicts the trajectory."""
    invocations = [_invocation("kev_check", _kev_content(in_catalog=True))]
    statuses = _statuses(_report(_cve(in_kev_catalog=False)), invocations)
    assert statuses["in_kev_catalog"] == "mismatch"


def test_kev_fabricated_flag_is_mismatch() -> None:
    invocations = [_invocation("kev_check", _kev_content(in_catalog=False))]
    statuses = _statuses(_report(_cve(in_kev_catalog=True)), invocations)
    assert statuses["in_kev_catalog"] == "mismatch"


def test_kev_due_date_supported_and_mismatch() -> None:
    invocations = [_invocation("kev_check", _kev_content(due_date="2021-12-24"))]
    ok = verify_grounding(
        _report(_cve(in_kev_catalog=True, kev_due_date="2021-12-24")),
        invocations,
    )
    assert ok.status is GroundingStatus.GROUNDED
    bad = _statuses(
        _report(_cve(in_kev_catalog=True, kev_due_date="2022-01-01")),
        invocations,
    )
    assert bad["kev_due_date"] == "mismatch"


def test_kev_due_date_unbacked_without_catalog_entry() -> None:
    invocations = [_invocation("cve_lookup", _cve_detail_content())]
    statuses = _statuses(_report(_cve(kev_due_date="2021-12-24")), invocations)
    assert statuses["kev_due_date"] == "unbacked"


def test_ransomware_true_needs_true_evidence() -> None:
    supported = verify_grounding(
        _report(_cve(in_kev_catalog=True, known_ransomware_use=True)),
        [_invocation("kev_check", _kev_content(known_ransomware_use=True))],
    )
    assert supported.status is GroundingStatus.GROUNDED
    contradicted = _statuses(
        _report(_cve(in_kev_catalog=True, known_ransomware_use=True)),
        [_invocation("kev_check", _kev_content(known_ransomware_use=False))],
    )
    assert contradicted["known_ransomware_use"] == "mismatch"


def test_ransomware_true_with_flagless_kev_is_unbacked() -> None:
    """KEV not providing the flag is absence of backing, not contradiction."""
    invocations = [_invocation("kev_check", _kev_content(known_ransomware_use=None))]
    statuses = _statuses(
        _report(_cve(in_kev_catalog=True, known_ransomware_use=True)),
        invocations,
    )
    assert statuses["known_ransomware_use"] == "unbacked"


# --- EPSS --------------------------------------------------------------------


def test_epss_supported_within_tolerance() -> None:
    invocations = [_invocation("epss_score", _epss_content(probability=0.97))]
    report = _report(_cve(epss_probability=0.975, epss_percentile=0.99))
    assert 0.975 - 0.97 < EPSS_TOLERANCE
    assessment = verify_grounding(report, invocations)
    assert assessment.status is GroundingStatus.GROUNDED


def test_epss_mismatch_beyond_tolerance() -> None:
    invocations = [_invocation("epss_score", _epss_content(probability=0.10))]
    statuses = _statuses(_report(_cve(epss_probability=0.90)), invocations)
    assert statuses["epss_probability"] == "mismatch"


def test_epss_not_found_status_gives_unbacked_values() -> None:
    invocations = [
        _invocation(
            "epss_score",
            _epss_content(status="not_found", probability=None, percentile=None),
        ),
    ]
    statuses = _statuses(
        _report(_cve(epss_probability=0.5, epss_percentile=0.9)),
        invocations,
    )
    assert statuses["epss_probability"] == "unbacked"
    assert statuses["epss_percentile"] == "unbacked"


# --- attack techniques -------------------------------------------------------


def _technique(technique_id: str = "T1190") -> AttackTechnique:
    return AttackTechnique(
        id=technique_id,
        name="Exploit Public-Facing Application",
        url="https://attack.mitre.org/techniques/T1190/",
    )


def _attack_content() -> list[dict[str, Any]]:
    return [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "url": "https://attack.mitre.org/techniques/T1190/",
        },
    ]


def test_attack_technique_supported_by_mapping_return() -> None:
    invocations = [_invocation("attack_mapping", _attack_content(), args={"cwe_ids": ["CWE-502"]})]
    assessment = verify_grounding(_report(techniques=[_technique()]), invocations)
    assert assessment.status is GroundingStatus.GROUNDED


def test_attack_technique_not_in_returns_is_unbacked() -> None:
    invocations = [_invocation("attack_mapping", _attack_content(), args={})]
    assessment = verify_grounding(_report(techniques=[_technique("T1059")]), invocations)
    statuses = {f.subject: f.status.value for f in assessment.findings}
    assert statuses["T1059"] == "unbacked"


def test_attack_technique_with_unparseable_mapping_is_unverifiable() -> None:
    invocations = [_invocation("attack_mapping", "garbage", args={})]
    assessment = verify_grounding(_report(techniques=[_technique()]), invocations)
    assert assessment.findings[0].status is GroundingClaimStatus.UNVERIFIABLE


# --- robustness --------------------------------------------------------------


def test_failed_and_no_return_invocations_are_not_evidence() -> None:
    invocations = [
        _invocation("kev_check", _kev_content(), outcome="failed"),
        _invocation("kev_check", None, outcome="no_return", call_id="c2"),
    ]
    statuses = _statuses(_report(_cve(in_kev_catalog=True)), invocations)
    # Failed calls don't even back the identity claim.
    assert statuses["cve_id"] == "unbacked"


def test_garbage_content_of_every_shape_never_raises() -> None:
    shapes: list[object] = [None, 42, "text", [1, 2], {"a": object()}, {"cve_id": 3}]
    tools = ("cve_lookup", "kev_check", "epss_score", "attack_mapping")
    invocations = [
        _invocation(tool, shape, call_id=f"c{i}")
        for i, (tool, shape) in enumerate((t, s) for t in tools for s in shapes)
    ]
    assessment = verify_grounding(
        _report(_cve(in_kev_catalog=True, cvss_v3_score=9.8)),
        invocations,
    )
    assert assessment.status in (GroundingStatus.GROUNDED, GroundingStatus.SUSPECT)


def test_findings_cap_sets_truncated_and_keeps_counts() -> None:
    # 10 CVEs whose identity is backed (queried via args) but whose 4 positive
    # claims each go non-supported, plus 20 unbacked techniques: 60 findings,
    # well past the cap. Counts must remain exact.
    cves = [
        CVEReference(
            cve_id=f"CVE-2024-{10000 + i}",
            summary="x",
            severity=Severity.HIGH,
            exploits_public=True,
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-10000",
            in_kev_catalog=True,
            cvss_v3_score=9.8,
            epss_probability=0.9,
        )
        for i in range(10)
    ]
    report = TriageReport(
        summary="Overflow.",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        recommended_action="Patch.",
        cves=cves,
        attack_techniques=[
            AttackTechnique(
                id=f"T1{i:03d}",
                name=f"Technique {i}",
                url="https://attack.mitre.org/techniques/T1190/",
            )
            for i in range(20)
        ],
    )
    # Every CVE id is mentioned via args so identity is supported and the
    # 4 positive per-CVE claims all go unbacked: 40 findings + 20 technique
    # findings = 60 > MAX_FINDINGS.
    invocations = [
        _invocation(
            "cve_lookup",
            "empty",
            args={"cve_id": f"CVE-2024-{10000 + i}"},
            call_id=f"c{i}",
        )
        for i in range(10)
    ]
    assessment = verify_grounding(report, invocations)
    assert assessment.truncated is True
    assert len(assessment.findings) == MAX_FINDINGS
    total = (
        assessment.supported + assessment.unbacked + assessment.mismatched + assessment.unverifiable
    )
    assert total == assessment.claims_checked
    assert assessment.unbacked + assessment.mismatched > MAX_FINDINGS


def test_exploit_return_with_an_errored_arm_cannot_back_a_claim() -> None:
    """A False with a source in error is unknown: it neither backs a positive
    claim nor contradicts it, so the claim degrades to unverifiable."""
    inconclusive = [_invocation("exploit_check", _exploit_content(False, github="error"))]
    statuses = _statuses(_report(_cve(exploits_public=True)), inconclusive)
    assert statuses["exploits_public"] == "unverifiable"
    # A negative claim over the same return is not a claim at all.
    assessment = verify_grounding(_report(_cve(exploits_public=False)), inconclusive)
    assert assessment.status is GroundingStatus.GROUNDED
    assert not [f for f in assessment.findings if f.field == "exploits_public"]


def test_exploit_return_with_conclusive_arms_contradicts_an_inflated_claim() -> None:
    conclusive = [_invocation("exploit_check", _exploit_content(False, github="not_found"))]
    statuses = _statuses(_report(_cve(exploits_public=True)), conclusive)
    assert statuses["exploits_public"] == "mismatch"
