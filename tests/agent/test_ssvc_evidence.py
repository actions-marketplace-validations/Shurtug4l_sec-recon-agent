"""Tests for the evidence-derived SSVC verdict (no LLM, no I/O).

The decision ladder itself is covered in test_ssvc.py. These tests pin the
part the trust story rests on: WHICH input the verdict is computed from. The
signals must come from the captured tool returns; the report's own fields
are consulted only where no usable evidence exists, and every such fallback
is named on the assessment so a verdict on the model's word is never
presented as a verdict on the tools' word.
"""

from typing import Any

from sec_recon_agent.agent.schema import (
    CVEReference,
    Severity,
    SsvcBasis,
    SsvcDecision,
)
from sec_recon_agent.agent.ssvc import assess_from_signals, assess_ssvc
from sec_recon_agent.agent.trajectory import ToolInvocation

CVE = "CVE-2021-44228"
OTHER = "CVE-2020-1472"


def _invocation(
    tool: str,
    content: object,
    *,
    cve_id: str = CVE,
    outcome: str = "success",
    call_id: str | None = None,
) -> ToolInvocation:
    return ToolInvocation(
        tool_name=tool,
        tool_call_id=call_id or f"{tool}-{cve_id}",
        args={"cve_id": cve_id},
        content=content,
        outcome=outcome,  # type: ignore[arg-type]
    )


def _cve(cve_id: str = CVE, **overrides: Any) -> CVEReference:
    base: dict[str, Any] = {
        "cve_id": cve_id,
        "summary": "Log4Shell RCE.",
        "severity": Severity.CRITICAL,
        "exploits_public": False,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
    base.update(overrides)
    return CVEReference(**base)


def _kev(
    *, in_catalog: bool = True, ransomware: bool | None = None, cve_id: str = CVE
) -> ToolInvocation:
    return _invocation(
        "kev_check",
        {"cve_id": cve_id, "in_catalog": in_catalog, "known_ransomware_use": ransomware},
        cve_id=cve_id,
    )


def _epss(
    *,
    status: str = "found",
    probability: float | None = 0.01,
    percentile: float | None = 0.10,
    cve_id: str = CVE,
) -> ToolInvocation:
    return _invocation(
        "epss_score",
        {"cve_id": cve_id, "status": status, "probability": probability, "percentile": percentile},
        cve_id=cve_id,
    )


def _exploit(*, has: bool = False, cve_id: str = CVE, github: str = "skipped") -> ToolInvocation:
    return _invocation(
        "exploit_check",
        {
            "cve_id": cve_id,
            "has_public_exploit": has,
            "exploit_db": "found" if has else "not_found",
            "github": github,
        },
        cve_id=cve_id,
    )


def _detail(*, score: float | None = 9.8, cve_id: str = CVE) -> ToolInvocation:
    return _invocation(
        "cve_lookup",
        {
            "cve_id": cve_id,
            "description": "Remote code execution.",
            "cvss_v3_score": score,
            "published": "2021-12-10",
            "last_modified": "2021-12-15",
        },
        cve_id=cve_id,
    )


def _quiet_trajectory(cve_id: str = CVE) -> list[ToolInvocation]:
    """Every feed consulted, every signal negative: baseline Track material."""
    return [
        _detail(score=5.0, cve_id=cve_id),
        _kev(in_catalog=False, cve_id=cve_id),
        _epss(cve_id=cve_id),
        _exploit(cve_id=cve_id),
    ]


# --- no trajectory -----------------------------------------------------------


def test_no_trajectory_computes_from_the_report_and_says_so() -> None:
    assessment = assess_ssvc([_cve(in_kev_catalog=True)], None)
    assert assessment.decision is SsvcDecision.ACT
    assert assessment.basis is SsvcBasis.REPORT
    assert assessment.unverified_signals == []


# --- evidence wins over the report -------------------------------------------


def test_evidence_overrides_a_downplayed_kev_flag() -> None:
    """The omission attack: the model writes in_kev_catalog=False, the tool said True."""
    trajectory = [_detail(), _kev(in_catalog=True), _epss(), _exploit()]
    assessment = assess_ssvc([_cve(in_kev_catalog=False)], trajectory)
    assert assessment.decision is SsvcDecision.ACT
    assert assessment.rule == "kev-active-exploitation"
    assert assessment.basis is SsvcBasis.EVIDENCE
    assert assessment.unverified_signals == []
    assert "taken from the report" not in assessment.rationale


def test_inflated_report_flags_cannot_escalate() -> None:
    report_cve = _cve(in_kev_catalog=True, exploits_public=True, epss_probability=0.99)
    assessment = assess_ssvc([report_cve], _quiet_trajectory())
    assert assessment.decision is SsvcDecision.TRACK
    assert assessment.rule == "baseline"
    assert assessment.basis is SsvcBasis.EVIDENCE


def test_ransomware_flag_comes_from_kev_evidence() -> None:
    trajectory = [_detail(), _kev(in_catalog=True, ransomware=True), _epss(), _exploit()]
    assessment = assess_ssvc([_cve(known_ransomware_use=False)], trajectory)
    assert assessment.rule == "ransomware"
    assert assessment.basis is SsvcBasis.EVIDENCE


def test_most_urgent_reading_wins_across_repeated_returns() -> None:
    trajectory = [
        _detail(),
        _kev(in_catalog=False, cve_id=CVE),
        _invocation("kev_check", {"cve_id": CVE, "in_catalog": True}, call_id="kev-again"),
        _epss(),
        _exploit(),
    ]
    assessment = assess_ssvc([_cve()], trajectory)
    assert assessment.decision is SsvcDecision.ACT


# --- evidence-backed absences are not fallbacks --------------------------------


def test_epss_not_found_is_an_answer_not_a_gap() -> None:
    trajectory = [
        _detail(score=5.0),
        _kev(in_catalog=False),
        _epss(status="not_found", probability=None, percentile=None),
        _exploit(),
    ]
    assessment = assess_ssvc([_cve(epss_probability=0.99, epss_percentile=0.99)], trajectory)
    assert assessment.decision is SsvcDecision.TRACK
    assert assessment.basis is SsvcBasis.EVIDENCE


def test_cve_record_without_score_yields_no_severity_signal() -> None:
    trajectory = [_detail(score=None), _kev(in_catalog=False), _epss(), _exploit()]
    assessment = assess_ssvc([_cve(severity=Severity.CRITICAL)], trajectory)
    assert assessment.rule == "baseline"
    assert assessment.basis is SsvcBasis.EVIDENCE


def test_severity_is_banded_from_cvss_evidence_not_the_report() -> None:
    trajectory = [_detail(score=9.8), _kev(in_catalog=False), _epss(), _exploit()]
    assessment = assess_ssvc([_cve(severity=Severity.LOW)], trajectory)
    assert assessment.decision is SsvcDecision.TRACK_STAR
    assert assessment.rule == "high-severity-no-exploitation"
    assert assessment.basis is SsvcBasis.EVIDENCE


# --- fallbacks are taken from the report and named ------------------------------


def test_missing_kev_lookup_falls_back_and_is_named() -> None:
    trajectory = [_detail(score=9.8), _epss(), _exploit()]
    assessment = assess_ssvc([_cve(in_kev_catalog=False)], trajectory)
    assert assessment.decision is SsvcDecision.TRACK_STAR
    assert assessment.basis is SsvcBasis.MIXED
    assert assessment.unverified_signals == [f"{CVE}:kev"]
    assert assessment.rationale.endswith(
        "1 signal(s) taken from the report, not verified against tool returns.",
    )


def test_missing_kev_lookup_still_honors_the_reports_flag_but_flags_it() -> None:
    """The fallback takes the model's word, visibly: the verdict matches what the
    CVE card shows, and `basis`/`unverified_signals` say it was not checked."""
    trajectory = [_detail(score=9.8), _epss(), _exploit()]
    assessment = assess_ssvc([_cve(in_kev_catalog=True)], trajectory)
    assert assessment.decision is SsvcDecision.ACT
    assert assessment.basis is SsvcBasis.MIXED
    assert assessment.unverified_signals == [f"{CVE}:kev"]


def test_epss_upstream_error_falls_back_to_the_report() -> None:
    trajectory = [
        _detail(score=5.0),
        _kev(in_catalog=False),
        _epss(status="upstream_error", probability=None, percentile=None),
        _exploit(),
    ]
    assessment = assess_ssvc([_cve(epss_probability=0.99)], trajectory)
    assert assessment.rule == "high-epss"
    assert assessment.basis is SsvcBasis.MIXED
    assert assessment.unverified_signals == [f"{CVE}:epss"]


def test_failed_return_is_not_evidence() -> None:
    trajectory = [_detail(score=5.0), _epss(), _exploit()]
    trajectory.append(_invocation("kev_check", None, outcome="failed"))
    assessment = assess_ssvc([_cve()], trajectory)
    assert assessment.unverified_signals == [f"{CVE}:kev"]


def test_unparseable_return_is_not_evidence() -> None:
    trajectory = [_detail(score=5.0), _epss(), _exploit()]
    trajectory.append(_invocation("kev_check", "upstream unavailable"))
    assessment = assess_ssvc([_cve()], trajectory)
    assert assessment.basis is SsvcBasis.MIXED
    assert assessment.unverified_signals == [f"{CVE}:kev"]


def test_fabricated_cve_takes_every_signal_from_the_report() -> None:
    assessment = assess_ssvc([_cve(cve_id="CVE-2099-0001")], _quiet_trajectory())
    assert assessment.basis is SsvcBasis.MIXED
    assert assessment.unverified_signals == [
        "CVE-2099-0001:kev",
        "CVE-2099-0001:exploit",
        "CVE-2099-0001:epss",
        "CVE-2099-0001:severity",
    ]


def test_empty_trajectory_over_a_cve_report_is_fully_unverified() -> None:
    assessment = assess_ssvc([_cve()], [])
    assert assessment.basis is SsvcBasis.MIXED
    assert len(assessment.unverified_signals) == 4


def test_unverified_entries_are_prefixed_per_cve() -> None:
    trajectory = _quiet_trajectory(CVE)  # nothing at all for OTHER
    assessment = assess_ssvc([_cve(), _cve(cve_id=OTHER)], trajectory)
    assert assessment.basis is SsvcBasis.MIXED
    assert all(entry.startswith(f"{OTHER}:") for entry in assessment.unverified_signals)
    assert len(assessment.unverified_signals) == 4


def test_no_cves_over_a_trajectory_is_vacuously_evidence_based() -> None:
    assessment = assess_ssvc([], _quiet_trajectory())
    assert assessment.rule == "no-cves"
    assert assessment.basis is SsvcBasis.EVIDENCE
    assert assessment.unverified_signals == []


# --- the shared core stamps what the caller declares ----------------------------


def test_gate_path_declares_its_basis() -> None:
    assessment = assess_from_signals([], basis=SsvcBasis.EVIDENCE)
    assert assessment.basis is SsvcBasis.EVIDENCE
    assert assessment.unverified_signals == []
    assert "taken from the report" not in assessment.rationale


def test_exploit_arm_in_error_is_not_evidence_of_absence() -> None:
    """exploit_check answered, but one source errored and nothing was accepted:
    the exploit signal is unknown, so the report's value is used and named."""
    trajectory = [_detail(score=5.0), _kev(in_catalog=False), _epss(), _exploit(github="error")]
    assessment = assess_ssvc([_cve(exploits_public=True)], trajectory)
    assert assessment.rule == "public-exploit"
    assert assessment.basis is SsvcBasis.MIXED
    assert assessment.unverified_signals == [f"{CVE}:exploit"]


def test_exploit_arm_skipped_by_configuration_is_conclusive() -> None:
    trajectory = [_detail(score=5.0), _kev(in_catalog=False), _epss(), _exploit(github="skipped")]
    assessment = assess_ssvc([_cve(exploits_public=True)], trajectory)
    assert assessment.rule == "baseline"
    assert assessment.basis is SsvcBasis.EVIDENCE


def test_exploit_found_on_one_arm_wins_even_if_the_other_errored() -> None:
    trajectory = [
        _detail(score=5.0),
        _kev(in_catalog=False),
        _epss(),
        _exploit(has=True, github="error"),
    ]
    assessment = assess_ssvc([_cve(exploits_public=False)], trajectory)
    assert assessment.rule == "public-exploit"
    assert assessment.basis is SsvcBasis.EVIDENCE
