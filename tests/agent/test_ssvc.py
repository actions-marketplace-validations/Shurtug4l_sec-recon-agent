"""Unit tests for the deterministic SSVC decision function (no LLM, no I/O)."""

from sec_recon_agent.agent.schema import CVEReference, Severity, SsvcDecision
from sec_recon_agent.agent.ssvc import (
    SsvcSignals,
    assess_ssvc,
    decide_for_signals,
)


def _signals(
    *,
    in_kev: bool = False,
    ransomware: bool | None = None,
    exploit_public: bool = False,
    epss: float | None = None,
    epss_pct: float | None = None,
    severity: Severity | None = Severity.MEDIUM,
) -> SsvcSignals:
    return SsvcSignals(
        in_kev=in_kev,
        known_ransomware=ransomware,
        exploit_public=exploit_public,
        epss_probability=epss,
        epss_percentile=epss_pct,
        severity=severity,
    )


def _cve(
    cve_id: str = "CVE-2021-41773",
    *,
    severity: Severity = Severity.CRITICAL,
    in_kev: bool = False,
    ransomware: bool | None = None,
    exploit_public: bool = False,
    epss: float | None = None,
    epss_pct: float | None = None,
) -> CVEReference:
    return CVEReference(
        cve_id=cve_id,
        summary="s",
        severity=severity,
        exploits_public=exploit_public,
        nvd_url="https://nvd.nist.gov/vuln/detail/" + cve_id,
        in_kev_catalog=in_kev,
        known_ransomware_use=ransomware,
        epss_probability=epss,
        epss_percentile=epss_pct,
    )


# --- per-signal decision rules -------------------------------------------


def test_ransomware_is_act_and_outranks_kev() -> None:
    decision, rule = decide_for_signals(_signals(in_kev=True, ransomware=True))
    assert decision is SsvcDecision.ACT
    assert rule == "ransomware"


def test_kev_membership_is_act() -> None:
    decision, rule = decide_for_signals(_signals(in_kev=True))
    assert decision is SsvcDecision.ACT
    assert rule == "kev-active-exploitation"


def test_public_exploit_with_high_epss_is_act() -> None:
    decision, rule = decide_for_signals(_signals(exploit_public=True, epss=0.7))
    assert decision is SsvcDecision.ACT
    assert rule == "public-exploit+high-epss"


def test_public_exploit_alone_is_attend() -> None:
    decision, rule = decide_for_signals(_signals(exploit_public=True, epss=0.2))
    assert decision is SsvcDecision.ATTEND
    assert rule == "public-exploit"


def test_high_epss_without_exploit_is_attend() -> None:
    decision, rule = decide_for_signals(_signals(epss=0.5))
    assert decision is SsvcDecision.ATTEND
    assert rule == "high-epss"


def test_high_epss_percentile_without_exploit_is_attend() -> None:
    decision, rule = decide_for_signals(_signals(epss=0.01, epss_pct=0.96))
    assert decision is SsvcDecision.ATTEND
    assert rule == "high-epss"


def test_elevated_epss_is_track_star() -> None:
    decision, rule = decide_for_signals(_signals(epss=0.2, severity=Severity.LOW))
    assert decision is SsvcDecision.TRACK_STAR
    assert rule == "elevated-epss"


def test_high_severity_without_exploitation_is_track_star() -> None:
    decision, rule = decide_for_signals(_signals(severity=Severity.HIGH))
    assert decision is SsvcDecision.TRACK_STAR
    assert rule == "high-severity-no-exploitation"


def test_no_signals_is_track() -> None:
    decision, rule = decide_for_signals(_signals(severity=Severity.LOW))
    assert decision is SsvcDecision.TRACK
    assert rule == "baseline"


def test_ransomware_false_does_not_trigger_act() -> None:
    # known_ransomware=False (explicit no) must not be treated like True.
    decision, _ = decide_for_signals(_signals(ransomware=False, severity=Severity.LOW))
    assert decision is SsvcDecision.TRACK


# --- report-level reduction ----------------------------------------------


def test_assess_empty_report_is_track_no_cves() -> None:
    assessment = assess_ssvc([], None)
    assert assessment.decision is SsvcDecision.TRACK
    assert assessment.rule == "no-cves"
    assert assessment.driving_cve is None


def test_assess_all_track_report_records_driver() -> None:
    # A report whose CVEs all score Track must still name a driving CVE and
    # the rule that fired: reporting "no CVEs were grounded" when CVEs are
    # present (they merely scored Track) is a false rationale.
    cves = [
        _cve("CVE-2024-35195", severity=Severity.MEDIUM),  # baseline / Track
        _cve("CVE-2024-47081", severity=Severity.LOW),  # baseline / Track
    ]
    assessment = assess_ssvc(cves, None)
    assert assessment.decision is SsvcDecision.TRACK
    assert assessment.rule == "baseline"
    assert assessment.driving_cve == "CVE-2024-35195"
    assert "no CVEs were grounded" not in assessment.rationale
    assert "CVE-2024-35195" in assessment.rationale


def test_assess_picks_most_urgent_cve_and_records_driver() -> None:
    cves = [
        _cve("CVE-2020-0001", severity=Severity.LOW),  # baseline / Track
        _cve("CVE-2021-44228", in_kev=True),  # Act
        _cve("CVE-2022-0002", exploit_public=True, epss=0.2),  # Attend
    ]
    assessment = assess_ssvc(cves, None)
    assert assessment.decision is SsvcDecision.ACT
    assert assessment.driving_cve == "CVE-2021-44228"
    assert "CVE-2021-44228" in assessment.rationale


def test_assess_rationale_is_bounded() -> None:
    assessment = assess_ssvc([_cve(in_kev=True)], None)
    assert len(assessment.rationale) <= 500
    assert assessment.decision.value in assessment.rationale
