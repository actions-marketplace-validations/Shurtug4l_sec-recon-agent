"""Unit tests for the red-team scorer."""

from sec_recon_agent.agent.schema import (
    Confidence,
    Severity,
    TriageReport,
)
from sec_recon_agent.redteam.payloads import (
    InjectionPayload,
    ResistanceCheck,
)
from sec_recon_agent.redteam.scorer import (
    PayloadVerdict,
    aggregate_by_atlas_technique,
    score_payload,
    summarize,
)


def _report(
    summary: str = "ok",
    recommended_action: str = "patch",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
) -> TriageReport:
    return TriageReport(
        summary=summary,
        severity=severity,
        confidence=confidence,
        recommended_action=recommended_action,
    )


def _payload(
    *checks: ResistanceCheck,
    atlas_techniques: tuple[str, ...] = (),
    payload_id: str = "test",
    category: str = "direct",
) -> InjectionPayload:
    return InjectionPayload(
        id=payload_id,
        category=category,
        severity="high",
        query="dummy",
        checks=checks,
        atlas_techniques=atlas_techniques,
    )


def test_resists_when_pattern_absent() -> None:
    payload = _payload(
        ResistanceCheck(field="summary", pattern_must_be_absent="LEAKED"),
    )
    verdict = score_payload(payload, _report(summary="all clean here"))
    assert verdict.resisted is True
    assert verdict.failed_checks == ()


def test_cedes_when_pattern_present() -> None:
    payload = _payload(
        ResistanceCheck(field="summary", pattern_must_be_absent="LEAKED"),
    )
    verdict = score_payload(payload, _report(summary="oops LEAKED canary"))
    assert verdict.resisted is False
    assert any("forbidden substring" in f for f in verdict.failed_checks)


def test_pattern_check_is_case_insensitive() -> None:
    payload = _payload(
        ResistanceCheck(field="summary", pattern_must_be_absent="canary"),
    )
    verdict = score_payload(payload, _report(summary="CANARY found"))
    assert verdict.resisted is False


def test_cedes_when_severity_matches_forbidden_value() -> None:
    payload = _payload(
        ResistanceCheck(field="severity", value_must_not_be="info"),
    )
    verdict = score_payload(payload, _report(severity=Severity.INFO))
    assert verdict.resisted is False
    assert any("matched forbidden value" in f for f in verdict.failed_checks)


def test_resists_when_severity_not_forbidden_value() -> None:
    payload = _payload(
        ResistanceCheck(field="severity", value_must_not_be="info"),
    )
    verdict = score_payload(payload, _report(severity=Severity.CRITICAL))
    assert verdict.resisted is True


def test_multi_check_payload_fails_on_any_break() -> None:
    payload = _payload(
        ResistanceCheck(field="severity", value_must_not_be="info"),
        ResistanceCheck(field="confidence", value_must_not_be="low"),
    )
    # severity fine, confidence broken
    verdict = score_payload(
        payload,
        _report(severity=Severity.HIGH, confidence=Confidence.LOW),
    )
    assert verdict.resisted is False
    assert len(verdict.failed_checks) == 1


def test_any_field_concatenates_text() -> None:
    payload = _payload(
        ResistanceCheck(field="any", pattern_must_be_absent="needle"),
    )
    verdict = score_payload(
        payload,
        _report(summary="clean", recommended_action="needle in haystack"),
    )
    assert verdict.resisted is False


def test_summarize_aggregates() -> None:
    verdicts = [
        PayloadVerdict("a", "direct", True, ()),
        PayloadVerdict("b", "direct", False, ("oops",)),
        PayloadVerdict("c", "role_play", True, ()),
    ]
    s = summarize(verdicts)
    assert s["total"] == 3
    assert s["resisted"] == 2
    assert abs(float(s["resistance_rate"]) - 2 / 3) < 1e-9


def test_score_payload_propagates_atlas_techniques() -> None:
    payload = _payload(
        ResistanceCheck(field="severity", value_must_not_be="info"),
        atlas_techniques=("AML.T0051.000", "AML.T0051.001"),
    )
    verdict = score_payload(payload, _report(severity=Severity.CRITICAL))
    assert verdict.atlas_techniques == ("AML.T0051.000", "AML.T0051.001")


def test_atlas_aggregate_counts_technique_overlaps_correctly() -> None:
    """A payload tagged with two techniques contributes to both
    aggregates; this is by design, the per-technique rate measures
    'how often the agent held the boundary on any payload exercising
    this technique', not a partition."""
    verdicts = [
        PayloadVerdict("a", "direct", True, (), ("AML.T0051.000",)),
        PayloadVerdict("b", "direct", False, ("oops",), ("AML.T0051.000", "AML.T0051.001")),
        PayloadVerdict("c", "indirect", True, (), ("AML.T0051.001",)),
        PayloadVerdict("d", "system_extract", True, (), ("AML.T0056",)),
    ]
    aggs = aggregate_by_atlas_technique(verdicts)
    by_id = {a.technique: a for a in aggs}
    # T0051.000: 2 total (a + b), 1 resisted (a). Rate 50%.
    assert by_id["AML.T0051.000"].total == 2
    assert by_id["AML.T0051.000"].resisted == 1
    assert by_id["AML.T0051.000"].rate == 0.5
    # T0051.001: 2 total (b + c), 1 resisted (c). Rate 50%.
    assert by_id["AML.T0051.001"].total == 2
    assert by_id["AML.T0051.001"].resisted == 1
    # T0056: 1 total (d), 1 resisted (d). Rate 100%.
    assert by_id["AML.T0056"].total == 1
    assert by_id["AML.T0056"].resisted == 1
    assert by_id["AML.T0056"].rate == 1.0


def test_atlas_aggregate_returns_empty_when_no_techniques() -> None:
    verdicts = [PayloadVerdict("a", "direct", True, (), ())]
    aggs = aggregate_by_atlas_technique(verdicts)
    assert aggs == []


def test_every_production_payload_carries_atlas_techniques() -> None:
    """Drift detector: every payload in the production battery must
    declare ATLAS techniques except the explicit sanity case. Keeps the
    governance documentation honest as the battery grows."""
    from sec_recon_agent.redteam.payloads import PAYLOADS

    missing = [p.id for p in PAYLOADS if not p.atlas_techniques and not p.id.startswith("sanity-")]
    assert missing == [], (
        f"these payloads are tagged as attacks but have no ATLAS technique: {missing}"
    )


def test_summarize_handles_empty() -> None:
    s = summarize([])
    assert s["total"] == 0
    assert s["resisted"] == 0
    assert s["resistance_rate"] == 0.0
