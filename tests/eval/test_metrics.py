"""Unit tests for the eval metric primitives (pure, no I/O)."""

import pytest

from sec_recon_agent.agent.schema import (
    Confidence,
    CVEReference,
    Severity,
    SsvcAssessment,
    SsvcBasis,
    SsvcDecision,
    TriageReport,
)
from sec_recon_agent.eval.metrics import (
    confidence_to_probability,
    expected_calibration_error,
    hit_at_k,
    hit_rate_at_k,
    is_conformant,
    mean_reciprocal_rank,
    percentile,
    reciprocal_rank,
)

# --- percentile ----------------------------------------------------------


def test_percentile_empty_is_none() -> None:
    assert percentile([], 95) is None


def test_percentile_single_value() -> None:
    assert percentile([4.2], 95) == pytest.approx(4.2)


def test_percentile_matches_linear_interpolation() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    # numpy.percentile(values, 95) == 3.85 with linear interpolation.
    assert percentile(values, 95) == pytest.approx(3.85)
    assert percentile(values, 50) == pytest.approx(2.5)
    assert percentile(values, 0) == pytest.approx(1.0)
    assert percentile(values, 100) == pytest.approx(4.0)


def test_percentile_rejects_out_of_range_p() -> None:
    with pytest.raises(ValueError, match="in \\[0, 100\\]"):
        percentile([1.0], 150)


# --- retrieval -----------------------------------------------------------


def test_reciprocal_rank_first_hit() -> None:
    assert reciprocal_rank(["a", "b", "c"], ["b"]) == pytest.approx(0.5)
    assert reciprocal_rank(["a", "b", "c"], ["a"]) == pytest.approx(1.0)


def test_reciprocal_rank_no_hit_is_zero() -> None:
    assert reciprocal_rank(["a", "b"], ["z"]) == 0.0


def test_mean_reciprocal_rank() -> None:
    results = [
        (["a", "b"], ["a"]),  # rr = 1.0
        (["a", "b"], ["b"]),  # rr = 0.5
        (["a", "b"], ["z"]),  # rr = 0.0
    ]
    assert mean_reciprocal_rank(results) == pytest.approx(0.5)


def test_mean_reciprocal_rank_empty_is_none() -> None:
    assert mean_reciprocal_rank([]) is None


def test_hit_at_k() -> None:
    assert hit_at_k(["a", "b", "c"], ["c"], 3) is True
    assert hit_at_k(["a", "b", "c"], ["c"], 2) is False
    assert hit_at_k(["a", "b", "c"], ["c"], 0) is False


def test_hit_rate_at_k() -> None:
    results = [
        (["a", "b", "c"], ["a"]),  # hit@1
        (["a", "b", "c"], ["c"]),  # miss@1, hit@3
        (["a", "b", "c"], ["z"]),  # miss
    ]
    assert hit_rate_at_k(results, 1) == pytest.approx(1 / 3)
    assert hit_rate_at_k(results, 3) == pytest.approx(2 / 3)


def test_hit_rate_at_k_empty_is_none() -> None:
    assert hit_rate_at_k([], 5) is None


# --- calibration ---------------------------------------------------------


def test_confidence_to_probability_accepts_enum_and_str() -> None:
    assert confidence_to_probability(Confidence.HIGH) == pytest.approx(0.9)
    assert confidence_to_probability("medium") == pytest.approx(0.6)
    assert confidence_to_probability(Confidence.LOW) == pytest.approx(0.3)


def test_ece_perfect_calibration_is_zero() -> None:
    # Predicted 0.0 always wrong, 1.0 always right -> perfectly calibrated.
    samples = [(1.0, True), (1.0, True), (0.0, False), (0.0, False)]
    assert expected_calibration_error(samples) == pytest.approx(0.0)


def test_ece_overconfident_is_nonzero() -> None:
    # Predicted 0.9 but only 50% correct -> |0.9 - 0.5| = 0.4 in that bin.
    samples = [(0.9, True), (0.9, False)]
    assert expected_calibration_error(samples) == pytest.approx(0.4)


def test_ece_empty_is_none() -> None:
    assert expected_calibration_error([]) is None


def test_ece_rejects_bad_bins() -> None:
    with pytest.raises(ValueError, match="n_bins"):
        expected_calibration_error([(0.5, True)], n_bins=0)


# --- conformance ---------------------------------------------------------


def _report(
    *,
    summary: str = "ok",
    recommended_action: str = "patch",
    with_ssvc: bool = True,
) -> TriageReport:
    ssvc = (
        SsvcAssessment(
            decision=SsvcDecision.TRACK,
            rule="baseline",
            rationale="r",
            basis=SsvcBasis.EVIDENCE,
        )
        if with_ssvc
        else None
    )
    return TriageReport(
        summary=summary,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommended_action=recommended_action,
        cves=[],
        ssvc=ssvc,
    )


def test_is_conformant_none_is_false() -> None:
    assert is_conformant(None) is False


def test_is_conformant_well_formed_report() -> None:
    assert is_conformant(_report()) is True


def test_is_conformant_rejects_empty_summary() -> None:
    assert is_conformant(_report(summary="   ")) is False


def test_is_conformant_rejects_empty_action() -> None:
    assert is_conformant(_report(recommended_action="")) is False


def test_is_conformant_rejects_missing_ssvc() -> None:
    assert is_conformant(_report(with_ssvc=False)) is False


def test_is_conformant_ignores_unused_cve_import() -> None:
    # Guard the CVEReference import is exercised so the fixture stays honest.
    cve = CVEReference(
        cve_id="CVE-2021-41773",
        summary="s",
        severity=Severity.HIGH,
        exploits_public=False,
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    )
    report = _report()
    report = report.model_copy(update={"cves": [cve]})
    assert is_conformant(report) is True
