"""Property-based tests using Hypothesis. Each test declares an invariant
the code is contractually obligated to honor for any input in the strategy's
domain. Failures here surface contract violations that explicit example
tests would miss because they only sample a handful of cases by hand.

These tests run fast (no network, no LLM). They are NOT marked slow.
"""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from sec_recon_agent.mcp_server.models import (
    CVECandidate,
    CVEDetail,
    NmapPort,
)
from sec_recon_agent.mcp_server.security import (
    FENCE_OVERHEAD,
    UNTRUSTED_END,
    UNTRUSTED_START,
    fence_untrusted,
    neutralize_markers,
)

# ----------------------------------------------------------------------------
# fence_untrusted: the untrusted-content wrapper at the tool boundary.
# Four invariants:
#   1. Any non-empty text is wrapped (both markers present, exactly once).
#   2. The text is preserved inside the wrapping, except that marker-shaped
#      tokens have their `<` escaped: we sanitize the BOUNDARY, never the
#      content, and a forged marker is part of the content.
#   3. None and "" pass through unchanged (empty fence adds tokens without
#      changing the LLM's interpretation).
#   4. With a budget, the output never exceeds budget + FENCE_OVERHEAD.
# ----------------------------------------------------------------------------


@given(st.text(min_size=1))
@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=200)
def test_fence_wraps_any_non_empty_string(text: str) -> None:
    result = fence_untrusted(text)
    assert result is not None
    assert result.startswith(UNTRUSTED_START)
    assert result.endswith(UNTRUSTED_END)


@given(st.text(min_size=1))
@settings(max_examples=200)
def test_fence_preserves_original_content(text: str) -> None:
    result = fence_untrusted(text)
    assert result is not None
    assert neutralize_markers(text) in result, "the (marker-neutralized) text must be preserved"
    # The real markers appear exactly once each, whatever the text carried.
    assert result.count(UNTRUSTED_START) == 1
    assert result.count(UNTRUSTED_END) == 1


@given(st.text(min_size=1, max_size=3000), st.integers(min_value=1, max_value=600))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_fence_with_budget_never_exceeds_budget_plus_overhead(text: str, budget: int) -> None:
    result = fence_untrusted(text, max_chars=budget)
    assert result is not None
    assert len(result) <= budget + FENCE_OVERHEAD


@given(st.sampled_from([None, ""]))
def test_fence_passes_empty_through(text: str | None) -> None:
    assert fence_untrusted(text) == text


def test_cvecandidate_summary_accommodates_fenced_max_truncation() -> None:
    """Regression: cve_semantic_search truncates the CVE description to 500
    chars, then wraps it in UNTRUSTED_CONTENT markers (FENCE_OVERHEAD chars).
    CVECandidate.summary must accommodate the fenced result. When it did not
    (max_length was 500), a hit whose description was long enough that the
    fenced form exceeded 500 chars crashed the tool with a string_too_long
    ValidationError, which surfaced to the agent as
    'Tool cve_semantic_search exceeded max retries' and took the triage down.
    """
    raw = "x" * 500  # cve_search caps the raw description at 500 before fencing
    fenced = fence_untrusted(raw)
    assert fenced is not None
    assert len(fenced) > 500, "the fence markers must push a 500-char payload over 500"
    # Must not raise: a full-length fenced description has to validate.
    candidate = CVECandidate(cve_id="CVE-2021-41773", summary=fenced, similarity=0.5)
    assert candidate.summary == fenced


# ----------------------------------------------------------------------------
# CveIdStr regex: ^CVE-\d{4}-\d{4,}$. Used at every CVE-accepting boundary
# (cve_lookup, exploit_check, kev_check when it lands). The pattern is the
# first line of defense against injection in URL params.
# ----------------------------------------------------------------------------


@given(
    year=st.integers(min_value=1999, max_value=2099),
    seq=st.integers(min_value=1000, max_value=99_999_999),
)
def test_valid_cve_ids_are_accepted(year: int, seq: int) -> None:
    cve_id = f"CVE-{year:04d}-{seq:04d}"
    candidate = CVECandidate(cve_id=cve_id, summary="x", similarity=0.5)
    assert candidate.cve_id == cve_id


@given(st.text(min_size=1).filter(lambda s: not s.startswith("CVE-")))
@settings(max_examples=100)
def test_invalid_cve_ids_are_rejected(garbage: str) -> None:
    try:
        CVECandidate(cve_id=garbage, summary="x", similarity=0.5)
    except ValidationError:
        return
    # If we reach here, Pydantic accepted invalid input. The only way that
    # can happen is if `garbage` accidentally matches the regex anyway, which
    # the filter above precludes.
    raise AssertionError(f"Invalid CVE ID accepted: {garbage!r}")


# ----------------------------------------------------------------------------
# Pydantic field constraints on the structured tool output. These are the
# guarantees the agent relies on when filling TriageReport.
# ----------------------------------------------------------------------------


@given(portid=st.integers(min_value=1, max_value=65535))
def test_nmap_port_accepts_valid_port_range(portid: int) -> None:
    port = NmapPort(portid=portid, protocol="tcp", state="open")
    assert port.portid == portid


@given(portid=st.one_of(st.integers(max_value=0), st.integers(min_value=65536)))
def test_nmap_port_rejects_out_of_range(portid: int) -> None:
    try:
        NmapPort(portid=portid, protocol="tcp", state="open")
    except ValidationError:
        return
    raise AssertionError(f"Out-of-range port accepted: {portid}")


@given(score=st.floats(min_value=0.0, max_value=10.0, allow_nan=False))
def test_cvss_score_in_valid_range_accepted(score: float) -> None:
    detail = CVEDetail(
        cve_id="CVE-2024-0001",
        description="x",
        cvss_v3_score=score,
        published="2024-01-01",
        last_modified="2024-01-02",
    )
    assert detail.cvss_v3_score == score


@given(
    score=st.one_of(
        st.floats(max_value=-0.001, allow_nan=False),
        st.floats(min_value=10.001, allow_nan=False),
    ),
)
def test_cvss_score_out_of_range_rejected(score: float) -> None:
    try:
        CVEDetail(
            cve_id="CVE-2024-0001",
            description="x",
            cvss_v3_score=score,
            published="2024-01-01",
            last_modified="2024-01-02",
        )
    except ValidationError:
        return
    raise AssertionError(f"Out-of-range CVSS accepted: {score}")


@given(similarity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
def test_candidate_similarity_in_valid_range(similarity: float) -> None:
    cand = CVECandidate(
        cve_id="CVE-2024-0001",
        summary="x",
        similarity=similarity,
    )
    assert cand.similarity == similarity
