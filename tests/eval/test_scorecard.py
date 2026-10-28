"""Unit tests for the scorecard generator (pure builder + parsers, no live stack)."""

from typing import Any

from sec_recon_agent.eval.cassette import Cassette, RecordedOutcomes
from sec_recon_agent.eval.golden_set import GOLDEN_SET
from sec_recon_agent.eval.scorecard import (
    build_scorecard,
    eval_metrics_from_records,
    golden_coverage,
    grounding_metrics_from_cassettes,
    main,
    redteam_coverage,
    redteam_metrics_from_json,
    retrieval_metrics_from_json,
    ssvc_thresholds,
)
from sec_recon_agent.redteam.payloads import PAYLOADS

# --- deterministic coverage ----------------------------------------------


def test_golden_coverage_reflects_golden_set() -> None:
    cov = golden_coverage()
    assert cov.total == len(GOLDEN_SET)
    assert cov.kev_cases == sum(1 for c in GOLDEN_SET if c.expected_in_kev is True)
    assert cov.ransomware_cases == sum(1 for c in GOLDEN_SET if c.expected_ransomware)


def test_redteam_coverage_reflects_payloads() -> None:
    cov = redteam_coverage()
    assert cov.total_payloads == len(PAYLOADS)
    # Every technique on a payload appears in the coverage, summing to >= payloads
    # (a payload can carry multiple techniques).
    assert set(cov.technique_payload_counts) == {t for p in PAYLOADS for t in p.atlas_techniques}
    assert all(v > 0 for v in cov.technique_payload_counts.values())


# --- eval metric parsing --------------------------------------------------


def _eval_record(
    *,
    passed: bool,
    confidence: str = "high",
    elapsed: float = 8.0,
    in_tok: int | None = 1000,
    out_tok: int | None = 200,
    cost: float | None = 0.002,
) -> dict[str, Any]:
    return {
        "case": {"id": "c"},
        "model": "haiku",
        "verdict": {
            "passed": passed,
            "severity_ok": True,
            "cve_recall": 1.0 if passed else 0.0,
        },
        "report": {"confidence": confidence},
        "elapsed_seconds": elapsed,
        "usage": {"input_tokens": in_tok, "output_tokens": out_tok, "cost_usd": cost},
        "conformant": passed,
    }


def test_eval_metrics_from_records_aggregates() -> None:
    records = [
        _eval_record(passed=True, elapsed=8.0),
        _eval_record(passed=False, confidence="low", elapsed=4.0),
        {  # error record: no verdict/report, null usage
            "case": {"id": "err"},
            "model": "haiku",
            "error": "boom",
            "elapsed_seconds": 2.0,
            "usage": {"input_tokens": None, "output_tokens": None, "cost_usd": None},
        },
    ]
    m = eval_metrics_from_records(records, "fallback")
    assert m is not None
    assert m.model == "haiku"
    assert m.cases == 3
    assert m.scored == 2
    assert m.passed == 1
    assert m.conformant == 1
    assert m.mean_input_tokens == 1000.0  # only the two scored records carry tokens
    assert m.total_cost_usd == 0.004
    assert m.latency_p95 is not None
    assert m.calibration_ece is not None


def test_eval_metrics_empty_is_none() -> None:
    assert eval_metrics_from_records([], "m") is None


def test_eval_metrics_model_fallback_when_absent() -> None:
    rec = _eval_record(passed=True)
    del rec["model"]
    m = eval_metrics_from_records([rec], "the-fallback")
    assert m is not None
    assert m.model == "the-fallback"


# --- retrieval / redteam parsing -----------------------------------------


def test_retrieval_metrics_from_json() -> None:
    data = {
        "sampled": 100,
        "top_k": 10,
        "mrr": 0.42,
        "hit_rate_at_1": 0.3,
        "hit_rate_at_3": 0.5,
        "hit_rate_at_5": 0.6,
    }
    m = retrieval_metrics_from_json(data)
    assert m is not None
    assert m.sampled == 100
    assert m.mrr == 0.42


def test_retrieval_metrics_empty_sample_is_none() -> None:
    assert retrieval_metrics_from_json({"sampled": 0}) is None


def test_redteam_metrics_from_json() -> None:
    data = {
        "summary": {"total": 18, "resisted": 17, "resistance_rate": 17 / 18},
        "atlas_breakdown": [
            {"technique": "AML.T0051.000", "total": 10, "resisted": 10, "rate": 1.0},
        ],
    }
    m = redteam_metrics_from_json(data)
    assert m is not None
    assert m.total == 18
    assert m.resisted == 17
    assert len(m.atlas_breakdown) == 1


def test_redteam_metrics_empty_is_none() -> None:
    assert redteam_metrics_from_json({"summary": {"total": 0}}) is None


# --- grounding metric aggregation ------------------------------------------


def _cassette(case_id: str, status: str = "grounded", checked: int = 5) -> Cassette:
    return Cassette(
        case_id=case_id,
        model="claude-sonnet-4-6",
        recorded_at="2026-07-08T10:00:00+00:00",
        staleness_hash="f" * 64,
        elapsed_seconds=60.0,
        messages=[],
        report={},
        outcomes=RecordedOutcomes(
            ssvc={"decision": "act", "rule": "kev"},
            grounding={
                "status": status,
                "claims_checked": checked,
                "supported": checked if status == "grounded" else checked - 1,
                "unbacked": 0 if status == "grounded" else 1,
                "mismatched": 0,
                "unverifiable": 0,
            },
            golden_passed=True,
        ),
    )


def test_grounding_metrics_from_cassettes() -> None:
    m = grounding_metrics_from_cassettes([_cassette("a"), _cassette("b", status="suspect")])
    assert m is not None
    assert m.cases == 2
    assert m.grounded == 1
    assert m.claims_checked == 10
    assert m.supported == 9
    assert m.unbacked == 1
    assert m.model == "claude-sonnet-4-6"
    assert m.recorded_on == "2026-07-08"
    assert m.surface_hash == "f" * 12


def test_grounding_metrics_empty_is_none() -> None:
    assert grounding_metrics_from_cassettes([]) is None


# --- markdown builder -----------------------------------------------------


def _build(**kwargs: Any) -> str:
    defaults: dict[str, Any] = {
        "model": "claude-haiku-4-5-20251001",
        "date": "2026-07-01",
        "commit": "abc1234",
        "golden": golden_coverage(),
        "redteam_cov": redteam_coverage(),
        "ssvc_thresholds": ssvc_thresholds(),
        "eval_metrics": None,
        "retrieval": None,
        "redteam": None,
        "grounding": None,
    }
    defaults.update(kwargs)
    return build_scorecard(**defaults)


def test_build_scorecard_stamps_and_reproduces() -> None:
    md = _build()
    assert "abc1234" in md
    assert "2026-07-01" in md
    assert "claude-haiku-4-5-20251001" in md
    assert "## Reproduce" in md
    assert "make scorecard" in md
    # SSVC thresholds are rendered from the real constants.
    assert "EPSS >= 0.5" in md


def test_build_scorecard_marks_live_sections_pending_without_results() -> None:
    md = _build()
    assert "_pending live run_" in md
    # Deterministic numbers are still present.
    assert f"**{len(PAYLOADS)} payloads**" in md
    assert f"**{len(GOLDEN_SET)} curated cases**" in md
    # No cassettes -> the grounding section points at the recorder.
    assert "make record-cassettes" in md


def test_build_scorecard_renders_grounding_from_cassettes() -> None:
    md = _build(grounding=grounding_metrics_from_cassettes([_cassette("a")]))
    assert "## Grounding (deterministic claim verification)" in md
    assert "- **Reports grounded**: 1/1" in md
    assert "surface `ffffffffffff`" in md


def test_build_scorecard_fills_live_sections() -> None:
    m = eval_metrics_from_records([_eval_record(passed=True)], "haiku")
    retrieval = retrieval_metrics_from_json(
        {
            "sampled": 50,
            "top_k": 10,
            "mrr": 0.5,
            "hit_rate_at_1": 0.4,
            "hit_rate_at_3": 0.6,
            "hit_rate_at_5": 0.7,
        },
    )
    redteam = redteam_metrics_from_json(
        {"summary": {"total": 18, "resisted": 18, "resistance_rate": 1.0}, "atlas_breakdown": []},
    )
    md = _build(eval_metrics=m, retrieval=retrieval, redteam=redteam)
    assert "Resistance: 18/18 (100%)" in md
    assert "MRR**: 0.500" in md
    # Golden pass rate line present (not pending) when eval metrics are supplied.
    assert "Pass rate" in md


# --- model pinning in reproduce / pending commands -----------------------


def test_reproduce_pins_real_model_on_llm_commands() -> None:
    # A full allowlist identifier is a real backend model.
    md = _build(model="claude-sonnet-4-6")
    # Golden-set eval and red-team are LLM-driven -> pinned.
    assert "--json-output data/scorecard/eval.json --model claude-sonnet-4-6" in md
    assert "--json-output data/scorecard/redteam.json --model claude-sonnet-4-6" in md
    # Retrieval eval is embeddings-only -> never pinned.
    assert "--retrieval --json-output data/scorecard/retrieval.json --model" not in md


def test_pending_commands_pin_real_model() -> None:
    # No live metrics: the inline "pending" run commands still carry the pin.
    md = _build(model="claude-sonnet-4-6", eval_metrics=None, redteam=None)
    assert (
        "make eval EVAL_ARGS='--json-output data/scorecard/eval.json "
        "--model claude-sonnet-4-6'" in md
    )
    assert (
        "make redteam REDTEAM_ARGS='--json-output data/scorecard/redteam.json "
        "--model claude-sonnet-4-6'" in md
    )


def test_short_alias_is_pinned() -> None:
    md = _build(model="sonnet")
    assert "--json-output data/scorecard/eval.json --model sonnet" in md


def test_deterministic_only_omits_model_pin() -> None:
    # The CLI default stamp is not a real model -> no --model anywhere.
    md = _build(model="n/a (deterministic-only)")
    assert "--model" not in md


# --- CLI end-to-end (deterministic) --------------------------------------


def test_main_writes_deterministic_scorecard(tmp_path: Any) -> None:
    out = tmp_path / "SCORECARD.md"
    # Point the result-JSON args at nonexistent files -> deterministic-only run.
    rc = main(
        [
            "--output",
            str(out),
            "--eval-json",
            str(tmp_path / "nope-eval.json"),
            "--retrieval-json",
            str(tmp_path / "nope-retrieval.json"),
            "--redteam-json",
            str(tmp_path / "nope-redteam.json"),
            "--cassettes-dir",
            str(tmp_path / "no-cassettes"),
        ],
    )
    assert rc == 0
    md = out.read_text(encoding="utf-8")
    assert "# Scorecard" in md
    assert "_pending live run_" in md
    assert f"**{len(PAYLOADS)} payloads**" in md
    # Default stamp is deterministic-only -> no bogus --model in the commands.
    assert "--model" not in md
