"""Record-replay merge gate.

Replays every committed cassette (tests/cassettes/) through the CURRENT
deterministic pipeline and asserts it reproduces the outcomes computed at
record time. Runs in the fast suite, so it is part of the required CI
check: a PR that changes trajectory extraction, grounding, SSVC, the
report schema, or the golden scorer gets validated against real recorded
LLM behavior at zero LLM cost.

The staleness test hard-fails when the LLM-visible surface (system prompt,
MCP tool schemas, TriageReport schema) no longer matches the hash stamped
in the cassettes: the frozen trajectories describe a model that saw a
DIFFERENT surface, so their replay would prove nothing. Re-record with
`make record-cassettes` (bills the LLM; see CONTRIBUTING.md on
behavior-bearing text).
"""

from pathlib import Path

import pytest
from pydantic_ai.messages import ModelMessagesTypeAdapter

from sec_recon_agent.agent.grounding import verify_grounding
from sec_recon_agent.agent.schema import TriageReport
from sec_recon_agent.agent.ssvc import assess_ssvc
from sec_recon_agent.agent.trajectory import extract_tool_invocations
from sec_recon_agent.eval.cassette import Cassette, load_cassette, staleness_hash
from sec_recon_agent.eval.golden_set import GOLDEN_SET
from sec_recon_agent.eval.scorer import score

CASSETTES_DIR = Path(__file__).resolve().parents[1] / "cassettes"
CASSETTE_PATHS = sorted(CASSETTES_DIR.glob("*.json"))

RERECORD_HINT = (
    "the LLM-visible surface (system prompt / tool schemas / output schema) changed: "
    "re-record with `make record-cassettes` (bills the LLM)"
)


@pytest.fixture(scope="module")
def current_surface_hash() -> str:
    return staleness_hash()


def test_cassettes_exist() -> None:
    """The gate must never pass vacuously because the fixtures vanished."""
    assert CASSETTE_PATHS, f"no cassettes in {CASSETTES_DIR}; run `make record-cassettes`"


def test_cassettes_cover_the_golden_set() -> None:
    """One cassette per golden case, no orphans in either direction.

    A new golden case requires a recording; a cassette whose case was
    removed or renamed is dead weight that would silently stop gating.
    """
    golden_ids = {case.id for case in GOLDEN_SET}
    cassette_ids = {path.stem for path in CASSETTE_PATHS}
    assert cassette_ids == golden_ids, (
        f"missing cassettes: {sorted(golden_ids - cassette_ids)}; "
        f"orphaned cassettes: {sorted(cassette_ids - golden_ids)}"
    )


@pytest.fixture(
    scope="module",
    params=CASSETTE_PATHS,
    ids=[path.stem for path in CASSETTE_PATHS],
)
def cassette(request: pytest.FixtureRequest) -> Cassette:
    loaded = load_cassette(request.param)
    assert loaded.case_id == request.param.stem, "cassette filename != case_id"
    return loaded


def test_cassette_is_fresh(cassette: Cassette, current_surface_hash: str) -> None:
    assert cassette.staleness_hash == current_surface_hash, RERECORD_HINT


def test_replay_reproduces_recorded_outcomes(cassette: Cassette) -> None:
    """Current deterministic pipeline over frozen behavior == recorded outcomes."""
    report = TriageReport.model_validate(cassette.report)
    # The recorded report is the RAW model output: the leave-null contract
    # must hold or the cassette was recorded from a stamped report.
    assert report.ssvc is None, "cassette report already carries an ssvc stamp"
    assert report.grounding is None, "cassette report already carries a grounding stamp"

    messages = ModelMessagesTypeAdapter.validate_python(cassette.messages)
    invocations = extract_tool_invocations(messages)
    assert invocations, "no tool invocations extracted from a real trajectory"

    ssvc = assess_ssvc(report.cves, invocations)
    grounding = verify_grounding(report, invocations)

    assert ssvc.model_dump(mode="json") == cassette.outcomes.ssvc, (
        "SSVC drift vs recording: intentional rule change? re-record"
    )
    assert grounding.model_dump(mode="json") == cassette.outcomes.grounding, (
        "grounding drift vs recording: intentional verifier change? re-record"
    )


def test_replay_passes_the_golden_scorer(cassette: Cassette) -> None:
    case = next(c for c in GOLDEN_SET if c.id == cassette.case_id)
    report = TriageReport.model_validate(cassette.report)
    invocations = extract_tool_invocations(
        ModelMessagesTypeAdapter.validate_python(cassette.messages),
    )
    stamped = report.model_copy(
        update={
            "ssvc": assess_ssvc(report.cves, invocations),
            "grounding": verify_grounding(report, invocations),
        },
    )
    verdict = score(case, stamped)
    assert cassette.outcomes.golden_passed, "cassette was recorded failing (--allow-failing?)"
    assert verdict.passed, f"golden regression on replay: {verdict.notes}"
