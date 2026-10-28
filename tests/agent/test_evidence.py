"""Tests for the shared trajectory evidence index."""

from sec_recon_agent.agent.evidence import build_evidence
from sec_recon_agent.agent.trajectory import ToolInvocation

CVE = "CVE-2021-44228"


def _invocation(
    tool: str,
    content: object,
    *,
    outcome: str = "success",
    args: dict[str, object] | None = None,
) -> ToolInvocation:
    return ToolInvocation(
        tool_name=tool,
        tool_call_id=f"{tool}-1",
        args=args if args is not None else {"cve_id": CVE},
        content=content,
        outcome=outcome,  # type: ignore[arg-type]
    )


def test_only_successful_returns_are_indexed() -> None:
    evidence = build_evidence(
        [
            _invocation("kev_check", {"cve_id": CVE, "in_catalog": True}),
            _invocation("exploit_check", None, outcome="failed"),
            _invocation("epss_score", None, outcome="no_return"),
        ],
    )
    assert [k.in_catalog for k in evidence.kev[CVE]] == [True]
    assert evidence.exploits == {}
    assert evidence.epss == {}
    assert evidence.unparsed == {}


def test_unparseable_success_is_kept_aside_not_dropped() -> None:
    evidence = build_evidence([_invocation("kev_check", "upstream unavailable")])
    assert evidence.kev == {}
    assert [inv.tool_name for inv in evidence.unparsed["kev_check"]] == ["kev_check"]
    # The queried id still counts as mentioned: the tool was asked about it.
    assert CVE in evidence.mentioned_cve_ids


def test_model_authored_args_count_as_mentions_only() -> None:
    evidence = build_evidence([_invocation("patch_lookup", None, args={"cve_id": CVE})])
    assert CVE in evidence.mentioned_cve_ids
    assert evidence.kev == {} and evidence.epss == {} and evidence.exploits == {}
