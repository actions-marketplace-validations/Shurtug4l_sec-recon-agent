"""Agent output contracts. The public surface returned to API clients."""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field, HttpUrl

from sec_recon_agent.mcp_server.models import AttackTechnique

CveIdStr = Annotated[
    str,
    Field(pattern=r"^CVE-\d{4}-\d{4,}$", examples=["CVE-2021-41773"]),
]


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SsvcDecision(StrEnum):
    """CISA SSVC outcome vocabulary (Stakeholder-Specific Vulnerability
    Categorization), ordered most- to least-urgent.

    ACT: remediate out-of-cycle, as fast as possible.
    ATTEND: remediate sooner than standard timelines; needs supervisor attention.
    TRACK_STAR: remediate within standard timelines, but monitor closely for
        signal changes that would escalate the decision.
    TRACK: no action beyond standard update timelines.

    This project derives the decision deterministically from the signals the
    agent actually collects (KEV / EPSS / public-exploit / ransomware / CVSS).
    It is SSVC-informed, not the full CISA tree: the CISA "Automatable" and
    "Mission & Well-being" decision points are approximated (EPSS stands in for
    exploitation likelihood / automatability; deployment-specific mission
    context is out of scope for a stateless triage tool). See agent/ssvc.py.
    """

    ACT = "Act"
    ATTEND = "Attend"
    TRACK_STAR = "Track*"
    TRACK = "Track"


class SsvcBasis(StrEnum):
    """Where the signals behind the SSVC verdict came from.

    EVIDENCE: every signal was read from a structured tool return captured in
        the run's trajectory, or from an evidence-backed absence (an EPSS
        "not_found" answer, a CVE record with no CVSS score). The model's
        report fields were not consulted.
    MIXED: at least one signal had no usable tool evidence (the feed was never
        called, failed, or returned something unparseable) and was taken from
        the report as the model wrote it. `unverified_signals` names each one.
    REPORT: no trajectory was available, so every signal came from the
        report. Reproducible from the same report, but not independent of the
        model. The SBOM gate never produces REPORT: it feeds typed tool
        results directly, so its basis is always EVIDENCE.
    """

    EVIDENCE = "evidence"
    MIXED = "mixed"
    REPORT = "report"


class SsvcAssessment(BaseModel):
    """Deterministic prioritization verdict stamped onto the report server-side.

    NOT produced by the LLM: computed by agent/ssvc.py from the signals the
    tools returned during the run (the trajectory evidence), so the verdict is
    reproducible from the same inputs and independent of what the model wrote
    in the report. The LLM echoes the resulting decision in
    `recommended_action` prose; this structured field is the authoritative
    machine-readable form and the one downstream consumers (scorecard, audit,
    exports) trust. `basis` says how much of it rests on tool evidence.
    """

    decision: SsvcDecision
    rule: str = Field(
        max_length=64,
        description="Stable identifier of the decision rule that fired (for audit / regression).",
    )
    rationale: str = Field(
        max_length=500,
        description="One-sentence human explanation of why this decision was reached.",
    )
    driving_cve: CveIdStr | None = Field(
        default=None,
        description="The CVE whose signals drove the report-level decision, when applicable.",
    )
    basis: SsvcBasis = Field(
        description=(
            "Provenance of the signals the decision was computed from: tool "
            "evidence, mixed (some taken from the report), or report only."
        ),
    )
    unverified_signals: list[str] = Field(
        default_factory=list,
        max_length=50,
        description=(
            "Signals taken from the report for lack of tool evidence, as "
            '"<CVE-ID>:<kev|exploit|epss|severity>". Empty unless basis is mixed.'
        ),
    )


class SignalStatus(StrEnum):
    """Per-feed coverage status, so the report is honest about what it checked.

    FOUND: the feed was queried and returned data for the CVE.
    NOT_FOUND: the feed was queried successfully but has no entry for the CVE
        (a real answer, not a failure: e.g. a CVE absent from the EPSS dataset).
    ERROR: the feed could not be consulted (timeout, 5xx, malformed response).
    NOT_QUERIED: the feed was not consulted for this triage.
    """

    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    NOT_QUERIED = "not_queried"


class FeedStatus(BaseModel):
    """Coverage of one external signal feed for this triage."""

    feed: str = Field(
        max_length=40,
        description="Feed identifier: nvd | kev | epss | exploit | osv | attack | semantic_search.",
    )
    status: SignalStatus
    detail: str | None = Field(
        default=None,
        max_length=200,
        description="Optional short note (e.g. which CVE was not_found, or the error class).",
    )


class GroundingStatus(StrEnum):
    """Report-level outcome of the post-run grounding verification.

    GROUNDED: every checked claim is supported by an actual tool result
        (vacuously true when the report makes no checkable claims).
    SUSPECT: at least one claim is unbacked or contradicts a tool result.
    NOT_EVALUATED: the run's message history was unavailable, so no
        verification could be performed (an honest skip, not a pass).
    """

    GROUNDED = "grounded"
    SUSPECT = "suspect"
    NOT_EVALUATED = "not_evaluated"


class GroundingClaimStatus(StrEnum):
    """Outcome of verifying one tool-derived claim in the report.

    SUPPORTED: a successful tool return backs the claim.
    UNBACKED: a positive claim with no backing tool output (fabrication signal).
    MISMATCH: the claim contradicts what a tool actually returned.
    UNVERIFIABLE: relevant tool output existed but could not be parsed back
        into its typed model, so the claim cannot be judged either way.
    """

    SUPPORTED = "supported"
    UNBACKED = "unbacked"
    MISMATCH = "mismatch"
    UNVERIFIABLE = "unverifiable"


class GroundingClaim(BaseModel):
    """One non-supported claim surfaced by the grounding verifier."""

    subject: str = Field(
        max_length=40,
        description='What the claim is about: a CVE id, an ATT&CK technique id, or "report".',
    )
    field: str = Field(
        max_length=40,
        description="The report field the claim lives in (e.g. in_kev_catalog, cvss_v3_score).",
    )
    status: GroundingClaimStatus
    detail: str | None = Field(
        default=None,
        max_length=200,
        description='Short evidence note (e.g. "kev_check returned in_catalog=false").',
    )


class GroundingAssessment(BaseModel):
    """Deterministic post-hoc verification of the report's tool-derived claims.

    NOT produced by the LLM: computed by agent/grounding.py against the tool
    returns captured from the run's message history, then stamped onto the
    report server-side (same authority pattern as `ssvc`). `findings` carries
    only non-supported claims so the payload stays bounded; the counts are
    always complete.
    """

    status: GroundingStatus
    claims_checked: int = Field(default=0, ge=0)
    supported: int = Field(default=0, ge=0)
    unbacked: int = Field(default=0, ge=0)
    mismatched: int = Field(default=0, ge=0)
    unverifiable: int = Field(default=0, ge=0)
    findings: list[GroundingClaim] = Field(default_factory=list, max_length=40)
    truncated: bool = Field(
        default=False,
        description="True when findings hit the cap; the counts remain complete.",
    )


class CVEReference(BaseModel):
    """A single CVE included in the triage report."""

    cve_id: CveIdStr
    summary: str = Field(max_length=1000)
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: Severity
    exploits_public: bool
    affected_products: list[str] = Field(default_factory=list, max_length=20)
    nvd_url: HttpUrl
    in_kev_catalog: bool = Field(
        default=False,
        description=(
            "True when CISA KEV reports the CVE as actively exploited "
            "in the wild. Highest-priority remediation signal."
        ),
    )
    kev_due_date: str | None = Field(
        default=None,
        description=(
            "ISO date by which CISA requires federal agencies to remediate. "
            "Set only when in_kev_catalog is True."
        ),
    )
    known_ransomware_use: bool | None = Field(
        default=None,
        description=(
            "CISA-reported association with known ransomware campaigns. "
            "None when KEV did not provide the flag."
        ),
    )
    epss_probability: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "EPSS probability of exploitation in the next 30 days. "
            "None when the CVE is not in the EPSS dataset."
        ),
    )
    epss_percentile: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="EPSS rank relative to all scored CVEs.",
    )


class TriageReport(BaseModel):
    """Structured agent output. Single source of truth returned over SSE."""

    summary: str = Field(max_length=500)
    severity: Severity
    confidence: Confidence
    recommended_action: str = Field(max_length=500)
    cves: list[CVEReference] = Field(default_factory=list, max_length=10)
    attack_techniques: list[AttackTechnique] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "MITRE ATT&CK techniques mapped from the CVEs' CWE IDs via the "
            "attack_mapping tool. Empty when no CWEs matched the curated table."
        ),
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
        description="Ordered audit log of tool calls and intermediate decisions",
    )
    ssvc: SsvcAssessment | None = Field(
        default=None,
        description=(
            "Deterministic SSVC prioritization verdict (Act / Attend / Track* / "
            "Track). Computed server-side from the CVE signals AFTER the model "
            "returns; leave this null. The recommended_action prose should echo "
            "the decision."
        ),
    )
    signal_coverage: list[FeedStatus] = Field(
        default_factory=list,
        max_length=16,
        description=(
            "Per-feed coverage honesty: for each external feed consulted, whether "
            "it returned data (found), was queried but had no entry (not_found), "
            "or could not be reached (error). Never imply a signal was checked "
            "clean when the feed errored or was not queried."
        ),
    )
    grounding: GroundingAssessment | None = Field(
        default=None,
        description=(
            "Deterministic grounding verification computed server-side AFTER "
            "the model returns, by checking tool-derived claims against actual "
            "tool results; leave this null."
        ),
    )
