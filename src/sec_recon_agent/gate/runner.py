"""In-process orchestrator: SBOM -> OSV -> KEV/EPSS/exploit -> SSVC -> policy.

Deterministic and LLM-free by design: this runs on every pull request of a
consumer repo, so it must be reproducible, bill nothing, and leave no prompt
surface for the SBOM content to attack. The chain reuses the MCP tool
functions directly (the FastMCP decorator returns the original callables) -
same typed models, same host-locking, same caps as the agent path.

Direct calls bypass the MCP argument-validation layer, so the one input this
module receives from outside (the SBOM text) is size-guarded here before
parsing.

Feed posture, per feed:
- KEV is the Act driver: a gate that cannot see the KEV catalog must not
  pass, so any KEV failure raises instead of degrading.
- EPSS / exploit failures degrade per-CVE and are recorded on the finding's
  coverage; `strict` mode turns those gaps into a failing gate.
- exploit_check is skipped for CVEs already on KEV: the decision is already
  Act and cannot escalate, and the GitHub search arm is rate-limited
  (10 req/min) - on a large SBOM that skip is the difference between
  seconds and tens of minutes.

Enrichment is deduplicated per CVE across components; the first lookup per
locally-cached feed (KEV catalog, ExploitDB CSV) runs alone to warm the
cache before the parallel fan-out, so concurrent first-calls never race the
download.
"""

import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import cast, get_args

from sec_recon_agent.agent.schema import SsvcBasis, SsvcDecision
from sec_recon_agent.agent.ssvc import (
    SsvcSignals,
    assess_from_signals,
    decide_for_signals,
    decision_rank,
)
from sec_recon_agent.gate.models import (
    FailOn,
    FeedCoverage,
    FindingCoverage,
    GateFinding,
    GatePolicy,
    GateReport,
    SkippedComponent,
    SkipReason,
)
from sec_recon_agent.gate.severity import severity_from_token
from sec_recon_agent.mcp_server.errors import (
    EpssError,
    ExploitsError,
    KevError,
    OsvError,
    SbomError,
)
from sec_recon_agent.mcp_server.models import (
    EpssScore,
    EpssStatus,
    ExploitArmStatus,
    ExploitCheck,
    KevCheck,
    OsvEcosystem,
    OsvScanResult,
    OsvVuln,
    SbomComponent,
)
from sec_recon_agent.mcp_server.tools.epss import epss_score
from sec_recon_agent.mcp_server.tools.exploits import exploit_check
from sec_recon_agent.mcp_server.tools.kev import kev_check
from sec_recon_agent.mcp_server.tools.osv import osv_lookup
from sec_recon_agent.mcp_server.tools.sbom import SBOM_MAX_CONTENT_BYTES, sbom_ingest
from sec_recon_agent.version import package_version

_OSV_ECOSYSTEMS: frozenset[str] = frozenset(get_args(OsvEcosystem))
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_FAIL_ON_DECISION: dict[str, SsvcDecision] = {
    "act": SsvcDecision.ACT,
    "attend": SsvcDecision.ATTEND,
    "track_star": SsvcDecision.TRACK_STAR,
}


def _cve_alias(vuln: OsvVuln) -> str | None:
    """The CVE id to enrich with, from the advisory id or its aliases."""
    if _CVE_RE.match(vuln.id):
        return vuln.id
    for alias in vuln.aliases:
        if _CVE_RE.match(alias):
            return alias
    return None


def _dedupe_advisories(vulns: list[OsvVuln]) -> list[tuple[OsvVuln, str | None]]:
    """Fold advisories that describe the same vulnerability on one component.

    OSV routinely returns a GHSA and a PYSEC record aliasing the same CVE;
    emitting both would duplicate every downstream artifact (two SARIF
    results collapsing onto one fingerprint, two VEX statements for one
    vulnerability). Group by the effective id (CVE alias when present, else
    the advisory's own id), pick the richest record deterministically
    (has-severity, then has-fixed, then lexicographic id), and merge what
    the primary lacks: the fixed version from the best sibling and the
    folded advisory ids into `aliases` so nothing disappears silently.
    """
    groups: dict[str, list[OsvVuln]] = {}
    for vuln in vulns:
        key = _cve_alias(vuln) or vuln.id
        groups.setdefault(key, []).append(vuln)

    out: list[tuple[OsvVuln, str | None]] = []
    for key, group in groups.items():
        ranked = sorted(group, key=lambda v: (v.severity is None, v.fixed is None, v.id))
        primary = ranked[0]
        fixed = next((v.fixed for v in ranked if v.fixed is not None), None)
        merged_aliases = list(primary.aliases)
        for sibling in group:
            for extra in (sibling.id, *sibling.aliases):
                if extra != primary.id and extra not in merged_aliases:
                    merged_aliases.append(extra)
        if fixed != primary.fixed or merged_aliases != primary.aliases:
            primary = primary.model_copy(update={"fixed": fixed, "aliases": merged_aliases[:20]})
        out.append((primary, key if _CVE_RE.match(key) else None))
    return out


async def _gather_keyed[T](
    keys: list[str],
    fn: Callable[[str], Awaitable[T]],
    *,
    concurrency: int,
    warm_first: bool,
) -> dict[str, T | Exception]:
    """Run `fn` once per key; exceptions are captured per key, not raised.

    `warm_first` runs the first key alone before the fan-out so a feed with a
    lazily-downloaded local cache is primed exactly once.
    """
    results: dict[str, T | Exception] = {}
    if not keys:
        return results
    remaining = keys
    if warm_first:
        first = keys[0]
        try:
            results[first] = await fn(first)
        except Exception as exc:  # re-raised selectively by callers
            results[first] = exc
        remaining = keys[1:]

    sem = asyncio.Semaphore(concurrency)

    async def one(key: str) -> None:
        async with sem:
            try:
                results[key] = await fn(key)
            except Exception as exc:  # re-raised selectively by callers
                results[key] = exc

    await asyncio.gather(*(one(k) for k in remaining))
    return results


def _partition(
    components: list[SbomComponent],
) -> tuple[list[SbomComponent], list[SkippedComponent]]:
    eligible: list[SbomComponent] = []
    skipped: list[SkippedComponent] = []
    for comp in components:
        reason: SkipReason | None = None
        if comp.version is None:
            reason = SkipReason.NO_VERSION
        elif comp.ecosystem is None:
            reason = SkipReason.NO_ECOSYSTEM
        elif comp.ecosystem not in _OSV_ECOSYSTEMS:
            reason = SkipReason.UNSUPPORTED_ECOSYSTEM
        if reason is None:
            eligible.append(comp)
        else:
            skipped.append(
                SkippedComponent(
                    name=comp.name,
                    version=comp.version,
                    ecosystem=comp.ecosystem,
                    reason=reason,
                )
            )
    return eligible, skipped


def _epss_coverage(result: EpssScore | Exception | None) -> FeedCoverage:
    if result is None:
        return FeedCoverage.NOT_APPLICABLE
    if isinstance(result, Exception):
        return FeedCoverage.ERROR
    if result.status is EpssStatus.FOUND:
        return FeedCoverage.OK
    if result.status is EpssStatus.NOT_FOUND:
        return FeedCoverage.NOT_FOUND
    return FeedCoverage.ERROR


def _exploit_coverage(
    result: ExploitCheck | Exception | None,
    *,
    cve_id: str | None,
    skipped_kev_act: bool,
) -> FeedCoverage:
    if cve_id is None:
        return FeedCoverage.NOT_APPLICABLE
    if skipped_kev_act:
        return FeedCoverage.SKIPPED
    if isinstance(result, Exception) or result is None:
        return FeedCoverage.ERROR
    # The tool no longer raises for one failing source: it reports per arm.
    # An arm in ERROR is a coverage gap even when the other arm found
    # something; an arm SKIPPED by configuration (no GITHUB_TOKEN) is honest
    # partial coverage.
    if not result.arms_conclusive():
        return FeedCoverage.ERROR
    if result.github is ExploitArmStatus.SKIPPED:
        return FeedCoverage.DEGRADED
    return FeedCoverage.OK


def _build_finding(
    comp: SbomComponent,
    vuln: OsvVuln,
    cve_id: str | None,
    kev: KevCheck | None,
    epss: EpssScore | Exception | None,
    exploit: ExploitCheck | Exception | None,
    *,
    exploit_skipped: bool,
) -> GateFinding:
    severity, cvss_score = severity_from_token(vuln.severity)
    in_kev = kev.in_catalog if kev is not None else False
    epss_probability = None
    epss_percentile = None
    if isinstance(epss, EpssScore) and epss.status is EpssStatus.FOUND:
        epss_probability = epss.probability
        epss_percentile = epss.percentile
    exploits_public = isinstance(exploit, ExploitCheck) and exploit.has_public_exploit

    signals = SsvcSignals(
        in_kev=in_kev,
        known_ransomware=kev.known_ransomware_use if kev is not None else None,
        exploit_public=exploits_public,
        epss_probability=epss_probability,
        epss_percentile=epss_percentile,
        severity=severity,
    )
    decision, rule = decide_for_signals(signals)

    reference_url = (
        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if cve_id is not None
        else f"https://osv.dev/vulnerability/{vuln.id}"
    )
    coverage = FindingCoverage(
        kev=FeedCoverage.OK if cve_id is not None else FeedCoverage.NOT_APPLICABLE,
        epss=_epss_coverage(epss),
        exploits=_exploit_coverage(exploit, cve_id=cve_id, skipped_kev_act=exploit_skipped),
    )
    # comp.version is non-None for every eligible component by construction.
    return GateFinding(
        component_name=comp.name,
        component_version=comp.version or "",
        component_ecosystem=comp.ecosystem or "",
        component_purl=comp.purl,
        osv_id=vuln.id,
        cve_id=cve_id,
        aliases=vuln.aliases,
        summary=vuln.summary,
        severity=severity,
        cvss_score=cvss_score,
        fixed_version=vuln.fixed,
        reference_url=reference_url,
        in_kev=in_kev,
        kev_due_date=kev.due_date if kev is not None else None,
        known_ransomware_use=kev.known_ransomware_use if kev is not None else None,
        exploits_public=exploits_public,
        epss_probability=epss_probability,
        epss_percentile=epss_percentile,
        decision=decision,
        rule=rule,
        coverage=coverage,
    )


def _evaluate_policy(
    findings: list[GateFinding],
    skipped: list[SkippedComponent],
    *,
    fail_on: FailOn,
    strict: bool,
) -> GatePolicy:
    coverage_gaps = sum(1 for s in skipped if s.reason is SkipReason.OSV_ERROR) + sum(
        1 for f in findings if FeedCoverage.ERROR in (f.coverage.epss, f.coverage.exploits)
    )
    triggered: list[str] = []
    if fail_on != "never":
        threshold = decision_rank(_FAIL_ON_DECISION[fail_on])
        seen: set[str] = set()
        for f in findings:
            vuln_id = f.cve_id or f.osv_id
            if decision_rank(f.decision) >= threshold and vuln_id not in seen:
                seen.add(vuln_id)
                triggered.append(vuln_id)
    passed = not triggered and not (strict and coverage_gaps > 0)
    return GatePolicy(
        fail_on=fail_on,
        strict=strict,
        triggered=triggered,
        coverage_gaps=coverage_gaps,
        passed=passed,
    )


async def run_gate(
    content: str,
    *,
    fail_on: FailOn = "act",
    strict: bool = False,
    concurrency: int = 8,
) -> GateReport:
    """Scan one SBOM document and return the full gate verdict.

    Raises SbomError for an unusable SBOM and KevError when the KEV catalog
    is unavailable (both map to infrastructure failures, not gate failures).
    OSV / EPSS / exploit errors degrade per component / per CVE and surface
    in the report's coverage fields.
    """
    if len(content) > SBOM_MAX_CONTENT_BYTES:
        raise SbomError(
            f"SBOM content exceeds the {SBOM_MAX_CONTENT_BYTES} byte cap enforced at the "
            "tool boundary"
        )
    ingested = sbom_ingest(content)
    eligible, skipped = _partition(ingested.components)

    async def _lookup(comp: SbomComponent) -> OsvScanResult:
        # Version/ecosystem non-None and OSV-valid by _partition construction;
        # narrow them to the tool's typed signature.
        return await osv_lookup(
            comp.name, cast(OsvEcosystem, comp.ecosystem), cast(str, comp.version)
        )

    sem = asyncio.Semaphore(concurrency)
    osv_results: dict[int, OsvScanResult | OsvError] = {}

    async def _one_lookup(idx: int, comp: SbomComponent) -> None:
        async with sem:
            try:
                osv_results[idx] = await _lookup(comp)
            except OsvError as exc:
                osv_results[idx] = exc

    await asyncio.gather(*(_one_lookup(i, c) for i, c in enumerate(eligible)))

    scanned: list[tuple[SbomComponent, OsvScanResult]] = []
    for idx, comp in enumerate(eligible):
        result = osv_results[idx]
        if isinstance(result, OsvScanResult):
            scanned.append((comp, result))
        else:
            skipped.append(
                SkippedComponent(
                    name=comp.name,
                    version=comp.version,
                    ecosystem=comp.ecosystem,
                    reason=SkipReason.OSV_ERROR,
                    detail=str(result)[:500],
                )
            )

    # (component, advisory, cve alias) triples plus the unique CVE set that
    # actually needs enrichment - advisories are folded per component first
    # (GHSA/PYSEC mirrors of one CVE become one finding) and each feed is
    # asked once per CVE no matter how many components share it.
    triples: list[tuple[SbomComponent, OsvVuln, str | None]] = []
    unique_cves: list[str] = []
    seen_cves: set[str] = set()
    for comp, result in scanned:
        for vuln, cve_id in _dedupe_advisories(result.vulnerabilities):
            triples.append((comp, vuln, cve_id))
            if cve_id is not None and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_cves.append(cve_id)

    kev_results = await _gather_keyed(
        unique_cves, kev_check, concurrency=concurrency, warm_first=True
    )
    for outcome in kev_results.values():
        if isinstance(outcome, KevError):
            raise outcome
        if isinstance(outcome, Exception):
            raise outcome

    epss_results: dict[str, EpssScore | Exception] = {}
    raw_epss = await _gather_keyed(
        unique_cves, epss_score, concurrency=concurrency, warm_first=False
    )
    for cve_id, epss_outcome in raw_epss.items():
        if isinstance(epss_outcome, Exception) and not isinstance(epss_outcome, EpssError):
            raise epss_outcome
        epss_results[cve_id] = epss_outcome

    kev_act = {
        cve_id
        for cve_id, outcome in kev_results.items()
        if isinstance(outcome, KevCheck) and outcome.in_catalog
    }
    exploit_targets = [c for c in unique_cves if c not in kev_act]
    exploit_results: dict[str, ExploitCheck | Exception] = {}
    raw_exploits = await _gather_keyed(
        exploit_targets, exploit_check, concurrency=concurrency, warm_first=True
    )
    for cve_id, exploit_outcome in raw_exploits.items():
        if isinstance(exploit_outcome, Exception) and not isinstance(
            exploit_outcome, ExploitsError
        ):
            raise exploit_outcome
        exploit_results[cve_id] = exploit_outcome

    findings: list[GateFinding] = []
    for comp, vuln, cve_id in triples:
        kev = None
        if cve_id is not None:
            kev_outcome = kev_results[cve_id]
            kev = kev_outcome if isinstance(kev_outcome, KevCheck) else None
        findings.append(
            _build_finding(
                comp,
                vuln,
                cve_id,
                kev,
                epss_results.get(cve_id) if cve_id is not None else None,
                exploit_results.get(cve_id) if cve_id is not None else None,
                exploit_skipped=cve_id in kev_act,
            )
        )

    # Every signal above was read from a typed tool result (or is an honest
    # absence recorded in `coverage`); nothing on this path comes from a model,
    # so the verdict's basis is evidence by construction.
    ssvc = assess_from_signals(
        (
            (
                f.cve_id or f.osv_id,
                SsvcSignals(
                    in_kev=f.in_kev,
                    known_ransomware=f.known_ransomware_use,
                    exploit_public=f.exploits_public,
                    epss_probability=f.epss_probability,
                    epss_percentile=f.epss_percentile,
                    severity=f.severity,
                ),
            )
            for f in findings
        ),
        basis=SsvcBasis.EVIDENCE,
    )
    policy = _evaluate_policy(findings, skipped, fail_on=fail_on, strict=strict)

    return GateReport(
        sbom_format=ingested.format,
        components_total=ingested.component_count,
        components_scanned=len(scanned),
        sbom_truncated=ingested.truncated,
        skipped=skipped,
        findings=findings,
        ssvc=ssvc,
        policy=policy,
        tool_version=package_version(),
    )
