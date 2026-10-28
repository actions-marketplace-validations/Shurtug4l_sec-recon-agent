"""Orchestrator tests with the feed tools stubbed at the runner boundary.

The tool contracts themselves are covered by the respx suites under
tests/mcp_server/; here the fakes return (or raise) typed results so the
tests pin the orchestration logic: partitioning, dedup, the KEV-Act
exploit short-circuit, coverage honesty, and the fail-on policy.
"""

import json
from typing import Any

import pytest
from pydantic import SecretStr

import sec_recon_agent.gate.runner as runner_mod
from sec_recon_agent.agent.schema import Severity, SsvcBasis, SsvcDecision
from sec_recon_agent.config import settings
from sec_recon_agent.gate.models import FeedCoverage, SkipReason
from sec_recon_agent.gate.runner import run_gate
from sec_recon_agent.mcp_server.errors import (
    EpssRequestError,
    KevDownloadError,
    OsvServerError,
    SbomError,
)
from sec_recon_agent.mcp_server.models import (
    EpssScore,
    EpssStatus,
    ExploitArmStatus,
    ExploitCheck,
    KevCheck,
    OsvScanResult,
    OsvVuln,
)
from sec_recon_agent.mcp_server.tools.sbom import SBOM_MAX_CONTENT_BYTES

V31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
V31_HIGH = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 7.4

Calls = dict[str, list[Any]]
Responses = dict[str, dict[str, Any]]


def osv_result(pkg: str, eco: str, ver: str, vulns: list[OsvVuln]) -> OsvScanResult:
    return OsvScanResult(
        package=pkg,
        ecosystem=eco,
        version=ver,
        is_vulnerable=bool(vulns),
        vulnerabilities=vulns,
    )


def vuln(
    vuln_id: str,
    *,
    aliases: list[str] | None = None,
    severity: str | None = V31_CRITICAL,
    fixed: str | None = "9.9.9",
) -> OsvVuln:
    return OsvVuln(id=vuln_id, aliases=aliases or [], severity=severity, fixed=fixed)


def kev_hit(cve: str, *, ransomware: bool = False) -> KevCheck:
    return KevCheck(
        cve_id=cve, in_catalog=True, known_ransomware_use=ransomware, due_date="2026-01-01"
    )


def epss_found(cve: str, probability: float, percentile: float) -> EpssScore:
    return EpssScore(
        cve_id=cve, status=EpssStatus.FOUND, probability=probability, percentile=percentile
    )


@pytest.fixture
def feeds(monkeypatch: pytest.MonkeyPatch) -> tuple[Calls, Responses]:
    """Stub the four feed tools; per-key responses configurable, calls recorded."""
    calls: Calls = {"osv": [], "kev": [], "epss": [], "exploit": []}
    responses: Responses = {"osv": {}, "kev": {}, "epss": {}, "exploit": {}}

    def _resolve(feed: str, key: str, default: Any) -> Any:
        out = responses[feed].get(key, default)
        if isinstance(out, Exception):
            raise out
        return out

    async def fake_osv(name: str, ecosystem: str, version: str) -> OsvScanResult:
        calls["osv"].append((name, ecosystem, version))
        return _resolve("osv", name, osv_result(name, ecosystem, version, []))

    async def fake_kev(cve_id: str) -> KevCheck:
        calls["kev"].append(cve_id)
        return _resolve("kev", cve_id, KevCheck(cve_id=cve_id, in_catalog=False))

    async def fake_epss(cve_id: str) -> EpssScore:
        calls["epss"].append(cve_id)
        return _resolve("epss", cve_id, EpssScore(cve_id=cve_id, status=EpssStatus.NOT_FOUND))

    async def fake_exploit(cve_id: str) -> ExploitCheck:
        calls["exploit"].append(cve_id)
        return _resolve(
            "exploit",
            cve_id,
            ExploitCheck(
                cve_id=cve_id,
                has_public_exploit=False,
                exploit_db=ExploitArmStatus.NOT_FOUND,
                # Mirrors the real tool: the GitHub arm is skipped by
                # configuration without a token, consulted with one.
                github=(
                    ExploitArmStatus.SKIPPED
                    if settings.github_token is None
                    else ExploitArmStatus.NOT_FOUND
                ),
            ),
        )

    monkeypatch.setattr(runner_mod, "osv_lookup", fake_osv)
    monkeypatch.setattr(runner_mod, "kev_check", fake_kev)
    monkeypatch.setattr(runner_mod, "epss_score", fake_epss)
    monkeypatch.setattr(runner_mod, "exploit_check", fake_exploit)
    monkeypatch.setattr(settings, "github_token", None)
    return calls, responses


class TestKevActPath:
    async def test_kev_act_short_circuits_exploit_check(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        calls, responses = feeds
        responses["osv"]["liba"] = osv_result(
            "liba", "PyPI", "1.0", [vuln("CVE-2021-0001", fixed="1.1")]
        )
        responses["kev"]["CVE-2021-0001"] = kev_hit("CVE-2021-0001", ransomware=True)

        report = await run_gate("liba==1.0\nlibb==2.0\n")

        assert calls["exploit"] == []  # decision already Act; rate-limited arm skipped
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.in_kev is True
        assert f.decision is SsvcDecision.ACT
        assert f.rule == "ransomware"
        assert f.coverage.exploits is FeedCoverage.SKIPPED
        assert f.coverage.kev is FeedCoverage.OK
        assert report.ssvc.decision is SsvcDecision.ACT
        assert report.ssvc.driving_cve == "CVE-2021-0001"
        # The gate feeds typed tool results: never the model's word.
        assert report.ssvc.basis is SsvcBasis.EVIDENCE
        assert report.ssvc.unverified_signals == []
        assert report.policy.passed is False
        assert report.policy.triggered == ["CVE-2021-0001"]

    async def test_fail_on_never_always_passes(self, feeds: tuple[Calls, Responses]) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [vuln("CVE-2021-0001")])
        responses["kev"]["CVE-2021-0001"] = kev_hit("CVE-2021-0001")

        report = await run_gate("liba==1.0\n", fail_on="never")

        assert report.policy.passed is True
        assert report.policy.triggered == []


class TestGhsaOnlyAdvisory:
    async def test_no_cve_alias_means_feeds_not_applicable(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        calls, responses = feeds
        responses["osv"]["libb"] = osv_result(
            "libb", "PyPI", "2.0", [vuln("GHSA-aaaa-bbbb-cccc", severity=V31_HIGH)]
        )

        report = await run_gate("libb==2.0\n")

        assert calls["kev"] == [] and calls["epss"] == [] and calls["exploit"] == []
        f = report.findings[0]
        assert f.cve_id is None
        assert f.coverage.kev is FeedCoverage.NOT_APPLICABLE
        assert f.coverage.epss is FeedCoverage.NOT_APPLICABLE
        assert f.coverage.exploits is FeedCoverage.NOT_APPLICABLE
        assert f.decision is SsvcDecision.TRACK_STAR  # high severity, no exploitation
        assert f.reference_url == "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"
        # A non-CVE driver is named in the rationale but never fabricated into
        # the CVE-shaped driving_cve field.
        assert report.ssvc.decision is SsvcDecision.TRACK_STAR
        assert report.ssvc.driving_cve is None
        assert "GHSA-aaaa-bbbb-cccc" in report.ssvc.rationale

    async def test_cve_alias_is_used_for_enrichment(self, feeds: tuple[Calls, Responses]) -> None:
        calls, responses = feeds
        responses["osv"]["libb"] = osv_result(
            "libb",
            "PyPI",
            "2.0",
            [vuln("GHSA-aaaa-bbbb-cccc", aliases=["CVE-2022-1234"])],
        )

        report = await run_gate("libb==2.0\n")

        assert calls["kev"] == ["CVE-2022-1234"]
        assert report.findings[0].cve_id == "CVE-2022-1234"
        assert report.findings[0].reference_url == "https://nvd.nist.gov/vuln/detail/CVE-2022-1234"


class TestDedup:
    async def test_shared_cve_enriched_once(self, feeds: tuple[Calls, Responses]) -> None:
        calls, responses = feeds
        shared = vuln("CVE-2021-0001")
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [shared])
        responses["osv"]["libb"] = osv_result("libb", "PyPI", "2.0", [shared])

        report = await run_gate("liba==1.0\nlibb==2.0\n")

        assert len(report.findings) == 2
        assert calls["kev"] == ["CVE-2021-0001"]
        assert calls["epss"] == ["CVE-2021-0001"]
        assert calls["exploit"] == ["CVE-2021-0001"]
        # One triggered id, not one per component.
        report_attend = await run_gate("liba==1.0\nlibb==2.0\n", fail_on="track_star")
        assert report_attend.policy.triggered == ["CVE-2021-0001"]


class TestAdvisoryFold:
    async def test_ghsa_pysec_mirrors_fold_into_one_finding(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        calls, responses = feeds
        ghsa = vuln(
            "GHSA-aaaa-bbbb-cccc",
            aliases=["CVE-2023-0001"],
            severity=V31_HIGH,
            fixed=None,
        )
        pysec = vuln("PYSEC-2023-1", aliases=["CVE-2023-0001"], severity=None, fixed="2.0")
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [ghsa, pysec])

        report = await run_gate("liba==1.0\n")

        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.cve_id == "CVE-2023-0001"
        assert f.osv_id == "GHSA-aaaa-bbbb-cccc"  # richest record wins (has severity)
        assert f.severity is Severity.HIGH
        assert f.fixed_version == "2.0"  # merged from the sibling
        assert "PYSEC-2023-1" in f.aliases  # folded id kept visible
        assert calls["kev"] == ["CVE-2023-0001"]


class TestCoverageHonesty:
    async def test_epss_error_is_a_gap_and_strict_fails(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result(
            "liba", "PyPI", "1.0", [vuln("CVE-2021-0001", severity=V31_HIGH)]
        )
        responses["epss"]["CVE-2021-0001"] = EpssRequestError("boom")

        relaxed = await run_gate("liba==1.0\n")
        assert relaxed.findings[0].coverage.epss is FeedCoverage.ERROR
        assert relaxed.policy.coverage_gaps == 1
        assert relaxed.policy.passed is True  # track_star finding, fail-on act

        strict = await run_gate("liba==1.0\n", strict=True)
        assert strict.policy.passed is False
        assert strict.policy.triggered == []

    async def test_epss_upstream_error_status_is_error_coverage(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [vuln("CVE-2021-0001")])
        responses["epss"]["CVE-2021-0001"] = EpssScore(
            cve_id="CVE-2021-0001", status=EpssStatus.UPSTREAM_ERROR
        )

        report = await run_gate("liba==1.0\n")

        assert report.findings[0].coverage.epss is FeedCoverage.ERROR
        assert report.policy.coverage_gaps == 1

    async def test_exploit_degraded_without_token_ok_with_token(
        self, feeds: tuple[Calls, Responses], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [vuln("CVE-2021-0001")])

        degraded = await run_gate("liba==1.0\n")
        assert degraded.findings[0].coverage.exploits is FeedCoverage.DEGRADED

        monkeypatch.setattr(settings, "github_token", SecretStr("ghp_x"))
        full = await run_gate("liba==1.0\n")
        assert full.findings[0].coverage.exploits is FeedCoverage.OK

    async def test_errored_exploit_arm_is_a_coverage_gap_not_a_clean_miss(
        self, feeds: tuple[Calls, Responses], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The tool no longer raises for one failing source; the gate must
        still see the gap. A throttled GitHub arm is `error`, never `ok`."""
        _, responses = feeds
        monkeypatch.setattr(settings, "github_token", SecretStr("ghp_x"))
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [vuln("CVE-2021-0001")])
        responses["exploit"]["CVE-2021-0001"] = ExploitCheck(
            cve_id="CVE-2021-0001",
            has_public_exploit=False,
            exploit_db=ExploitArmStatus.NOT_FOUND,
            github=ExploitArmStatus.ERROR,
        )

        report = await run_gate("liba==1.0\n")

        assert report.findings[0].coverage.exploits is FeedCoverage.ERROR
        assert report.findings[0].exploits_public is False
        assert report.policy.coverage_gaps == 1

    async def test_osv_error_skips_component_and_counts_gap(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = OsvServerError("HTTP 503")

        report = await run_gate("liba==1.0\n")

        assert report.components_scanned == 0
        assert report.findings == []
        assert len(report.skipped) == 1
        assert report.skipped[0].reason is SkipReason.OSV_ERROR
        assert report.policy.coverage_gaps == 1

    async def test_kev_failure_hard_fails(self, feeds: tuple[Calls, Responses]) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [vuln("CVE-2021-0001")])
        responses["kev"]["CVE-2021-0001"] = KevDownloadError("catalog unreachable")

        with pytest.raises(KevDownloadError):
            await run_gate("liba==1.0\n")


class TestSsvcSignalPaths:
    async def test_high_epss_drives_attend(self, feeds: tuple[Calls, Responses]) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [vuln("CVE-2021-0001")])
        responses["epss"]["CVE-2021-0001"] = epss_found("CVE-2021-0001", 0.9, 0.99)

        report = await run_gate("liba==1.0\n", fail_on="attend")

        f = report.findings[0]
        assert f.decision is SsvcDecision.ATTEND
        assert f.rule == "high-epss"
        assert report.policy.passed is False

    async def test_public_exploit_plus_high_epss_is_act(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result("liba", "PyPI", "1.0", [vuln("CVE-2021-0001")])
        responses["epss"]["CVE-2021-0001"] = epss_found("CVE-2021-0001", 0.9, 0.99)
        responses["exploit"]["CVE-2021-0001"] = ExploitCheck(
            cve_id="CVE-2021-0001",
            has_public_exploit=True,
            exploit_db=ExploitArmStatus.FOUND,
            github=ExploitArmStatus.SKIPPED,
            exploit_db_ids=["12345"],
        )

        report = await run_gate("liba==1.0\n")

        assert report.findings[0].decision is SsvcDecision.ACT
        assert report.findings[0].rule == "public-exploit+high-epss"
        assert report.policy.passed is False

    async def test_no_severity_token_means_track_baseline(
        self, feeds: tuple[Calls, Responses]
    ) -> None:
        _, responses = feeds
        responses["osv"]["liba"] = osv_result(
            "liba", "PyPI", "1.0", [vuln("CVE-2021-0001", severity=None)]
        )

        report = await run_gate("liba==1.0\n")

        f = report.findings[0]
        assert f.severity is None and f.cvss_score is None
        assert f.decision is SsvcDecision.TRACK
        assert f.rule == "baseline"


class TestPartitioning:
    async def test_cyclonedx_skip_reasons(self, feeds: tuple[Calls, Responses]) -> None:
        calls, _ = feeds
        sbom = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "no-version", "purl": "pkg:pypi/no-version"},
                    {"name": "no-purl", "version": "1.0"},
                    {"name": "phpthing", "version": "1.0", "purl": "pkg:composer/phpthing@1.0"},
                    {"name": "rusty", "version": "0.3.0", "purl": "pkg:cargo/rusty@0.3.0"},
                ],
            }
        )

        report = await run_gate(sbom)

        reasons = {s.name: s.reason for s in report.skipped}
        assert reasons == {
            "no-version": SkipReason.NO_VERSION,
            "no-purl": SkipReason.NO_ECOSYSTEM,
            "phpthing": SkipReason.UNSUPPORTED_ECOSYSTEM,
        }
        assert calls["osv"] == [("rusty", "crates.io", "0.3.0")]
        assert report.components_total == 4
        assert report.components_scanned == 1

    async def test_oversized_content_is_refused(self, feeds: tuple[Calls, Responses]) -> None:
        with pytest.raises(SbomError):
            await run_gate("a" * (SBOM_MAX_CONTENT_BYTES + 1))
