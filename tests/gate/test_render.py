"""GateReport -> SARIF / OpenVEX adapter tests.

The spec mechanics are pinned by tests/export/; here the assertions cover
what the gate adapters add: per-component fingerprints, unknown-severity
fallbacks, per-statement product purls, PyPI purl synthesis, and the
exclusion accounting for findings without product identity.
"""

from datetime import UTC, datetime
from typing import Any

import pytest

from sec_recon_agent.agent.schema import Severity, SsvcAssessment, SsvcBasis, SsvcDecision
from sec_recon_agent.export.openvex import ProductIdentityError
from sec_recon_agent.gate.models import (
    FeedCoverage,
    FindingCoverage,
    GateFinding,
    GatePolicy,
    GateReport,
)
from sec_recon_agent.gate.render import gate_to_openvex, gate_to_sarif, openvex_excluded

TS = datetime(2026, 7, 8, 12, 0, 0, tzinfo=UTC)

_NA_COVERAGE = FindingCoverage(
    kev=FeedCoverage.NOT_APPLICABLE,
    epss=FeedCoverage.NOT_APPLICABLE,
    exploits=FeedCoverage.NOT_APPLICABLE,
)


def finding(**overrides: Any) -> GateFinding:
    base: dict[str, Any] = {
        "component_name": "liba",
        "component_version": "1.0",
        "component_ecosystem": "PyPI",
        "component_purl": None,
        "osv_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": None,
        "summary": None,
        "severity": None,
        "cvss_score": None,
        "fixed_version": None,
        "reference_url": "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
        "decision": SsvcDecision.TRACK,
        "rule": "baseline",
        "coverage": _NA_COVERAGE,
    }
    base.update(overrides)
    return GateFinding(**base)


def report(findings: list[GateFinding], **overrides: Any) -> GateReport:
    base: dict[str, Any] = {
        "sbom_format": "requirements",
        "components_total": 2,
        "components_scanned": 2,
        "findings": findings,
        "ssvc": SsvcAssessment(
            decision=SsvcDecision.TRACK,
            rule="no-cves",
            rationale="test",
            driving_cve=None,
            basis=SsvcBasis.EVIDENCE,
        ),
        "policy": GatePolicy(fail_on="act", triggered=[], passed=True),
        "tool_version": "0.1.0",
    }
    base.update(overrides)
    return GateReport(**base)


def cve_finding(component: str, purl: str | None = None) -> GateFinding:
    return finding(
        component_name=component,
        component_purl=purl,
        osv_id="CVE-2021-0001",
        cve_id="CVE-2021-0001",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="2.0",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
        decision=SsvcDecision.ACT,
        rule="kev-active-exploitation",
        in_kev=True,
        coverage=FindingCoverage(
            kev=FeedCoverage.OK, epss=FeedCoverage.OK, exploits=FeedCoverage.SKIPPED
        ),
    )


class TestGateSarif:
    def test_shared_cve_one_rule_two_results_distinct_fingerprints(self) -> None:
        doc = gate_to_sarif(
            report([cve_finding("liba"), cve_finding("libb")]), artifact_uri="sbom.json"
        )
        run = doc["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 2
        fingerprints = {r["partialFingerprints"]["primaryLocationLineHash"] for r in run["results"]}
        assert len(fingerprints) == 2  # component discriminator keeps alerts distinct

    def test_unknown_severity_falls_back_to_warning_without_security_severity(self) -> None:
        doc = gate_to_sarif(report([finding()]), artifact_uri="sbom.json")
        run = doc["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "warning"
        assert "security-severity" not in rule["properties"]
        assert "unknown severity" in rule["shortDescription"]["text"]
        assert run["results"][0]["level"] == "warning"

    def test_critical_finding_renders_error_level_and_security_severity(self) -> None:
        doc = gate_to_sarif(report([cve_finding("liba")]), artifact_uri="sbom.json")
        run = doc["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["security-severity"] == "9.8"
        assert "Upgrade liba to 2.0 or later." in rule["help"]["text"]
        assert rule["helpUri"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-0001"

    def test_result_carries_component_context_and_coverage(self) -> None:
        doc = gate_to_sarif(report([cve_finding("liba")]), artifact_uri="sbom.json")
        props = doc["runs"][0]["results"][0]["properties"]
        assert props["component"] == "liba"
        assert props["component_version"] == "1.0"
        assert props["osv_id"] == "CVE-2021-0001"
        assert props["fixed_version"] == "2.0"
        assert props["coverage"] == {"kev": "ok", "epss": "ok", "exploits": "skipped"}

    def test_run_properties_expose_gate_provenance(self) -> None:
        doc = gate_to_sarif(report([]), artifact_uri="sbom.json")
        props = doc["runs"][0]["properties"]
        assert props["source"] == "sec-recon-gate"
        assert props["sbom_format"] == "requirements"
        assert props["policy"]["passed"] is True
        assert props["ssvc"]["decision"] == "Track"

    def test_ssvc_note_appended_to_message(self) -> None:
        doc = gate_to_sarif(report([cve_finding("liba")]), artifact_uri="sbom.json")
        message = doc["runs"][0]["results"][0]["message"]["text"]
        assert "SSVC Act: on the CISA KEV catalog: actively exploited in the wild." in message


class TestGateOpenvex:
    def test_statement_binds_component_purl(self) -> None:
        purl = "pkg:cargo/rusty@0.3.0"
        doc = gate_to_openvex(report([cve_finding("rusty", purl=purl)]), timestamp=TS)
        stmt = doc["statements"][0]
        assert stmt["products"] == [{"@id": purl, "identifiers": {"purl": purl}}]
        assert stmt["status"] == "affected"
        assert stmt["action_statement"] == "Upgrade rusty to 2.0 or later."
        assert stmt["status_notes"].startswith("SSVC Act:")

    def test_pypi_purl_is_synthesized_and_normalized(self) -> None:
        f = cve_finding("Foo_Bar.baz")
        doc = gate_to_openvex(report([f]), timestamp=TS)
        assert doc["statements"][0]["products"][0]["@id"] == "pkg:pypi/foo-bar-baz@1.0"
        assert openvex_excluded(report([f])) == []

    def test_non_pypi_without_purl_is_excluded_never_guessed(self) -> None:
        maven = cve_finding("com.example:lib")
        maven = finding(
            **{
                **maven.model_dump(),
                "component_ecosystem": "Maven",
                "component_purl": None,
            }
        )
        pypi = cve_finding("liba")
        doc = gate_to_openvex(report([maven, pypi]), timestamp=TS)
        assert len(doc["statements"]) == 1
        assert openvex_excluded(report([maven, pypi])) == ["CVE-2021-0001"]

    def test_all_excluded_raises_product_identity_error(self) -> None:
        maven = finding(component_ecosystem="Maven", component_purl=None)
        with pytest.raises(ProductIdentityError):
            gate_to_openvex(report([maven]), timestamp=TS)

    def test_document_id_is_deterministic(self) -> None:
        rep = report([cve_finding("liba")])
        first = gate_to_openvex(rep, timestamp=TS)
        second = gate_to_openvex(rep, timestamp=TS)
        assert first["@id"] == second["@id"]
        assert first == second
