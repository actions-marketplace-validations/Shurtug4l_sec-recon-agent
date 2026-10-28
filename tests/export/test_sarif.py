"""Unit tests for the pure TriageReport -> SARIF 2.1.0 renderer."""

from typing import Any

import pytest

from sec_recon_agent.agent.schema import (
    Confidence,
    CVEReference,
    GroundingAssessment,
    GroundingStatus,
    Severity,
    SsvcAssessment,
    SsvcBasis,
    SsvcDecision,
    TriageReport,
)
from sec_recon_agent.export.sarif import SARIF_SCHEMA_URI, SARIF_VERSION, to_sarif


def _cve(**overrides: Any) -> CVEReference:
    base: dict[str, Any] = {
        "cve_id": "CVE-2021-44228",
        "summary": "Log4Shell RCE in Apache Log4j2 via JNDI lookup.",
        "cvss_v3_score": 10.0,
        "severity": Severity.CRITICAL,
        "exploits_public": True,
        "affected_products": ["Apache Log4j2"],
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "in_kev_catalog": True,
        "kev_due_date": "2021-12-24",
        "known_ransomware_use": True,
        "epss_probability": 0.975,
        "epss_percentile": 0.999,
    }
    base.update(overrides)
    return CVEReference(**base)


def _report(**overrides: Any) -> TriageReport:
    base: dict[str, Any] = {
        "summary": "Critical Log4Shell exposure in the queried product.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "recommended_action": "Upgrade log4j-core to 2.17.1 or later immediately.",
        "cves": [_cve()],
        "ssvc": SsvcAssessment(
            decision=SsvcDecision.ACT,
            rule="kev-active-exploitation",
            rationale="on the CISA KEV catalog: actively exploited in the wild",
            driving_cve="CVE-2021-44228",
            basis=SsvcBasis.EVIDENCE,
        ),
    }
    base.update(overrides)
    return TriageReport(**base)


def test_envelope_declares_sarif_2_1_0() -> None:
    doc = to_sarif(_report(), artifact_uri="sbom.json")
    assert doc["$schema"] == SARIF_SCHEMA_URI
    assert doc["version"] == SARIF_VERSION
    assert len(doc["runs"]) == 1


def test_driver_carries_name_and_injected_version() -> None:
    doc = to_sarif(_report(), artifact_uri="sbom.json", tool_version="1.2.3")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "sec-recon-agent"
    assert driver["semanticVersion"] == "1.2.3"


def test_driver_version_resolves_from_package_metadata() -> None:
    driver = to_sarif(_report(), artifact_uri="s.json")["runs"][0]["tool"]["driver"]
    assert driver["semanticVersion"]  # editable install resolves a real version


def test_rule_has_github_required_fields() -> None:
    rule = to_sarif(_report(), artifact_uri="sbom.json")["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "CVE-2021-44228"
    assert rule["shortDescription"]["text"]
    assert rule["fullDescription"]["text"]
    assert rule["help"]["text"]
    assert rule["helpUri"].startswith("https://nvd.nist.gov/")
    assert "security" in rule["properties"]["tags"]


def test_security_severity_is_a_string_score() -> None:
    rule = to_sarif(_report(), artifact_uri="s.json")["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "10.0"


@pytest.mark.parametrize("score", [None, 0.0])
def test_security_severity_omitted_without_a_positive_score(score: float | None) -> None:
    report = _report(cves=[_cve(cvss_v3_score=score)])
    rule = to_sarif(report, artifact_uri="s.json")["runs"][0]["tool"]["driver"]["rules"][0]
    assert "security-severity" not in rule["properties"]


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_level_is_a_display_mapping_of_cve_severity(severity: Severity, level: str) -> None:
    report = _report(cves=[_cve(severity=severity)])
    doc = to_sarif(report, artifact_uri="s.json")
    assert doc["runs"][0]["results"][0]["level"] == level
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["defaultConfiguration"]["level"] == level


def test_result_message_carries_signals_and_driving_ssvc_rationale() -> None:
    text = to_sarif(_report(), artifact_uri="s.json")["runs"][0]["results"][0]["message"]["text"]
    assert "CISA KEV" in text
    assert "ransomware" in text
    assert "public exploit" in text
    assert "EPSS 0.975" in text
    assert "SSVC Act" in text


def test_non_driving_cve_does_not_echo_ssvc() -> None:
    other = _cve(
        cve_id="CVE-2021-45046",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
        in_kev_catalog=False,
        kev_due_date=None,
        known_ransomware_use=None,
    )
    report = _report(cves=[_cve(), other])
    results = to_sarif(report, artifact_uri="s.json")["runs"][0]["results"]
    assert "SSVC" in results[0]["message"]["text"]
    assert "SSVC" not in results[1]["message"]["text"]


def test_location_pins_artifact_uri_and_line_one() -> None:
    result = to_sarif(_report(), artifact_uri="data/sbom.json")["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "data/sbom.json"
    assert location["region"]["startLine"] == 1


def test_fingerprint_is_stable_and_artifact_scoped() -> None:
    first = to_sarif(_report(), artifact_uri="a.json")["runs"][0]["results"][0]
    second = to_sarif(_report(), artifact_uri="a.json")["runs"][0]["results"][0]
    moved = to_sarif(_report(), artifact_uri="b.json")["runs"][0]["results"][0]
    key = "primaryLocationLineHash"
    assert first["partialFingerprints"][key] == second["partialFingerprints"][key]
    assert first["partialFingerprints"][key] != moved["partialFingerprints"][key]


def test_duplicate_cve_ids_share_one_rule() -> None:
    report = _report(cves=[_cve(), _cve()])
    run = to_sarif(report, artifact_uri="s.json")["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
    assert {r["ruleIndex"] for r in run["results"]} == {0}


def test_run_properties_pass_ssvc_and_grounding_verbatim() -> None:
    grounding = GroundingAssessment(status=GroundingStatus.GROUNDED, claims_checked=5, supported=5)
    props = to_sarif(_report(grounding=grounding), artifact_uri="s.json")["runs"][0]["properties"]
    assert props["ssvc"]["decision"] == "Act"
    assert props["ssvc"]["rule"] == "kev-active-exploitation"
    assert props["grounding_status"] == "grounded"
    assert props["confidence"] == "high"


def test_run_properties_honest_when_stamps_absent() -> None:
    props = to_sarif(_report(ssvc=None), artifact_uri="s.json")["runs"][0]["properties"]
    assert "ssvc" not in props
    assert props["grounding_status"] is None


def test_report_without_cves_renders_empty_run() -> None:
    run = to_sarif(_report(cves=[], ssvc=None), artifact_uri="s.json")["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_renderer_is_deterministic() -> None:
    assert to_sarif(_report(), artifact_uri="s.json", tool_version="1.0.0") == to_sarif(
        _report(), artifact_uri="s.json", tool_version="1.0.0"
    )


def test_blank_artifact_uri_is_rejected() -> None:
    with pytest.raises(ValueError, match="artifact_uri"):
        to_sarif(_report(), artifact_uri="   ")
