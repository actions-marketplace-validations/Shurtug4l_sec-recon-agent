"""Unit tests for the pure TriageReport -> OpenVEX v0.2.0 renderer."""

from datetime import UTC, datetime
from typing import Any

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
from sec_recon_agent.export.openvex import (
    OPENVEX_CONTEXT,
    ProductIdentityError,
    to_openvex,
)

_TS = datetime(2026, 7, 8, 12, 0, 0, tzinfo=UTC)
_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


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


def test_envelope_carries_the_exact_v0_2_0_context() -> None:
    doc = to_openvex(_report(), products=[_PURL], timestamp=_TS)
    assert doc["@context"] == OPENVEX_CONTEXT
    assert doc["@id"].startswith("https://openvex.dev/docs/public/vex-")
    assert doc["author"]
    assert doc["timestamp"] == "2026-07-08T12:00:00+00:00"
    assert doc["version"] == 1


def test_document_id_is_deterministic_over_content() -> None:
    first = to_openvex(_report(), products=[_PURL], timestamp=_TS)
    second = to_openvex(_report(), products=[_PURL], timestamp=_TS)
    later = to_openvex(_report(), products=[_PURL], timestamp=datetime(2026, 7, 9, tzinfo=UTC))
    assert first == second
    assert first["@id"] != later["@id"]


def test_statement_binds_cve_to_the_supplied_product() -> None:
    statement = to_openvex(_report(), products=[_PURL], timestamp=_TS)["statements"][0]
    assert statement["vulnerability"]["name"] == "CVE-2021-44228"
    assert statement["vulnerability"]["@id"].startswith("https://nvd.nist.gov/")
    assert statement["products"] == [{"@id": _PURL, "identifiers": {"purl": _PURL}}]


def test_affected_status_carries_action_statement_and_ssvc_notes() -> None:
    statement = to_openvex(_report(), products=[_PURL], timestamp=_TS)["statements"][0]
    assert statement["status"] == "affected"
    assert statement["action_statement"] == "Upgrade log4j-core to 2.17.1 or later immediately."
    assert statement["status_notes"].startswith("SSVC Act:")


def test_status_notes_absent_without_an_ssvc_stamp() -> None:
    statement = to_openvex(_report(ssvc=None), products=[_PURL], timestamp=_TS)["statements"][0]
    assert "status_notes" not in statement


def test_multiple_products_attach_to_every_statement() -> None:
    other = "pkg:pypi/mypackage@1.0.0"
    statement = to_openvex(_report(), products=[_PURL, other], timestamp=_TS)["statements"][0]
    assert [p["@id"] for p in statement["products"]] == [_PURL, other]


def test_duplicate_cves_collapse_to_one_statement() -> None:
    doc = to_openvex(_report(cves=[_cve(), _cve()]), products=[_PURL], timestamp=_TS)
    assert len(doc["statements"]) == 1


def test_report_without_cves_renders_empty_statements() -> None:
    doc = to_openvex(_report(cves=[], ssvc=None), products=[_PURL], timestamp=_TS)
    assert doc["statements"] == []


@pytest.mark.parametrize("products", [[], [""], ["   "]])
def test_missing_product_identity_is_refused(products: list[str]) -> None:
    with pytest.raises(ProductIdentityError, match="product purl"):
        to_openvex(_report(), products=products, timestamp=_TS)


def test_non_purl_product_identity_is_refused() -> None:
    with pytest.raises(ProductIdentityError, match="purls"):
        to_openvex(_report(), products=["log4j-core 2.14.1"], timestamp=_TS)


def test_naive_timestamp_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        to_openvex(_report(), products=[_PURL], timestamp=datetime(2026, 7, 8))  # noqa: DTZ001
