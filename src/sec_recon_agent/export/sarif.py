"""SARIF 2.1.0 renderer for GitHub code scanning.

Core (`render_sarif`) is a pure function over neutral VulnRecord rows plus a
run-level property bag; `to_sarif` is the TriageReport adapter and keeps the
public signature and byte-for-byte output it had before the SBOM gate landed.
The record producer stays the single source of truth - the renderer never
re-derives a verdict:

- `result.level` is a display mapping of each record's own severity
  (critical/high -> error, medium -> warning, low/info -> note; unknown ->
  warning), not a second prioritization. The authoritative SSVC verdict
  passes through verbatim in the run property bag, and its rationale is
  echoed via the record's `ssvc_note`.
- `rule.properties["security-severity"]` carries the CVSS score as a
  string, the exact form GitHub maps onto critical/high/medium/low bands
  (>9.0 / 7.0-8.9 / 4.0-6.9 / 0.1-3.9); omitted when the score is absent
  or 0.0, which GitHub treats as "no security severity".
- `partialFingerprints.primaryLocationLineHash` is synthetic but stable
  (sha256 over rule id + artifact uri + the record's fingerprint_extra),
  so re-uploading the same document updates alerts instead of duplicating
  them, while two components sharing a CVE keep distinct alerts.

GitHub-required fields honored per result: message.text, one location with
artifactLocation.uri + region.startLine, partialFingerprints; per rule:
shortDescription, fullDescription, help. Findings here have no source
line, so startLine is pinned to 1 (the same convention Trivy uses for
container-image findings).
"""

import hashlib
from collections.abc import Sequence
from typing import Any

from sec_recon_agent.agent.schema import CVEReference, Severity, TriageReport
from sec_recon_agent.export.records import VulnRecord
from sec_recon_agent.version import package_version

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_TOOL_NAME = "sec-recon-agent"
_INFORMATION_URI = "https://github.com/Shurtug4l/sec-recon-agent"

_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# A record without a severity (gate finding whose advisory carried no usable
# CVSS data) still deserves attention over a note-level nit.
_LEVEL_UNKNOWN = "warning"


def _level(severity: Severity | None) -> str:
    return _LEVEL_BY_SEVERITY[severity] if severity is not None else _LEVEL_UNKNOWN


def _fingerprint(rule_id: str, artifact_uri: str, extra: str = "") -> str:
    seed = f"{rule_id}|{artifact_uri}" if not extra else f"{rule_id}|{artifact_uri}|{extra}"
    digest = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return f"{digest}:1"


def _rule(record: VulnRecord) -> dict[str, Any]:
    properties: dict[str, Any] = {"tags": ["security", "vulnerability"]}
    if record.cvss_score is not None and record.cvss_score > 0.0:
        properties["security-severity"] = f"{record.cvss_score:.1f}"
    severity_text = record.severity if record.severity is not None else "unknown"
    return {
        "id": record.rule_id,
        "shortDescription": {"text": f"{record.rule_id}: {severity_text} severity"},
        "fullDescription": {"text": record.summary},
        "help": {"text": f"{record.action}\n\n{record.reference_label}: {record.url}"},
        "helpUri": record.url,
        "defaultConfiguration": {"level": _level(record.severity)},
        "properties": properties,
    }


def _result_message(record: VulnRecord) -> str:
    parts = [record.summary]
    signals: list[str] = []
    if record.in_kev:
        due = f" (federal remediation due {record.kev_due_date})" if record.kev_due_date else ""
        signals.append(f"listed in CISA KEV{due}")
    if record.known_ransomware:
        signals.append("associated with known ransomware campaigns")
    if record.exploit_public:
        signals.append("public exploit available")
    if record.epss_probability is not None:
        signals.append(f"EPSS {record.epss_probability:.3f}")
    if signals:
        parts.append("Signals: " + "; ".join(signals) + ".")
    if record.ssvc_note is not None:
        parts.append(record.ssvc_note)
    return " ".join(parts)


def _result(record: VulnRecord, rule_index: int, artifact_uri: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "in_kev_catalog": record.in_kev,
        "known_ransomware_use": record.known_ransomware,
        "exploits_public": record.exploit_public,
        "epss_probability": record.epss_probability,
        "epss_percentile": record.epss_percentile,
    }
    properties.update(record.extra_properties)
    return {
        "ruleId": record.rule_id,
        "ruleIndex": rule_index,
        "level": _level(record.severity),
        "message": {"text": _result_message(record)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": 1},
                },
            },
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": _fingerprint(
                record.rule_id, artifact_uri, record.fingerprint_extra
            ),
        },
        "properties": properties,
    }


def render_sarif(
    records: Sequence[VulnRecord],
    *,
    artifact_uri: str,
    run_properties: dict[str, Any],
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Render neutral records as a SARIF 2.1.0 log with a single run.

    `artifact_uri` is the location GitHub attaches every alert to: use a
    path relative to the consumer repository root (e.g. the SBOM or report
    file that produced the findings). One rule per distinct rule id (first
    record wins); records sharing the rule emit their own results.
    """
    if not artifact_uri.strip():
        raise ValueError("artifact_uri must be a non-empty relative path or identifier")

    rule_indices: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for record in records:
        if record.rule_id not in rule_indices:
            rule_indices[record.rule_id] = len(rules)
            rules.append(_rule(record))
    results = [_result(r, rule_indices[r.rule_id], artifact_uri) for r in records]

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _INFORMATION_URI,
                        "semanticVersion": tool_version or package_version(),
                        "rules": rules,
                    },
                },
                "results": results,
                "properties": run_properties,
            },
        ],
    }


def _record_from_cve(report: TriageReport, cve: CVEReference) -> VulnRecord:
    ssvc_note: str | None = None
    if report.ssvc is not None and report.ssvc.driving_cve == cve.cve_id:
        ssvc_note = f"SSVC {report.ssvc.decision}: {report.ssvc.rationale}"
    return VulnRecord(
        rule_id=cve.cve_id,
        summary=cve.summary,
        severity=cve.severity,
        cvss_score=cve.cvss_v3_score,
        url=str(cve.nvd_url),
        action=report.recommended_action,
        in_kev=cve.in_kev_catalog,
        kev_due_date=cve.kev_due_date,
        known_ransomware=cve.known_ransomware_use,
        exploit_public=cve.exploits_public,
        epss_probability=cve.epss_probability,
        epss_percentile=cve.epss_percentile,
        ssvc_note=ssvc_note,
    )


def to_sarif(
    report: TriageReport,
    *,
    artifact_uri: str,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Render the report as a SARIF 2.1.0 log with a single run.

    TriageReport adapter over render_sarif; the SSVC rationale is echoed on
    the driving CVE's result message and the verdict passes through verbatim
    in the run property bag.
    """
    records = [_record_from_cve(report, cve) for cve in report.cves]
    run_properties: dict[str, Any] = {
        "summary": report.summary,
        "confidence": report.confidence,
        "grounding_status": report.grounding.status if report.grounding is not None else None,
    }
    if report.ssvc is not None:
        run_properties["ssvc"] = report.ssvc.model_dump(mode="json")
    return render_sarif(
        records,
        artifact_uri=artifact_uri,
        run_properties=run_properties,
        tool_version=tool_version,
    )
