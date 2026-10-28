/**
 * Render a TriageReport as a Markdown document. Used by the
 * "Export as Markdown" button on the report view. Pure function, no
 * side effects - the file/download trigger lives in the component.
 *
 * The output mirrors the on-screen layout: header + summary +
 * recommended action + per-CVE details + ATT&CK techniques +
 * reasoning chain. Free-text fields are passed through verbatim
 * (they were already fenced at the tool boundary on the backend
 * before reaching the model).
 */

import type {
  TriageReport,
  CVEReference,
  AttackTechnique,
  GroundingAssessment,
  SsvcAssessment,
  FeedStatus,
} from "./types";

const UNTRUSTED_START = "<UNTRUSTED_CONTENT>";
const UNTRUSTED_END = "</UNTRUSTED_CONTENT>";

function stripFence(text: string): string {
  const t = text.trim();
  if (t.startsWith(UNTRUSTED_START) && t.endsWith(UNTRUSTED_END)) {
    return t.slice(UNTRUSTED_START.length, -UNTRUSTED_END.length).trim();
  }
  return text;
}

function formatYesNo(value: boolean | null | undefined): string {
  if (value === true) return "yes";
  if (value === false) return "no";
  return "unknown";
}

function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return "n/a";
  return `${(value * 100).toFixed(1)}%`;
}

function renderCve(cve: CVEReference): string {
  const lines: string[] = [];
  lines.push(`### ${cve.cve_id}`);
  lines.push("");
  lines.push(`- **Severity**: ${cve.severity}`);
  if (cve.cvss_v3_score !== null) {
    lines.push(`- **CVSS v3**: ${cve.cvss_v3_score.toFixed(1)}`);
  }
  lines.push(`- **Public exploit**: ${formatYesNo(cve.exploits_public)}`);
  if (cve.in_kev_catalog) {
    const due = cve.kev_due_date ? ` (CISA due ${cve.kev_due_date})` : "";
    lines.push(`- **CISA KEV**: yes${due}`);
  } else {
    lines.push(`- **CISA KEV**: no`);
  }
  if (cve.known_ransomware_use !== null) {
    lines.push(`- **Known ransomware use**: ${formatYesNo(cve.known_ransomware_use)}`);
  }
  if (cve.epss_probability !== null) {
    const pct = cve.epss_percentile !== null ? ` (p${(cve.epss_percentile * 100).toFixed(0)})` : "";
    lines.push(`- **EPSS**: ${formatPercent(cve.epss_probability)}${pct}`);
  }
  if (cve.affected_products.length > 0) {
    lines.push(`- **Affected**: ${cve.affected_products.join(", ")}`);
  }
  lines.push(`- **NVD**: ${cve.nvd_url}`);
  lines.push("");
  lines.push("> " + stripFence(cve.summary).replace(/\n/g, "\n> "));
  lines.push("");
  return lines.join("\n");
}

function renderTechnique(t: AttackTechnique): string {
  const lines: string[] = [];
  const tactics = t.tactics.length > 0 ? ` _(tactics: ${t.tactics.join(", ")})_` : "";
  lines.push(`### ${t.id} - ${t.name}${tactics}`);
  lines.push("");
  lines.push(`- **Reference**: ${t.url}`);
  if (t.related_cwes.length > 0) {
    lines.push(`- **Triggered by**: ${t.related_cwes.join(", ")}`);
  }
  if (t.mitigations.length > 0) {
    lines.push(`- **Mitigations**:`);
    for (const m of t.mitigations) {
      lines.push(`  - ${m.id} - ${m.name} (${m.url})`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

function renderSsvc(ssvc: SsvcAssessment, shared: boolean): string {
  const lines: string[] = [];
  lines.push("## SSVC verdict");
  lines.push("");
  lines.push(
    shared
      ? "_As written in the shared link: a claim, not a verdict this site computed._"
      : "_Deterministic prioritization, computed server-side from the collected signals (not the LLM)._",
  );
  lines.push("");
  lines.push(`- **Decision**: ${ssvc.decision}`);
  lines.push(`- **Rule**: \`${ssvc.rule}\``);
  if (ssvc.driving_cve) {
    lines.push(`- **Driving CVE**: ${ssvc.driving_cve}`);
  }
  if (ssvc.basis && ssvc.basis !== "evidence") {
    const unverified = ssvc.unverified_signals ?? [];
    const suffix = unverified.length > 0 ? ` (unverified: ${unverified.join(", ")})` : "";
    lines.push(`- **Basis**: ${ssvc.basis}${suffix}`);
  }
  lines.push("");
  lines.push(ssvc.rationale);
  lines.push("");
  return lines.join("\n");
}

function renderCoverage(coverage: FeedStatus[]): string {
  const lines: string[] = [];
  lines.push(`## Signal coverage (${coverage.length} feeds)`);
  lines.push("");
  lines.push("| Feed | Status | Detail |");
  lines.push("|---|---|---|");
  for (const f of coverage) {
    lines.push(`| ${f.feed} | ${f.status} | ${f.detail ?? ""} |`);
  }
  lines.push("");
  return lines.join("\n");
}

function renderGrounding(g: GroundingAssessment, shared: boolean): string {
  const lines: string[] = [];
  lines.push("## Grounding verification");
  lines.push("");
  lines.push(
    shared
      ? "_As written in the shared link: this site cannot re-run the check, so every status below is a claim._"
      : "_Deterministic post-run check: every tool-derived claim re-verified server-side against the tool results captured from the run (not the model's self-assessment)._",
  );
  lines.push("");
  lines.push(`- **Status**: ${g.status}`);
  if (g.status !== "not_evaluated") {
    lines.push(`- **Claims checked**: ${g.claims_checked}`);
    lines.push(`- **Supported**: ${g.supported}`);
    if (g.unbacked > 0) lines.push(`- **Unbacked**: ${g.unbacked}`);
    if (g.mismatched > 0) lines.push(`- **Mismatched**: ${g.mismatched}`);
    if (g.unverifiable > 0) lines.push(`- **Unverifiable**: ${g.unverifiable}`);
  }
  lines.push("");
  if (g.findings.length > 0) {
    lines.push("| Subject | Field | Status | Detail |");
    lines.push("|---|---|---|---|");
    for (const f of g.findings) {
      lines.push(`| ${f.subject} | \`${f.field}\` | ${f.status} | ${f.detail ?? ""} |`);
    }
    lines.push("");
  }
  if (g.truncated) {
    lines.push("_Findings list truncated at 40 entries; the counters remain complete._");
    lines.push("");
  }
  return lines.join("\n");
}

function renderProvenance(shared: boolean): string {
  const lines: string[] = [];
  lines.push("## Provenance");
  lines.push("");
  lines.push("_Which part of this report came from where, and who holds the pen._");
  lines.push("");
  lines.push(
    "- **Deterministic** (server-computed, not the model): SSVC verdict, grounding verification. Fixed code stamps these after the model returns; the same signals always produce the same result.",
  );
  lines.push(
    "- **Model-authored** (tool-grounded): summary, recommended action, confidence, reasoning chain. Written by the LLM, constrained to the typed TriageReport schema and grounded in the tool returns.",
  );
  lines.push(
    "- **External feed data** (verbatim): CVE / CVSS / CWE, KEV + EPSS, exploit signals, ATT&CK mapping, from NVD, CISA, FIRST, Exploit-DB / GitHub, OSV.dev and MITRE. Untrusted free text is fenced before reaching the model.",
  );
  lines.push("");
  lines.push(
    shared
      ? "These lanes describe a live run. This report came from a shared link, so none of them can be checked: whoever wrote the link held every pen, the deterministic lane included."
      : "A prompt injection that fully persuades the model still cannot move the verdict from Act to Track: the model does not hold that pen, the deterministic lane does.",
  );
  lines.push("");
  return lines.join("\n");
}

// `shared`: the report came from a /r permalink. The export then says so up
// front and swaps every "deterministic, server-computed" line for a claim,
// so a forged link cannot be laundered into an authoritative-looking file.
export function reportToMarkdown(
  report: TriageReport,
  query?: string,
  { shared = false }: { shared?: boolean } = {},
): string {
  const now = new Date().toISOString().replace(/T.*/, "");
  const lines: string[] = [];

  lines.push("# Triage report");
  lines.push("");
  if (shared) {
    lines.push(
      "> **Unverified content.** Exported from a shared sec-recon-agent link. Anyone can write one; the SSVC verdict and the grounding assessment below are claims made by the link, not results this site computed.",
    );
    lines.push("");
  }
  lines.push(`- **Severity**: ${report.severity}`);
  lines.push(`- **Confidence**: ${report.confidence}`);
  lines.push(`- **${shared ? "Exported" : "Generated"}**: ${now}`);
  if (query) {
    const oneLineQuery = query.length > 200 ? query.slice(0, 200) + "..." : query;
    lines.push(`- **Query**: \`${oneLineQuery.replace(/`/g, "\\`")}\``);
  }
  lines.push("");

  if (report.ssvc) {
    lines.push(renderSsvc(report.ssvc, shared));
  }

  lines.push("## Summary");
  lines.push("");
  lines.push(stripFence(report.summary));
  lines.push("");

  lines.push("## Recommended action");
  lines.push("");
  lines.push(stripFence(report.recommended_action));
  lines.push("");

  if (report.signal_coverage?.length > 0) {
    lines.push(renderCoverage(report.signal_coverage));
  }

  if (report.cves.length > 0) {
    lines.push(`## CVEs (${report.cves.length})`);
    lines.push("");
    for (const cve of report.cves) {
      lines.push(renderCve(cve));
    }
  }

  if (report.attack_techniques.length > 0) {
    lines.push(`## MITRE ATT&CK techniques (${report.attack_techniques.length})`);
    lines.push("");
    for (const t of report.attack_techniques) {
      lines.push(renderTechnique(t));
    }
  }

  if (report.grounding) {
    lines.push(renderGrounding(report.grounding, shared));
  }

  lines.push(renderProvenance(shared));

  if (report.reasoning_chain.length > 0) {
    lines.push(`## Reasoning chain (${report.reasoning_chain.length} steps)`);
    lines.push("");
    report.reasoning_chain.forEach((step, i) => {
      lines.push(`${i + 1}. ${step}`);
    });
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push(
    shared
      ? "_Exported from a shared sec-recon-agent link; content not verified._"
      : "_Generated by sec-recon-agent._",
  );
  lines.push("");

  return lines.join("\n");
}

/**
 * Trigger a browser download of the markdown payload. Lives next to
 * `reportToMarkdown` so the component only imports one symbol; the
 * DOM-y bits stay out of the component body.
 */
export function downloadMarkdown(filename: string, contents: string): void {
  triggerDownload(filename, contents, "text/markdown;charset=utf-8");
}

/**
 * Trigger a browser download of the report as raw JSON - the full validated
 * shape, including the SSVC verdict and per-feed coverage.
 */
export function downloadJson(filename: string, contents: string): void {
  triggerDownload(filename, contents, "application/json;charset=utf-8");
}

function triggerDownload(filename: string, contents: string, mime: string): void {
  const blob = new Blob([contents], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Browsers handle the eventual revocation, but releasing the object
  // URL on the next tick prevents the underlying blob from staying
  // referenced until GC.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
