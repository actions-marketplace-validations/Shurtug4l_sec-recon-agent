"use client";

import { useState, type ReactNode } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  Braces,
  ChevronDown,
  CircleCheck,
  CircleDashed,
  CircleSlash,
  Crosshair,
  Download,
  ExternalLink,
  Flame,
  Printer,
  Radar,
  Share2,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Skull,
  TrendingUp,
  Wrench,
  Zap,
} from "lucide-react";

import { ProvenanceNote } from "@/components/provenance-note";
import { SsvcDecisionTrace } from "@/components/ssvc-decision-trace";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Separator } from "@/components/ui/separator";
import { InfoTip, Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { downloadJson, downloadMarkdown, reportToMarkdown } from "@/lib/markdown-export";
import { allowedHref } from "@/lib/external-link";
import { buildPermalink } from "@/lib/permalink";
import { cn } from "@/lib/utils";
import type {
  FeedStatus,
  GroundingAssessment,
  GroundingClaimStatus,
  GroundingStatus,
  Severity,
  SignalStatus,
  SsvcAssessment,
  SsvcDecision,
  TriageReport,
} from "@/lib/types";

const severityClass: Record<Severity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

// SSVC ladder, most- to least-urgent. Position encodes urgency; the active
// stop also carries an icon + fill + text, so the verdict never rests on color
// alone (colorblind-safe, print-safe).
const SSVC_ORDER: SsvcDecision[] = ["Act", "Attend", "Track*", "Track"];
const SSVC_META: Record<
  SsvcDecision,
  { icon: typeof Zap; blurb: string; activeClass: string }
> = {
  Act: {
    icon: Zap,
    blurb: "Remediate out-of-cycle, as fast as possible.",
    activeClass: "bg-destructive text-destructive-foreground",
  },
  Attend: {
    icon: AlertTriangle,
    blurb: "Remediate ahead of standard timelines; needs attention.",
    activeClass: "bg-warning text-warning-foreground",
  },
  "Track*": {
    icon: Radar,
    blurb: "Standard timeline, but monitor for signals that would escalate.",
    activeClass: "bg-[hsl(var(--severity-low))] text-background",
  },
  Track: {
    icon: CircleCheck,
    blurb: "No action beyond standard update timelines.",
    activeClass: "bg-secondary text-foreground ring-1 ring-inset ring-primary/30",
  },
};

// Per-feed coverage status: icon + text + hue (redundant encoding).
const COVERAGE_META: Record<
  SignalStatus,
  { icon: typeof CircleCheck; label: string; className: string }
> = {
  found: { icon: CircleCheck, label: "found", className: "text-[hsl(var(--success))]" },
  not_found: { icon: CircleSlash, label: "not found", className: "text-muted-foreground" },
  error: { icon: AlertTriangle, label: "error", className: "text-warning" },
  not_queried: { icon: CircleDashed, label: "not queried", className: "text-muted-foreground/60" },
};

// Plain-language glosses for the coverage strip: what each feed is and what
// each status actually means. The load-bearing distinction is not_found vs
// error: "no entry" is a real answer, "error" means the feed was unreachable.
const FEED_GLOSS: Record<string, string> = {
  nvd: "NVD: NIST National Vulnerability Database (CVE records, CVSS)",
  kev: "CISA KEV: Known Exploited Vulnerabilities catalog (confirmed in-the-wild exploitation)",
  epss: "FIRST EPSS: estimated probability of exploitation in the next 30 days",
  exploit: "Public exploit search across Exploit-DB and GitHub",
  osv: "OSV.dev: open source package advisories",
  attack: "MITRE ATT&CK: attacker technique mapping from CWE ids",
  semantic_search: "Semantic search over a local index of recent high-severity CVEs",
};
const STATUS_GLOSS: Record<SignalStatus, string> = {
  found: "queried, returned data",
  not_found: "queried successfully, no entry: a real answer, not a failure",
  error: "could not be consulted (timeout or unusable response)",
  not_queried: "not consulted for this triage",
};

// Bridge each feed to the guide section that explains it, so a live signal is
// one click from its background. Ids mirror guide-data.ts SECTIONS; feeds
// without a dedicated section (exploit) simply carry no link.
const FEED_TO_GUIDE: Record<string, string> = {
  nvd: "cve-nvd",
  kev: "kev",
  epss: "epss",
  osv: "osv",
  attack: "attack",
  semantic_search: "cve-nvd",
};

// Report-level grounding outcome: icon + text + hue (redundant encoding, same
// discipline as the coverage strip). "suspect" renders as warning, not
// destructive: destructive is reserved for real-world danger signals (KEV,
// public exploits); a grounding flag is an integrity signal about the report.
const GROUNDING_META: Record<
  GroundingStatus,
  { icon: typeof CircleCheck; label: string; iconClass: string; gloss: string }
> = {
  grounded: {
    icon: CircleCheck,
    label: "grounded",
    iconClass: "text-[hsl(var(--success))]",
    gloss: "Every checked claim is backed by an actual tool result from this run.",
  },
  suspect: {
    icon: AlertTriangle,
    label: "suspect",
    iconClass: "text-warning",
    gloss: "At least one claim is unbacked or contradicts what a tool actually returned.",
  },
  not_evaluated: {
    icon: CircleDashed,
    label: "not evaluated",
    iconClass: "text-muted-foreground/60",
    gloss:
      "The run's message history was unavailable, so no claim could be checked. An honest skip, not a pass.",
  },
};

const CLAIM_META: Record<
  GroundingClaimStatus,
  { icon: typeof CircleCheck; label: string; className: string; tooltip: string }
> = {
  supported: {
    icon: CircleCheck,
    label: "supported",
    className: "text-[hsl(var(--success))]",
    tooltip: "A successful tool return backs this claim.",
  },
  unbacked: {
    icon: CircleSlash,
    label: "unbacked",
    className: "text-warning",
    tooltip: "A positive claim with no backing tool output: the fabrication signal.",
  },
  mismatch: {
    icon: AlertTriangle,
    label: "mismatch",
    className: "text-destructive",
    tooltip: "The claim contradicts what a tool actually returned.",
  },
  unverifiable: {
    icon: CircleDashed,
    label: "unverifiable",
    className: "text-muted-foreground/60",
    tooltip:
      "Relevant tool output existed but could not be parsed back into its typed model, so the claim cannot be judged either way.",
  },
};

const UNTRUSTED_START = "<UNTRUSTED_CONTENT>";
const UNTRUSTED_END = "</UNTRUSTED_CONTENT>";

// Strip the marker tokens for display while keeping a visual signal that
// the text is vendor-authored. The fence is a wire-level convention; in
// the UI we render it as a styled quote.
function unfence(text: string): { body: string; fenced: boolean } {
  const t = text.trim();
  if (t.startsWith(UNTRUSTED_START) && t.endsWith(UNTRUSTED_END)) {
    return {
      body: t.slice(UNTRUSTED_START.length, -UNTRUSTED_END.length).trim(),
      fenced: true,
    };
  }
  return { body: text, fenced: false };
}

export function TriageReportView({
  report,
  query,
  shared = false,
}: {
  report: TriageReport;
  query?: string;
  // True on /r: the report came from a permalink, so its server-side stamps
  // are rendered as unverified claims.
  shared?: boolean;
}) {
  const [linkState, setLinkState] = useState<"idle" | "copied" | "toolarge">("idle");
  // Grounding detail panel; opens by default when the verifier flagged
  // something, because a suspect report should not hide its findings.
  const [groundingOpen, setGroundingOpen] = useState(
    () => report.grounding?.status === "suspect",
  );

  function handleShowGrounding() {
    setGroundingOpen(true);
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document
      .getElementById("grounding-section")
      ?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
  }

  async function handleCopyLink() {
    // Encode the whole report (plus the originating query) into a URL fragment,
    // client-side, never sent to a server, and copy it. Oversized reports fall
    // back to the JSON export.
    const url = await buildPermalink(report, window.location.origin, query);
    if (!url) {
      setLinkState("toolarge");
      window.setTimeout(() => setLinkState("idle"), 2500);
      return;
    }
    await navigator.clipboard.writeText(url);
    setLinkState("copied");
    window.setTimeout(() => setLinkState("idle"), 1500);
  }

  function handleExportMarkdown() {
    const md = reportToMarkdown(report, query, { shared });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
    downloadMarkdown(`triage-${stamp}.md`, md);
  }

  function handleExportPdf() {
    // Browser print-to-PDF. The @media print stylesheet hides chrome and
    // shows only the .printable-report block (this component). The user
    // picks "Save as PDF" in the system print dialog. Native multi-page,
    // pixel-perfect, zero JS dependency.
    window.print();
  }

  function handleExportJson() {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
    // The full validated report, verbatim - the machine-readable form that
    // carries the deterministic SSVC verdict and per-feed coverage. A shared
    // report is wrapped instead: it was never validated here, and the wrapper
    // makes `sec-recon-export` reject it rather than turn a forged verdict
    // into SARIF or OpenVEX under this project's name.
    const payload = shared ? { source: "shared-permalink-unverified", report } : report;
    downloadJson(`triage-${stamp}.json`, JSON.stringify(payload, null, 2));
  }

  return (
    <div id="printable-report" className="printable-report animate-fade-in space-y-4">
      {shared && <SharedReportNote />}
      <Card className="border-2 border-primary/20">
        <CardHeader className="space-y-3">
          {report.ssvc && <SsvcVerdict ssvc={report.ssvc} shared={shared} />}
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              className={cn("text-xs uppercase tracking-wider", severityClass[report.severity])}
              title="Overall severity: the highest CVSS severity across the CVEs in this report."
            >
              {report.severity}
            </Badge>
            <span className="inline-flex items-center gap-1">
              <Badge variant="outline" className="text-xs uppercase tracking-wider">
                {report.confidence} confidence
              </Badge>
              <InfoTip label="What confidence means">
                The agent&apos;s self-assessed confidence: high = backed by direct
                tool data, medium = partial, low = speculative or a tool failed
                during the run. Self-reported by the model; the grounding badge next
                to it is the server-verified counterpart
                {shared ? ", except on a shared link, where it is a claim too" : ""}.
              </InfoTip>
            </span>
            {report.grounding && (
              <GroundingBadge grounding={report.grounding} shared={shared} onClick={handleShowGrounding} />
            )}
            <div className="ml-auto flex items-center gap-1 print:hidden">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleCopyLink}
                title="Copy a shareable link; the full report is encoded in the URL fragment, never sent to a server"
              >
                <Share2 className="h-3.5 w-3.5" />
                {linkState === "copied"
                  ? "Link copied"
                  : linkState === "toolarge"
                    ? "Too large - use JSON"
                    : "Copy link"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleExportMarkdown}
                title="Export the full report as a Markdown file"
              >
                <Download className="h-3.5 w-3.5" />
                Export .md
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleExportJson}
                title="Download the full report as JSON (includes the SSVC verdict, signal coverage + grounding verification)"
              >
                <Braces className="h-3.5 w-3.5" />
                Export JSON
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleExportPdf}
                title="Open the print dialog; pick 'Save as PDF'"
              >
                <Printer className="h-3.5 w-3.5" />
                Export PDF
              </Button>
            </div>
          </div>
          <p className="text-base font-medium leading-relaxed">{report.summary}</p>
        </CardHeader>
        <CardContent className="space-y-4">
          <Separator />
          <div>
            <div className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Recommended action
            </div>
            <p className="whitespace-pre-line text-sm leading-relaxed">{report.recommended_action}</p>
          </div>
        </CardContent>
      </Card>

      {report.signal_coverage?.length > 0 && (
        <SignalCoverageStrip coverage={report.signal_coverage} shared={shared} />
      )}

      {report.cves.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            CVEs ({report.cves.length})
            <Link
              href="/guide#cve-nvd"
              className="ml-auto shrink-0 text-[10px] font-normal normal-case tracking-normal text-primary hover:underline print:hidden"
            >
              CVE, CVSS &amp; CWE explained
            </Link>
          </div>
          {report.cves.map((cve) => {
            const { body, fenced } = unfence(cve.summary);
            return (
              <Card key={cve.cve_id} id={`cve-${cve.cve_id}`} className="scroll-mt-20 overflow-hidden">
                <CardHeader className="space-y-2 pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <ExternalRef
                      url={cve.nvd_url}
                      className="font-mono text-sm font-semibold"
                      icon
                    >
                      {cve.cve_id}
                    </ExternalRef>
                    <Badge className={cn("text-[10px] uppercase", severityClass[cve.severity])}>
                      {cve.severity}
                    </Badge>
                    {cve.cvss_v3_score !== null && (
                      <Badge
                        variant="outline"
                        className="text-[10px]"
                        title="CVSS v3 base score (0-10): how severe the flaw is if exploited. From NVD."
                      >
                        CVSS {cve.cvss_v3_score.toFixed(1)}
                      </Badge>
                    )}
                    {cve.exploits_public ? (
                      <Badge
                        variant="destructive"
                        className="gap-1 text-[10px]"
                        title="Public exploit code found on Exploit-DB or GitHub."
                      >
                        <ShieldX className="h-3 w-3" /> exploit public
                      </Badge>
                    ) : (
                      <Badge
                        variant="outline"
                        className="gap-1 text-[10px]"
                        title="No public exploit code found on Exploit-DB or GitHub at triage time. Absence of evidence, not proof of absence."
                      >
                        <ShieldCheck className="h-3 w-3" /> no public exploit
                      </Badge>
                    )}
                    {cve.in_kev_catalog && (
                      <Badge
                        variant="destructive"
                        className="gap-1 text-[10px]"
                        title="Listed in CISA's Known Exploited Vulnerabilities catalog: exploitation in the wild is confirmed. The due date is the deadline CISA sets for US federal agencies to remediate."
                      >
                        <Flame className="h-3 w-3" />
                        CISA KEV
                        {cve.kev_due_date ? ` · due ${cve.kev_due_date}` : ""}
                      </Badge>
                    )}
                    {cve.known_ransomware_use && (
                      <Badge
                        variant="destructive"
                        className="gap-1 text-[10px]"
                        title="CISA reports this CVE used in known ransomware campaigns."
                      >
                        <Skull className="h-3 w-3" /> ransomware
                      </Badge>
                    )}
                    {cve.epss_probability !== null && (
                      <Badge
                        variant={cve.epss_probability >= 0.5 ? "destructive" : "outline"}
                        className="gap-1 text-[10px]"
                        title="EPSS: estimated probability this CVE is exploited in the next 30 days (FIRST.org). pNN is its percentile rank among all scored CVEs."
                      >
                        <TrendingUp className="h-3 w-3" />
                        EPSS {(cve.epss_probability * 100).toFixed(1)}%
                        {cve.epss_percentile !== null
                          ? ` (p${(cve.epss_percentile * 100).toFixed(0)})`
                          : ""}
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3 pt-0">
                  <div>
                    {fenced && (
                      <div
                        className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground"
                        title="This description comes from the external feed, not from the agent. The backend wraps such free text in markers so the model treats it as data, not instructions (prompt-injection defense); the UI renders it as a quote."
                      >
                        NVD description (untrusted vendor text)
                      </div>
                    )}
                    <p className={cn("text-sm leading-relaxed", fenced && "border-l-2 border-muted pl-3 text-muted-foreground")}>
                      {body}
                    </p>
                  </div>
                  {cve.affected_products.length > 0 && (
                    <div>
                      <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                        Affected
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {cve.affected_products.map((p) => (
                          <Badge key={p} variant="secondary" className="font-mono text-[10px]">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {report.attack_techniques.length > 0 && (
        <AttackSection techniques={report.attack_techniques} />
      )}

      {report.grounding && (
        <GroundingSection
          grounding={report.grounding}
          shared={shared}
          open={groundingOpen}
          onOpenChange={setGroundingOpen}
        />
      )}

      <ProvenanceNote shared={shared} />

      <ReasoningChain steps={report.reasoning_chain} />
    </div>
  );
}

// Rendered inside #printable-report so it travels with the PDF: on /r the
// whole report came from the link, and the print stylesheet hides the
// interactive chips that carry the per-stamp "not verified" labels.
function SharedReportNote() {
  return (
    <div
      role="note"
      className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
      <p className="leading-relaxed">
        <span className="font-medium">Unverified content.</span> This report was decoded
        from a shared link. Anyone can write one, and this site did not produce or check
        it: the SSVC verdict and the grounding assessment are claims. Run the triage
        yourself for a result this deployment computed.
      </p>
    </div>
  );
}

// A report URL as a link only when it points at an allowed reference host
// (lib/external-link.ts); otherwise the label renders as plain text, so a
// model-written or permalink-forged URL never becomes an off-site link here.
function ExternalRef({
  url,
  className,
  icon = false,
  children,
}: {
  url: string;
  className: string;
  icon?: boolean;
  children: ReactNode;
}) {
  const href = allowedHref(url);
  if (!href) {
    return (
      <span className={className} title="Link withheld: not an NVD or MITRE ATT&CK URL">
        {children}
      </span>
    );
  }
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={cn(className, "text-primary hover:underline")}
    >
      {children}
      {icon && <ExternalLink className="ml-1 inline h-3 w-3" />}
    </a>
  );
}

// On /r the report is decoded from the link, so the server-side stamps
// (SSVC verdict, grounding) are claims made by whoever built the link: this
// chip replaces "deterministic, server-computed" there. `plain` renders a
// title-only span for spots inside another control (the grounding
// collapsible trigger), where a tooltip button would nest interactives.
function SharedClaimChip({ subject, plain = false }: { subject: string; plain?: boolean }) {
  const className =
    "rounded border border-warning/60 px-1.5 py-0.5 font-mono text-[10px] normal-case tracking-normal text-foreground";
  const gloss = `This ${subject} was read from the shared link, not computed by this site. Anyone can write a permalink, so treat it as a claim: re-run the triage to get a result this deployment computed.`;
  if (plain) {
    return (
      <span className={className} title={gloss}>
        from the link · not verified
      </span>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger
        className={cn(
          className,
          "cursor-help focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
        )}
      >
        from the link · not verified
      </TooltipTrigger>
      <TooltipContent>{gloss}</TooltipContent>
    </Tooltip>
  );
}

function SsvcVerdict({ ssvc, shared }: { ssvc: SsvcAssessment; shared: boolean }) {
  const meta = SSVC_META[ssvc.decision];
  const Icon = meta.icon;
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        <ShieldAlert className="h-3.5 w-3.5" />
        <span title="SSVC: Stakeholder-Specific Vulnerability Categorization, CISA's scheme for deciding how urgently to act on a vulnerability. A prioritization decision, not a severity score.">
          SSVC verdict
        </span>
        {shared ? (
          <SharedClaimChip subject="verdict" />
        ) : (
          <Tooltip>
            <TooltipTrigger className="cursor-help rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] normal-case tracking-normal text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background">
              deterministic · server-computed
            </TooltipTrigger>
            <TooltipContent>
              Computed by a fixed server-side rule from the signals the tools
              returned (KEV, EPSS, public exploits, ransomware use, CVSS), read from
              the run&apos;s own trajectory rather than from the fields the model
              wrote, after the model returns. The LLM does not pick this verdict; the
              same tool returns always produce the same decision.
            </TooltipContent>
          </Tooltip>
        )}
        <Link
          href="/guide#ssvc"
          className="ml-auto shrink-0 rounded text-[10px] font-normal normal-case tracking-normal text-primary hover:underline print:hidden"
        >
          What is SSVC?
        </Link>
      </div>
      <div
        className="grid grid-cols-4 gap-1"
        role="group"
        aria-label={`SSVC decision: ${ssvc.decision}`}
      >
        {SSVC_ORDER.map((decision) => {
          const active = decision === ssvc.decision;
          const stopMeta = SSVC_META[decision];
          const StopIcon = stopMeta.icon;
          return (
            <div
              key={decision}
              aria-current={active ? "true" : undefined}
              title={stopMeta.blurb}
              className={cn(
                "flex items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-semibold transition-colors",
                active ? stopMeta.activeClass : "bg-muted/40 text-muted-foreground",
              )}
            >
              <StopIcon className="h-3.5 w-3.5 shrink-0" />
              <span>{decision}</span>
            </div>
          );
        })}
      </div>
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
        <div className="space-y-0.5">
          <p className="text-[11px] font-medium text-muted-foreground">
            {ssvc.decision}: {meta.blurb}
          </p>
          {ssvc.rationale && (
            <p className="text-sm leading-relaxed">{ssvc.rationale}</p>
          )}
          <p className="text-[11px] text-muted-foreground">
            rule <span className="font-mono">{ssvc.rule}</span>
            {ssvc.driving_cve ? (
              <>
                {" · driven by "}
                <a
                  href={`#cve-${ssvc.driving_cve}`}
                  className="font-mono text-primary hover:underline"
                >
                  {ssvc.driving_cve}
                </a>
              </>
            ) : null}
          </p>
          <SsvcBasisNote ssvc={ssvc} />
        </div>
      </div>
      <SsvcDecisionTrace ssvc={ssvc} shared={shared} />
    </div>
  );
}

// The verdict is computed from the tool returns in the run's trajectory, not
// from the fields the model wrote. When a signal had no usable evidence the
// server falls back to the report for it and says so: this note is the
// operator-facing form of that stamp. Silent when every signal came from a
// tool return (the common case) or when the capture predates the field.
function SsvcBasisNote({ ssvc }: { ssvc: SsvcAssessment }) {
  if (!ssvc.basis || ssvc.basis === "evidence") return null;
  const unverified = ssvc.unverified_signals ?? [];
  const text =
    ssvc.basis === "report"
      ? "no trajectory was available; every signal was taken from the model's report"
      : `${unverified.length} signal${unverified.length === 1 ? "" : "s"} taken from the model's report, not from a tool return`;
  return (
    <p className="flex items-start gap-1.5 text-[11px] text-warning" role="note">
      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
      <span>
        <span className="font-medium">verdict basis: {ssvc.basis}</span>
        {" · "}
        {text}
        {unverified.length > 0 ? (
          <>
            {": "}
            <span className="font-mono">{unverified.join(", ")}</span>
          </>
        ) : null}
      </span>
    </p>
  );
}

function SignalCoverageStrip({ coverage, shared }: { coverage: FeedStatus[]; shared: boolean }) {
  if (!coverage || coverage.length === 0) return null;
  return (
    <div className="rounded-lg border border-border bg-card/50 p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        <Radar className="h-3.5 w-3.5" />
        Signal coverage
        <span className="normal-case tracking-normal text-muted-foreground">
          {shared
            ? "per-feed results as written in the shared link"
            : "what each feed actually returned; a miss or an error is reported as such, never hidden"}
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {coverage.map((feed) => {
          const statusMeta = COVERAGE_META[feed.status] ?? COVERAGE_META.not_queried;
          const StatusIcon = statusMeta.icon;
          const guideId = FEED_TO_GUIDE[feed.feed];
          const chipClass = cn(
            "inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2 py-1 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
            guideId ? "cursor-pointer hover:border-primary/40 hover:bg-accent" : "cursor-help",
          );
          const chipInner = (
            <>
              <StatusIcon className={cn("h-3.5 w-3.5 shrink-0", statusMeta.className)} />
              <span className="font-mono">{feed.feed}</span>
              <span className="text-muted-foreground">{statusMeta.label}</span>
            </>
          );
          return (
            <Tooltip key={feed.feed}>
              <TooltipTrigger asChild>
                {guideId ? (
                  <Link href={`/guide#${guideId}`} className={chipClass}>
                    {chipInner}
                  </Link>
                ) : (
                  <span tabIndex={0} className={chipClass}>
                    {chipInner}
                  </span>
                )}
              </TooltipTrigger>
              <TooltipContent>
                <div className="font-medium text-popover-foreground">
                  {FEED_GLOSS[feed.feed] ?? feed.feed}
                </div>
                <div className="mt-1 text-muted-foreground">{STATUS_GLOSS[feed.status]}</div>
                {feed.detail && (
                  <div className="mt-1 text-muted-foreground">{feed.detail}</div>
                )}
                {guideId && (
                  <div className="mt-1.5 text-primary">Open the guide section &rarr;</div>
                )}
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
}

function AttackSection({ techniques }: { techniques: TriageReport["attack_techniques"] }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        <Crosshair className="h-3 w-3" />
        MITRE ATT&CK ({techniques.length})
        <span className="normal-case tracking-normal text-muted-foreground">
          how an attacker would use these weaknesses, with mitigations
        </span>
        <Link
          href="/guide#attack"
          className="ml-auto shrink-0 text-[10px] font-normal normal-case tracking-normal text-primary hover:underline print:hidden"
        >
          What is ATT&CK?
        </Link>
      </div>
      {techniques.map((technique) => (
        <Card key={technique.id} className="overflow-hidden">
          <CardHeader className="space-y-2 pb-3">
            <div className="flex flex-wrap items-center gap-2">
              <ExternalRef url={technique.url} className="font-mono text-sm font-semibold" icon>
                {technique.id}
              </ExternalRef>
              <span className="text-sm font-medium">{technique.name}</span>
            </div>
            <div className="flex flex-wrap items-center gap-1">
              {technique.tactics.map((tactic) => (
                <Badge key={tactic} variant="secondary" className="text-[10px]">
                  {tactic}
                </Badge>
              ))}
              {technique.related_cwes.length > 0 && (
                <span
                  className="ml-2 text-[10px] text-muted-foreground"
                  title="CWE: Common Weakness Enumeration, the weakness class behind the CVE. ATT&CK techniques are derived from these ids."
                >
                  mapped from {technique.related_cwes.join(", ")}
                </span>
              )}
            </div>
          </CardHeader>
          {technique.mitigations.length > 0 && (
            <CardContent className="pt-0">
              <div className="mb-1.5 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                <Wrench className="h-3 w-3" />
                Mitigations
              </div>
              <ul className="space-y-1 text-xs">
                {technique.mitigations.map((m) => (
                  <li key={m.id} className="flex items-center gap-2">
                    <ExternalRef
                      url={m.url}
                      className="inline-flex min-h-6 shrink-0 items-center font-mono"
                    >
                      {m.id}
                    </ExternalRef>
                    <span className="leading-snug">{m.name}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          )}
        </Card>
      ))}
    </div>
  );
}

function GroundingBadge({
  grounding,
  shared,
  onClick,
}: {
  grounding: GroundingAssessment;
  shared: boolean;
  onClick: () => void;
}) {
  const meta = GROUNDING_META[grounding.status];
  // A shared "grounded" must not wear the success check: it is a claim.
  const Icon = shared ? CircleDashed : meta.icon;
  const flagged = grounding.unbacked + grounding.mismatched;
  const status =
    grounding.status === "grounded"
      ? `grounded ${grounding.supported}/${grounding.claims_checked}`
      : grounding.status === "suspect"
        ? `suspect ${flagged}/${grounding.claims_checked}`
        : "grounding not evaluated";
  const label = shared ? `claimed: ${status}` : status;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={onClick}
          className="rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background"
        >
          <Badge variant="outline" className="gap-1 text-xs uppercase tracking-wider">
            <Icon className={cn("h-3 w-3 shrink-0", shared ? "text-muted-foreground/60" : meta.iconClass)} />
            {label}
          </Badge>
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {shared
          ? "Grounding as written in the shared link. This site cannot re-run the verifier without the original tool results, so the status is a claim, not a check. Click for the per-claim breakdown the link carries."
          : "Deterministic grounding verification: after the model returns, the server re-checks every tool-derived claim (CVE identity, CVSS, KEV, EPSS, exploit flags, ATT&CK ids) against the tool results captured from the run. Not the model's self-assessment. Click for the per-claim breakdown."}
      </TooltipContent>
    </Tooltip>
  );
}

function GroundingSection({
  grounding,
  shared,
  open,
  onOpenChange,
}: {
  grounding: GroundingAssessment;
  shared: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const meta = GROUNDING_META[grounding.status];
  const StatusIcon = shared ? CircleDashed : meta.icon;
  const counters: { label: string; value: number; claimStatus: GroundingClaimStatus }[] = [
    { label: "supported", value: grounding.supported, claimStatus: "supported" },
    { label: "unbacked", value: grounding.unbacked, claimStatus: "unbacked" },
    { label: "mismatched", value: grounding.mismatched, claimStatus: "mismatch" },
    { label: "unverifiable", value: grounding.unverifiable, claimStatus: "unverifiable" },
  ];
  return (
    <Collapsible open={open} onOpenChange={onOpenChange}>
      <Card id="grounding-section" className="scroll-mt-20">
        <CollapsibleTrigger asChild>
          <button className="flex w-full items-center justify-between p-4 text-left transition-colors hover:bg-accent">
            <div className="flex flex-wrap items-center gap-2">
              <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Grounding verification
              </span>
              {shared ? (
                <SharedClaimChip subject="grounding assessment" plain />
              ) : (
                <span
                  className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] normal-case tracking-normal text-muted-foreground"
                  title="Computed by a fixed server-side verifier from the tool results captured in the run's message history, after the model returns. The LLM does not produce this assessment; the same run always verifies the same way."
                >
                  deterministic · server-computed
                </span>
              )}
              <Badge variant="secondary" className="gap-1 text-[10px]">
                <StatusIcon className={cn("h-3 w-3 shrink-0", shared ? "text-muted-foreground/60" : meta.iconClass)} />
                {shared ? `claimed: ${meta.label}` : meta.label}
              </Badge>
              <span className="text-[11px] normal-case tracking-normal text-muted-foreground">
                {shared
                  ? "as written in the shared link; this site cannot re-run the check"
                  : "every tool-derived claim re-checked against what the tools actually returned"}
              </span>
            </div>
            <ChevronDown
              className={cn(
                "h-4 w-4 shrink-0 text-muted-foreground transition-transform",
                open && "rotate-180",
              )}
            />
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <Separator />
          <CardContent className="space-y-3 pt-4">
            <p className="text-sm leading-relaxed">
              {shared ? `The link claims: ${meta.gloss}` : meta.gloss}
            </p>
            {grounding.status !== "not_evaluated" && (
              <div className="flex flex-wrap gap-1.5">
                <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2 py-1 text-[11px]">
                  <span className="font-mono">{grounding.claims_checked}</span>
                  <span className="text-muted-foreground">claims checked</span>
                </span>
                {counters
                  .filter((c) => c.value > 0)
                  .map((c) => {
                    const claimMeta = CLAIM_META[c.claimStatus];
                    const CounterIcon = claimMeta.icon;
                    return (
                      <span
                        key={c.label}
                        title={claimMeta.tooltip}
                        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2 py-1 text-[11px]"
                      >
                        <CounterIcon className={cn("h-3.5 w-3.5 shrink-0", claimMeta.className)} />
                        <span className="font-mono">{c.value}</span>
                        <span className="text-muted-foreground">{c.label}</span>
                      </span>
                    );
                  })}
              </div>
            )}
            {grounding.status === "grounded" && (
              <p className="text-xs text-muted-foreground">
                {grounding.claims_checked === 0
                  ? "The report makes no checkable tool-derived claims."
                  : shared
                    ? `The link claims all ${grounding.claims_checked} tool-derived claims matched the tool returns of its run.`
                    : `All ${grounding.claims_checked} tool-derived claims match the tool returns captured from this run.`}
              </p>
            )}
            {grounding.findings.length > 0 && (
              <ul className="space-y-2 text-sm">
                {grounding.findings.map((finding, i) => {
                  const claimMeta = CLAIM_META[finding.status];
                  const FindingIcon = claimMeta.icon;
                  const isCve = /^CVE-\d{4}-\d+$/i.test(finding.subject);
                  return (
                    <li key={i} className="flex items-start gap-2">
                      <FindingIcon
                        className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", claimMeta.className)}
                      />
                      <div className="space-y-0.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {isCve ? (
                            <a
                              href={`#cve-${finding.subject.toUpperCase()}`}
                              className="font-mono text-xs font-semibold text-primary hover:underline"
                            >
                              {finding.subject}
                            </a>
                          ) : (
                            <span className="font-mono text-xs font-semibold">
                              {finding.subject}
                            </span>
                          )}
                          <span className="font-mono text-xs text-muted-foreground">
                            {finding.field}
                          </span>
                          <Badge
                            variant="secondary"
                            className="text-[10px]"
                            title={claimMeta.tooltip}
                          >
                            {claimMeta.label}
                          </Badge>
                        </div>
                        {finding.detail && (
                          <p className="text-xs leading-snug text-muted-foreground">
                            {finding.detail}
                          </p>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
            {grounding.truncated && (
              <p className="text-[11px] text-muted-foreground">
                Findings list truncated at 40 entries; the counters above remain complete.
              </p>
            )}
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}

function ReasoningChain({ steps }: { steps: string[] }) {
  const [open, setOpen] = useState(false);
  if (steps.length === 0) return null;

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <Card>
        <CollapsibleTrigger asChild>
          <button className="flex w-full items-center justify-between p-4 text-left transition-colors hover:bg-accent">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Reasoning chain
              </span>
              <Badge variant="secondary" className="text-[10px]">
                {steps.length} steps
              </Badge>
              <span className="text-[11px] normal-case tracking-normal text-muted-foreground">
                the agent&apos;s own log of tool calls and decisions, in order
              </span>
            </div>
            <ChevronDown
              className={cn(
                "h-4 w-4 text-muted-foreground transition-transform",
                open && "rotate-180",
              )}
            />
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <Separator />
          <CardContent className="pt-4">
            <ol className="space-y-2 text-sm">
              {steps.map((step, i) => (
                <li key={i} className="flex gap-3">
                  <span className="select-none font-mono text-xs text-muted-foreground">
                    {(i + 1).toString().padStart(2, "0")}
                  </span>
                  <span className="leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
