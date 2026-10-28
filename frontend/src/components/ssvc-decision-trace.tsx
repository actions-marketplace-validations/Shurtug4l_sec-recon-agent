"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ChevronDown,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CircleSlash,
  GitBranch,
  Radar,
  Zap,
} from "lucide-react";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { SSVC_TRACE_EVENT } from "@/lib/nav-events";
import { cn } from "@/lib/utils";
import type { SsvcAssessment, SsvcDecision } from "@/lib/types";

// Static mirror of the eight first-match-wins rules in
// src/sec_recon_agent/agent/ssvc.py::decide_for_signals. THAT function is the
// authority; this table only re-tells it so the report can show WHY a verdict
// was reached, not just its rule id. Keep the ids, order, and outcomes in sync
// with the backend (a new or reordered rule there must change this table). The
// thresholds match the module constants (EPSS high = 0.5 prob or 0.95
// percentile; elevated = 0.10 prob).
interface Rule {
  id: string;
  outcome: SsvcDecision;
  when: string; // plain-language condition, in the LLM-free voice of the code
  signal: string; // the mono predicate, mirroring the guard in the code
}

const SSVC_RULES: Rule[] = [
  {
    id: "ransomware",
    outcome: "Act",
    when: "Associated with known ransomware campaigns (CISA's top escalator on a KEV entry).",
    signal: "known_ransomware = true",
  },
  {
    id: "kev-active-exploitation",
    outcome: "Act",
    when: "On the CISA KEV catalog: exploitation in the wild is confirmed, not predicted.",
    signal: "in_kev = true",
  },
  {
    id: "public-exploit+high-epss",
    outcome: "Act",
    when: "Public exploit code exists and EPSS predicts high near-term exploitation: effectively imminent.",
    signal: "exploit_public AND epss_high",
  },
  {
    id: "public-exploit",
    outcome: "Attend",
    when: "A public exploit or proof-of-concept exists, without an active-exploitation or high-EPSS signal.",
    signal: "exploit_public",
  },
  {
    id: "high-epss",
    outcome: "Attend",
    when: "EPSS predicts high near-term exploitation, with no known public exploit yet.",
    signal: "epss_high",
  },
  {
    id: "elevated-epss",
    outcome: "Track*",
    when: "EPSS is elevated but below the high-risk threshold: worth watching, not yet attending.",
    signal: "epss_probability >= 0.10",
  },
  {
    id: "high-severity-no-exploitation",
    outcome: "Track*",
    when: "High or critical CVSS severity with no exploitation signal observed yet.",
    signal: "severity in {critical, high}",
  },
  {
    id: "baseline",
    outcome: "Track",
    when: "No active-exploitation, public-exploit, or high-EPSS signal observed.",
    signal: "default",
  },
];

// Outcome accent, redundant with the outcome label (never color alone). Mirrors
// the report's SsvcVerdict ladder and the hero's RUNG_META rather than importing
// either (importing triage-report-view would cycle; the hero is a sibling).
const OUTCOME_META: Record<
  SsvcDecision,
  { icon: typeof Zap; badgeClass: string }
> = {
  Act: { icon: Zap, badgeClass: "border-destructive/40 text-destructive" },
  Attend: { icon: AlertTriangle, badgeClass: "border-warning/40 text-warning" },
  "Track*": {
    icon: Radar,
    badgeClass: "border-[hsl(var(--severity-low))]/40 text-[hsl(var(--severity-low))]",
  },
  Track: { icon: CircleCheck, badgeClass: "border-border text-muted-foreground" },
};

type RowStatus = "matched" | "ruled-out" | "not-reached" | "not-evaluated";

const STATUS_META: Record<
  RowStatus,
  { icon: typeof CircleDot; label: string; iconClass: string }
> = {
  matched: { icon: CircleDot, label: "matched", iconClass: "text-primary" },
  "ruled-out": { icon: CircleSlash, label: "not matched", iconClass: "text-muted-foreground" },
  "not-reached": { icon: CircleDashed, label: "not reached", iconClass: "text-muted-foreground/70" },
  "not-evaluated": { icon: CircleDashed, label: "not evaluated", iconClass: "text-muted-foreground/70" },
};

export function SsvcDecisionTrace({
  ssvc,
  shared = false,
}: {
  ssvc: SsvcAssessment;
  shared?: boolean;
}) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function reveal() {
      setOpen(true);
      const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      document
        .getElementById("ssvc-decision-trace")
        ?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "center" });
    }
    window.addEventListener(SSVC_TRACE_EVENT, reveal);
    return () => window.removeEventListener(SSVC_TRACE_EVENT, reveal);
  }, []);

  // -1 when the fired rule is not one of the eight (the "no-cves" sentinel that
  // assess_from_signals emits when nothing was grounded): every rule then reads
  // "not evaluated" and the note below explains the default-Track fall-through.
  const matchedIndex = SSVC_RULES.findIndex((r) => r.id === ssvc.rule);
  const noCvesGrounded = matchedIndex === -1;

  function statusFor(i: number): RowStatus {
    if (noCvesGrounded) return "not-evaluated";
    if (i < matchedIndex) return "ruled-out";
    if (i === matchedIndex) return "matched";
    return "not-reached";
  }

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div id="ssvc-decision-trace" className="scroll-mt-24">
        <CollapsibleTrigger asChild>
          <button
            type="button"
            className="group inline-flex items-center gap-1.5 rounded text-[11px] font-medium text-primary transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background print:hidden"
          >
            <GitBranch className="h-3.5 w-3.5" />
            {open ? "Hide decision trace" : "Show decision trace"}
            <ChevronDown
              className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")}
            />
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="mt-3 rounded-lg border border-border bg-background p-3">
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              First-match-wins over eight fixed rules, checked top to bottom
              {ssvc.driving_cve ? (
                <>
                  {" for "}
                  <a
                    href={`#cve-${ssvc.driving_cve}`}
                    className="font-mono text-primary hover:underline"
                  >
                    {ssvc.driving_cve}
                  </a>
                </>
              ) : null}
              . The first rule whose condition holds sets the verdict; the rules
              below it are never reached. This ladder is a static mirror of{" "}
              <code className="font-mono text-foreground/80">agent/ssvc.py</code>,
              the code that actually decides.
              {shared
                ? " On a shared link the rule id comes from the link itself, so the matched row is the link's claim, not a decision this site made."
                : ""}
            </p>

            <ol className="mt-3 space-y-1">
              {SSVC_RULES.map((rule, i) => {
                const status = statusFor(i);
                const statusMeta = STATUS_META[status];
                const StatusIcon = statusMeta.icon;
                const outcomeMeta = OUTCOME_META[rule.outcome];
                const OutcomeIcon = outcomeMeta.icon;
                const isMatch = status === "matched";
                return (
                  <li
                    key={rule.id}
                    className={cn(
                      "rounded-md border px-2.5 py-2 transition-colors",
                      isMatch ? "border-primary/40 bg-primary/5" : "border-transparent",
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <StatusIcon
                        className={cn("h-3.5 w-3.5 shrink-0", statusMeta.iconClass)}
                      />
                      <code
                        className={cn(
                          "font-mono text-xs",
                          isMatch ? "font-semibold text-foreground" : "text-muted-foreground",
                        )}
                      >
                        {rule.id}
                      </code>
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
                          outcomeMeta.badgeClass,
                        )}
                      >
                        <OutcomeIcon className="h-3 w-3 shrink-0" />
                        {rule.outcome}
                      </span>
                      <span
                        className={cn(
                          "ml-auto text-[10px] uppercase tracking-wider",
                          isMatch ? "font-semibold text-primary" : "text-muted-foreground",
                        )}
                      >
                        {statusMeta.label}
                      </span>
                    </div>
                    <p className="mt-1 pl-[1.375rem] text-[11px] leading-snug text-muted-foreground">
                      {rule.when}{" "}
                      <code className="whitespace-nowrap font-mono text-foreground/80">
                        {rule.signal}
                      </code>
                    </p>
                  </li>
                );
              })}
            </ol>

            {noCvesGrounded && (
              <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
                No CVE was grounded in this triage, so no rule fired; the verdict
                defaults to <span className="font-semibold">Track</span>.
              </p>
            )}

            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2">
              <p className="text-[10px] leading-relaxed text-muted-foreground">
                EPSS thresholds: <span className="font-mono">epss_high</span> = probability
                &ge; 50% or percentile &ge; 95; elevated = probability &ge; 10%.
              </p>
              <Link
                href="/guide#ssvc"
                className="shrink-0 text-[10px] font-medium text-primary hover:underline print:hidden"
              >
                What is SSVC?
              </Link>
            </div>
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}
