"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, ArrowRight, CircleCheck, Radar, Zap } from "lucide-react";

import { cn } from "@/lib/utils";

type Decision = "Act" | "Attend" | "Track*" | "Track";

// The hero instrument replays FACTS, it does not stage them: one real
// captured case per SSVC rung, with the CVE id, rule and rationale taken
// verbatim from the server-stamped verdicts in src/demo/fixtures/*.json.
// If a re-capture ever changes a verdict, update this table with it.
const CASES: {
  decision: Decision;
  cve: string;
  title: string;
  subtitle: string;
  rule: string;
  why: string;
}[] = [
  {
    decision: "Act",
    cve: "CVE-2021-44228",
    title: "Log4Shell",
    subtitle: "Apache Log4j JNDI lookup RCE",
    rule: "ransomware",
    why: "On the CISA KEV catalog and associated with known ransomware campaigns.",
  },
  {
    decision: "Attend",
    cve: "CVE-2024-52046",
    title: "Apache MINA",
    subtitle: "Java deserialization RCE",
    rule: "high-epss",
    why: "EPSS predicts high near-term exploitation likelihood.",
  },
  {
    decision: "Track*",
    cve: "CVE-2024-45491",
    title: "libexpat overflow",
    subtitle: "XML parser integer overflow",
    rule: "high-severity-no-exploitation",
    why: "High CVSS severity with no observed exploitation signal yet.",
  },
  {
    decision: "Track",
    cve: "CVE-2024-35195",
    title: "requests TLS bypass",
    subtitle: "Session verify=False stickiness",
    rule: "baseline",
    why: "No active-exploitation, public-exploit, or high-EPSS signal observed.",
  },
];

// Rung styling mirrors the report's SsvcVerdict ladder (triage-report-view
// SSVC_META) so the hero teaches the exact visual language the report speaks:
// position encodes urgency, the active stop carries icon + fill + text, never
// color alone.
//
// Fill and text are separate classes on purpose: the fill is an aria-hidden
// sibling of the label (it sweeps in under it), so a text color set on the fill
// never reaches the label. One combined class left the active label on the
// default foreground over a saturated fill (2.5:1), caught by axe-core 4.13.
const RUNG_META: Record<
  Decision,
  { icon: typeof Zap; fillClass: string; textClass: string; gloss: string }
> = {
  Act: {
    icon: Zap,
    fillClass: "bg-destructive",
    textClass: "text-destructive-foreground",
    gloss: "remediate out-of-cycle",
  },
  Attend: {
    icon: AlertTriangle,
    fillClass: "bg-warning",
    textClass: "text-warning-foreground",
    gloss: "ahead of standard timelines",
  },
  "Track*": {
    icon: Radar,
    fillClass: "bg-[hsl(var(--severity-low))]",
    textClass: "text-background",
    gloss: "standard timeline, watch for escalation",
  },
  Track: {
    icon: CircleCheck,
    fillClass: "bg-secondary ring-1 ring-inset ring-primary/30",
    textClass: "text-foreground",
    gloss: "standard update timelines",
  },
};

const CYCLE_MS = 5500;

// The signature moment: an SSVC ladder reading real verdicts like an
// instrument. Auto-advances through the four cases; hover/focus pauses,
// clicking a rung jumps, prefers-reduced-motion disables the cycle entirely
// (the static Act state still renders complete).
export function SsvcLadderHero() {
  const [active, setActive] = useState(0);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (paused) return;
    const id = setInterval(() => {
      // Skip ticks in a hidden tab so the reading does not jump on return.
      if (!document.hidden) setActive((i) => (i + 1) % CASES.length);
    }, CYCLE_MS);
    return () => clearInterval(id);
  }, [paused]);

  const current = CASES[active];

  return (
    <div
      className="relative overflow-hidden rounded-xl border border-border bg-gradient-to-b from-card to-background p-5 shadow-sm md:p-6"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocusCapture={() => setPaused(true)}
      onBlurCapture={() => setPaused(false)}
    >
      {/* Instrument-screen scanline, hero-only by design (P0 primitive). */}
      <div aria-hidden className="scanline-overlay pointer-events-none absolute inset-0" />

      <div className="relative">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            SSVC verdict
          </p>
          <span className="rounded-full border border-border bg-card px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
            deterministic · server-computed
          </span>
        </div>
        <div className="rule-hairline mt-3" aria-hidden />

        <div
          role="group"
          aria-label="SSVC ladder, one real captured verdict per stop"
          className="mt-4 space-y-1.5"
        >
          {CASES.map((c, i) => {
            const meta = RUNG_META[c.decision];
            const Icon = meta.icon;
            const isActive = i === active;
            return (
              <button
                key={c.decision}
                type="button"
                onClick={() => setActive(i)}
                aria-pressed={isActive}
                aria-label={`${c.decision}: ${c.cve} (${c.title})`}
                className={cn(
                  "relative block w-full overflow-hidden rounded-md border text-left transition-colors duration-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
                  isActive ? "border-transparent" : "border-border/70 hover:border-primary/40",
                )}
              >
                {/* Fill sweeps in from the left when the rung becomes the verdict. */}
                <span
                  aria-hidden
                  className={cn(
                    "absolute inset-0 origin-left transition-transform duration-500 ease-out",
                    meta.fillClass,
                    isActive ? "scale-x-100" : "scale-x-0",
                  )}
                />
                <span
                  className={cn(
                    "relative flex items-center gap-2.5 px-3 py-2 transition-colors duration-300",
                    isActive ? meta.textClass : "text-muted-foreground",
                  )}
                >
                  <Icon className="h-3.5 w-3.5 shrink-0" />
                  <span className="font-display text-sm font-semibold tracking-tight">
                    {c.decision}
                  </span>
                  <span
                    className={cn(
                      "ml-auto hidden font-mono text-[10px] sm:inline",
                      // Full opacity when active: at 80% the 10px id drops below
                      // 4.5:1 on three of the four light-theme fills.
                      !isActive && "opacity-60",
                    )}
                  >
                    {isActive ? c.cve : meta.gloss}
                  </span>
                </span>
              </button>
            );
          })}
        </div>

        {/* Instrument reading: the case behind the active rung. Keyed remount
            re-runs the fade so the reading visibly updates on each cycle. */}
        <div key={current.cve} className="mt-4 animate-fade-in">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className="font-mono text-sm font-semibold text-primary">{current.cve}</span>
            <span className="text-sm font-semibold">{current.title}</span>
            <span className="text-xs text-muted-foreground">· {current.subtitle}</span>
          </div>
          <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
            {current.why}{" "}
            <span className="whitespace-nowrap">
              rule <code className="font-mono text-foreground/80">{current.rule}</code>
            </span>
          </p>
        </div>

        <div className="rule-hairline mt-4" aria-hidden />
        <div className="mt-3 flex items-center justify-between gap-2">
          <p className="text-[11px] text-muted-foreground">
            Four real captured runs, one per rung. The verdict is computed in
            code from the collected signals, never by the model.
          </p>
          <Link
            href="/triage"
            className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-primary hover:underline"
          >
            Replay them <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>
    </div>
  );
}
