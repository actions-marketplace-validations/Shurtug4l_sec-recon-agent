"use client";

import { useState } from "react";
import Link from "next/link";
import { AlertTriangle, ChevronDown, Cpu, Database, Fingerprint, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Separator } from "@/components/ui/separator";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

// A report is not one undifferentiated blob of model output. Three distinct
// authorities produce its parts, and the security posture rests on keeping them
// separate. This note states that boundary once, plainly: the glass-box thesis.
interface Lane {
  icon: typeof Cpu;
  title: string;
  authority: string;
  accent: string; // icon + chip tint
  detail: string;
  fields: string[];
}

const LANES: Lane[] = [
  {
    icon: Fingerprint,
    title: "Deterministic",
    authority: "server-computed, not the model",
    accent: "text-primary",
    detail:
      "Fixed code runs after the model returns and stamps these onto the report. The same signals always produce the same result; the LLM only echoes it in prose.",
    fields: ["SSVC verdict", "grounding verification"],
  },
  {
    icon: Cpu,
    title: "Model-authored",
    authority: "written by the LLM, tool-grounded",
    accent: "text-warning",
    detail:
      "The LLM writes these, constrained to a typed TriageReport schema and grounded in the tool returns. The grounding verifier re-checks every tool-derived claim against what the tools actually returned.",
    fields: ["summary", "recommended action", "confidence", "reasoning chain"],
  },
  {
    icon: Database,
    title: "External feed data",
    authority: "verbatim from the source feeds",
    accent: "text-[hsl(var(--severity-low))]",
    detail:
      "Pulled from NVD, CISA KEV, FIRST EPSS, Exploit-DB / GitHub, OSV.dev and MITRE ATT&CK by the typed tools. Untrusted free text (vendor descriptions, scan banners) is fenced before reaching the model so it is read as data, not instructions.",
    fields: ["CVE / CVSS / CWE", "KEV + EPSS", "exploit signals", "ATT&CK mapping"],
  },
];

export function ProvenanceNote({ shared = false }: { shared?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <Card id="provenance-note" className="scroll-mt-20">
        <CollapsibleTrigger asChild>
          <button className="flex w-full items-center justify-between p-4 text-left transition-colors hover:bg-accent">
            <div className="flex flex-wrap items-center gap-2">
              <Fingerprint className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Provenance
              </span>
              <span className="text-[11px] normal-case tracking-normal text-muted-foreground">
                which part of this report came from where, and who holds the pen
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
          <CardContent className="space-y-4 pt-4">
            <div className="grid gap-3 sm:grid-cols-3">
              {LANES.map((lane) => {
                const Icon = lane.icon;
                return (
                  <div
                    key={lane.title}
                    className="rounded-lg border border-border bg-background p-3"
                  >
                    <div className="flex items-center gap-2">
                      <Icon className={cn("h-4 w-4 shrink-0", lane.accent)} />
                      <span className="text-sm font-semibold">{lane.title}</span>
                    </div>
                    <p className="mt-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                      {lane.authority}
                    </p>
                    <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                      {lane.detail}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {lane.fields.map((f) => (
                        <Badge key={f} variant="secondary" className="text-[10px]">
                          {f}
                        </Badge>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
            <div
              className={cn(
                "flex items-start gap-2 rounded-lg border p-3",
                shared ? "border-warning/40 bg-warning/10" : "border-primary/20 bg-primary/5",
              )}
            >
              {shared ? (
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
              ) : (
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              )}
              {shared ? (
                <p className="text-xs leading-relaxed">
                  These lanes describe a live run. This report came from a shared
                  link, so none of them can be checked here: anyone who writes the
                  link holds every pen, the deterministic lane included.{" "}
                  <Link
                    href="/guide#ssvc"
                    className="font-medium text-primary hover:underline print:hidden"
                  >
                    How the verdict is decided
                  </Link>
                  .
                </p>
              ) : (
                <p className="text-xs leading-relaxed">
                  This boundary is the injection-resistance story: a prompt injection
                  that fully persuades the model still cannot move the verdict from{" "}
                  <span className="font-semibold">Act</span> to{" "}
                  <span className="font-semibold">Track</span>, because the model
                  does not hold that pen. The deterministic lane does.{" "}
                  <Link
                    href="/guide#ssvc"
                    className="font-medium text-primary hover:underline print:hidden"
                  >
                    How the verdict is decided
                  </Link>
                  .
                </p>
              )}
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
