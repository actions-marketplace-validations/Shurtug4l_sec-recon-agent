"use client";

import { useMemo } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Crosshair,
  Flame,
  ShieldX,
  Skull,
  TrendingUp,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBarChart, ToolActivityBars } from "@/components/dashboard/charts";
import { KpiCard } from "@/components/dashboard/kpi-card";
import { allowedHref } from "@/lib/external-link";
import { aggregate, formatDuration } from "@/lib/stats";
import type { HistoryEntry } from "@/lib/types";

export function StatisticsTab({ entries }: { entries: HistoryEntry[] }) {
  const stats = useMemo(() => aggregate(entries), [entries]);

  if (entries.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          Run a triage from the home page to populate the dashboard.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="Total runs" value={stats.totalRuns} icon={Activity} />
        <KpiCard
          label="Avg time"
          value={formatDuration(stats.avgDurationMs)}
          hint={`across ${stats.completedRuns} completed`}
          icon={Clock}
        />
        <KpiCard
          label="Critical"
          value={stats.criticalCount}
          hint={`${stats.highCount} high`}
          icon={ShieldX}
          accent="critical"
        />
        <KpiCard
          label="Success rate"
          value={
            stats.totalRuns > 0
              ? `${Math.round((stats.completedRuns / stats.totalRuns) * 100)}%`
              : "n/a"
          }
          hint={stats.errorRuns > 0 ? `${stats.errorRuns} errored` : "no errors"}
          icon={CheckCircle2}
          accent="success"
        />
      </div>

      <p className="text-[11px] text-muted-foreground">
        Threat signals over the CVEs in your completed reports; a CVE reported in two runs
        counts twice.
      </p>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <KpiCard
          label="CISA KEV"
          value={stats.kevCount}
          hint="on CISA's Known Exploited Vulnerabilities catalog: exploited in the wild"
          icon={Flame}
          accent={stats.kevCount > 0 ? "critical" : "default"}
        />
        <KpiCard
          label="Ransomware"
          value={stats.ransomwareCount}
          hint="known ransomware use, per the KEV catalog"
          icon={Skull}
          accent={stats.ransomwareCount > 0 ? "critical" : "default"}
        />
        <KpiCard
          label="High EPSS"
          value={stats.highEpssCount}
          hint="EPSS exploit probability >= 0.5 (FIRST.org 30-day forecast)"
          icon={TrendingUp}
          accent={stats.highEpssCount > 0 ? "high" : "default"}
        />
      </div>

      {/* min-w-0 on the grid items: a grid cell's default min-width:auto lets it
          grow to its content's intrinsic size, and Recharts' ResponsiveContainer
          briefly reports a wide default before its ResizeObserver measures the
          parent — that flash made the cell (and the page) overflow on a 360px
          phone. min-w-0 lets the cell shrink to the track, so width="100%"
          resolves to the real column width with no flash. */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Severity distribution</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              Final severity of each completed report (the highest CVSS severity across its
              CVEs). One bar per level; the y-axis counts runs.
            </p>
          </CardHeader>
          <CardContent>
            <SeverityBarChart data={stats.bySeverity} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Tool call counts</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              Counted by matching tool names in each report&apos;s reasoning chain (the
              agent&apos;s self-reported audit log), not from server-side telemetry. Exact
              per-call data lives in the OpenTelemetry traces (observability tab).
            </p>
          </CardHeader>
          <CardContent>
            <ToolActivityBars data={stats.toolCalls} />
          </CardContent>
        </Card>
      </div>

      {stats.topCves.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Most-referenced CVEs</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              CVEs that appear most often across your triage reports. CVSS is the 0-10 base
              severity score from NVD (higher = more severe); links open the NVD record.
            </p>
          </CardHeader>
          <CardContent className="space-y-1">
            {stats.topCves.map((cve) => (
              <div
                key={cve.cveId}
                className="flex items-center justify-between rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent"
              >
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-primary hover:underline"
                >
                  {cve.cveId}
                </a>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  {cve.cvss !== null && (
                    <span className="tabular-nums">CVSS {cve.cvss.toFixed(1)}</span>
                  )}
                  <span className="tabular-nums">
                    {cve.count}
                    {cve.count > 1 && " refs"}
                  </span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {stats.topAttackTechniques.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Crosshair className="h-4 w-4" />
              Top ATT&CK techniques
            </CardTitle>
            <p className="text-[11px] text-muted-foreground">
              MITRE ATT&amp;CK techniques (the standard catalog of adversary behaviors)
              that the agent mapped from the CVEs&apos; weakness types: how an attacker
              would actually use the flaw. Gray labels are the ATT&amp;CK tactics; links
              open the MITRE page.
            </p>
          </CardHeader>
          <CardContent className="space-y-1">
            {stats.topAttackTechniques.map((technique) => (
              <a
                key={technique.id}
                // Model-written URL from history: only allowed reference hosts
                // get an href (lib/external-link.ts); otherwise a plain row.
                href={allowedHref(technique.url) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <span className="font-mono text-primary">{technique.id}</span>
                  <span className="truncate">{technique.name}</span>
                </div>
                <div className="flex shrink-0 items-center gap-3 text-xs text-muted-foreground">
                  <span className="hidden truncate sm:inline">
                    {technique.tactics.slice(0, 2).join(", ")}
                  </span>
                  <span className="tabular-nums">
                    {technique.count}
                    {technique.count > 1 && " refs"}
                  </span>
                </div>
              </a>
            ))}
          </CardContent>
        </Card>
      )}

      {stats.errorRuns > 0 && (
        <Card className="border-destructive/40">
          <CardContent className="flex items-center gap-3 p-4">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <p className="text-sm">
              {stats.errorRuns} run{stats.errorRuns > 1 ? "s" : ""} ended in an error.
              Check the observability tab for the timeline.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
