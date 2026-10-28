"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, Link2, Search, TriangleAlert } from "lucide-react";

import { Header } from "@/components/header";
import { TriageReportView } from "@/components/triage-report-view";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { decodeReport } from "@/lib/permalink";
import type { SharedReport } from "@/lib/permalink";

type Status = "loading" | "ok" | "empty" | "error";

export default function SharedReportPage() {
  const [shared, setShared] = useState<SharedReport | null>(null);
  const [status, setStatus] = useState<Status>("loading");

  useEffect(() => {
    // The payload lives in the URL fragment (#r=...), which the browser never
    // sends to the server. Decode it locally.
    const match = window.location.hash.match(/[#&]r=([^&]+)/);
    if (!match) {
      setStatus("empty");
      return;
    }
    let cancelled = false;
    decodeReport(decodeURIComponent(match[1])).then((decoded) => {
      if (cancelled) return;
      if (decoded) {
        setShared(decoded);
        setStatus("ok");
      } else {
        setStatus("error");
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main id="main-content" tabIndex={-1} className="container max-w-3xl flex-1 py-8 focus-visible:outline-none">
        {status === "loading" && (
          <p className="py-16 text-center text-sm text-muted-foreground">
            Decoding shared report...
          </p>
        )}

        {(status === "empty" || status === "error") && (
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center gap-3 py-14 text-center">
              <TriangleAlert className="h-6 w-6 text-warning" />
              <div>
                <p className="text-sm font-medium">
                  {status === "empty" ? "No shared report in this link" : "Could not read this shared report"}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {status === "empty"
                    ? "A permalink carries the full report in the URL fragment (#r=...)."
                    : "The link may be truncated or corrupted."}
                </p>
              </div>
              <Button asChild size="sm">
                <Link href="/triage">
                  Run a triage <ArrowRight className="h-4 w-4" />
                </Link>
              </Button>
            </CardContent>
          </Card>
        )}

        {status === "ok" && shared && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Link2 className="h-4 w-4 text-primary" />
                Shared report: decoded locally from the link, nothing sent to a server.
              </div>
              <Button asChild size="sm" variant="outline">
                <Link href="/triage">
                  Run your own <ArrowRight className="h-4 w-4" />
                </Link>
              </Button>
            </div>
            {shared.query && (
              <div className="rounded-lg border border-border bg-card/50 p-3">
                <div className="mb-1 flex flex-wrap items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  <Search className="h-3.5 w-3.5" />
                  Query
                  {shared.queryTruncated && (
                    <span className="normal-case tracking-normal text-muted-foreground/70">
                      clipped to fit the link
                    </span>
                  )}
                </div>
                <p
                  tabIndex={0}
                  className="max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
                >
                  {shared.query}
                </p>
              </div>
            )}
            {/* Anyone can mint a permalink with any content: shared mode opens
                the report with an "unverified" note (kept in print) and shows
                the verdict and grounding as claims, not as checks. */}
            <TriageReportView report={shared.report} query={shared.query} shared />
          </div>
        )}
      </main>
    </div>
  );
}
