"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import dynamic from "next/dynamic";
import { AreaChart } from "@tremor/react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityPill } from "@/components/severity-pill";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import type { DashboardSummary, Severity } from "@/lib/types";

const DashboardMap = dynamic(() => import("@/components/dashboard-map"), {
  ssr: false,
  loading: () => <p className="p-8 text-center text-sm text-muted-foreground">Loading map…</p>,
});

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function KpiTile({
  label,
  value,
  color,
  href,
}: {
  label: string;
  value: number | undefined;
  color?: string;
  href?: string;
}) {
  const body = (
    <Card className={href ? "transition-colors hover:border-ring/50" : undefined}>
      <CardContent className="p-4">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
        <p className="mt-1 text-2xl font-semibold tabular-nums" style={color ? { color } : undefined}>
          {value ?? 0}
        </p>
      </CardContent>
    </Card>
  );
  return href ? <Link href={href}>{body}</Link> : body;
}

export default function DashboardPage() {
  const { user, loading, logout } = useAuth();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<DashboardSummary>("/api/dashboard/summary")
      .then((data) => {
        setSummary(data);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load dashboard"));
  }, []);

  useEffect(() => {
    if (loading) return;
    load();
    // ponytail: 60s polling is plenty for feed ingestion dashboards
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, [loading, load]);

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center text-muted-foreground">Loading…</main>
    );
  }

  const empty = !!summary && summary.kpis.total_iocs === 0;

  return (
    <main className="mx-auto max-w-6xl p-8">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="text-xl font-semibold tracking-tight">ThreatIntelHub</h1>
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-muted-foreground">
            {user?.email} · {summary?.kpis.active_feeds ?? 0} active feeds
          </span>
          <Button asChild variant="ghost">
            <Link href="/settings">Settings</Link>
          </Button>
          <Button asChild variant="ghost">
            <Link href="/reports">Reports</Link>
          </Button>
          <Button asChild variant="ghost">
            <Link href="/yara">YARA</Link>
          </Button>
          <Button asChild variant="outline">
            <Link href="/iocs">Browse IOCs</Link>
          </Button>
          <Button variant="outline" onClick={logout}>
            Log out
          </Button>
        </div>
      </header>

      {error && <p className="mt-4 text-sm text-red-500">{error}</p>}

      {!summary && !error ? (
        <p className="mt-8 text-sm text-muted-foreground">Loading…</p>
      ) : summary ? (
        <>
          <section className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <KpiTile label="Total IOCs" value={summary.kpis.total_iocs} />
            {SEVERITIES.map((s) => (
              <KpiTile key={s} label={s} value={summary.kpis.by_severity[s]} href={`/iocs?severity=${s}`} />
            ))}
          </section>

          {empty ? (
            <Card className="mt-6">
              <CardContent className="flex flex-col items-center gap-2 p-12 text-center">
                <p className="text-lg font-medium">No IOCs yet — waiting for feed ingestion</p>
                <p className="text-sm text-muted-foreground">
                  Once your feeds start producing indicators, KPIs, the trend chart and the world map will fill in here.
                </p>
                <Button asChild variant="outline" className="mt-2">
                  <Link href="/settings">Configure feeds</Link>
                </Button>
              </CardContent>
            </Card>
          ) : (
            <>
              <Card className="mt-6">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">IOC trend · last 14 days</CardTitle>
                </CardHeader>
                <CardContent>
                  <AreaChart
                    data={summary.trend}
                    index="date"
                    categories={["count"]}
                    colors={["cyan"]}
                    showGridLines={false}
                    className="h-72"
                  />
                </CardContent>
              </Card>

              <Card className="mt-6">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Geographic distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  {summary.map.length === 0 ? (
                    <p className="py-8 text-center text-sm text-muted-foreground">
                      No geo data yet.
                    </p>
                  ) : (
                    <DashboardMap data={summary.map} />
                  )}
                </CardContent>
              </Card>

              <section className="mt-6 flex flex-wrap items-center gap-3">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">By severity:</span>
                {SEVERITIES.map((s) => (
                  <SeverityPill key={s} severity={s} />
                ))}
              </section>
            </>
          )}
        </>
      ) : null}
    </main>
  );
}
