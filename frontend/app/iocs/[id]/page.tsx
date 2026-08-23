"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityPill } from "@/components/severity-pill";
import { useAuth } from "@/hooks/useAuth";
import { api, downloadFile } from "@/lib/api";
import type { IocDetail } from "@/lib/types";

const ENRICHMENT_SOURCES = ["otx", "virustotal", "abuseipdb", "shodan"] as const;

function fmt(n: number): string {
  return Number.isFinite(n) ? n.toFixed(2) : String(n);
}

export default function IocDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const { loading: authLoading } = useAuth();
  const [detail, setDetail] = useState<IocDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<string>("otx");

  useEffect(() => {
    if (authLoading || !id) return;
    api<IocDetail>(`/api/iocs/${id}`)
      .then(setDetail)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load IOC"));
  }, [authLoading, id]);

  function exportAs(format: "csv" | "json") {
    downloadFile(`/api/iocs/${id}/export?format=${format}`, `ioc-${id}.${format}`).catch((err) =>
      setError(err instanceof Error ? err.message : "Export failed"),
    );
  }

  if (authLoading) {
    return (
      <main className="flex min-h-screen items-center justify-center text-muted-foreground">Loading…</main>
    );
  }

  if (error) {
    return (
      <main className="mx-auto max-w-6xl p-8">
        <Button asChild variant="ghost">
          <Link href="/iocs">← Back to IOCs</Link>
        </Button>
        <p className="mt-6 text-sm text-red-500">{error}</p>
      </main>
    );
  }

  if (!detail) {
    return (
      <main className="flex min-h-screen items-center justify-center text-muted-foreground">Loading…</main>
    );
  }

  const bd = detail.score_breakdown;
  // ponytail: single max for bar widths — contributions are always >= 0 by construction of the formula
  const maxContribution = Math.max(1, ...(bd?.per_source ?? []).map((s) => s.contribution));
  const enrichmentSources = Array.from(
    new Set<string>([...ENRICHMENT_SOURCES, ...Object.keys(detail.enrichments ?? {})]),
  );
  const activeTab = tab in (detail.enrichments ?? {}) ? tab : null;
  const payload = activeTab ? detail.enrichments?.[activeTab] : undefined;

  return (
    <main className="mx-auto max-w-6xl p-8">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <Button asChild variant="ghost">
          <Link href="/iocs">← Back to IOCs</Link>
        </Button>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => exportAs("csv")}>Export CSV</Button>
          <Button variant="outline" size="sm" onClick={() => exportAs("json")}>Export JSON</Button>
        </div>
      </header>

      <section className="mt-6 flex flex-wrap items-center gap-4">
        <h1 className="min-w-0 break-all font-mono text-2xl font-semibold">{detail.value_norm}</h1>
        <SeverityPill severity={detail.severity} />
        <span className="rounded bg-secondary px-2 py-0.5 text-xs uppercase text-secondary-foreground">{detail.type}</span>
        <div className="ml-auto text-right">
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Threat score</p>
          <p className="text-4xl font-bold tabular-nums text-primary">{detail.threat_score}</p>
        </div>
      </section>

      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Score breakdown</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(bd?.per_source ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">No scored sources yet.</p>
            ) : (
              (bd?.per_source ?? []).map((s) => (
                <div key={s.source}>
                  <div className="mb-1 flex items-baseline justify-between text-sm">
                    <span className="uppercase">{s.source}</span>
                    <span className="font-mono tabular-nums text-muted-foreground">
                      +{fmt(s.contribution)}{" "}
                      <span className="text-xs">
                        (w {fmt(s.reliability_weight)}, {s.hours_age}h old, decay ×{fmt(s.decay)})
                      </span>
                    </span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-secondary">
                    <div
                      className="h-full rounded-full bg-cyan-400"
                      style={{ width: `${Math.min(100, (s.contribution / maxContribution) * 100)}%` }}
                    />
                  </div>
                </div>
              ))
            )}
            <div className="space-y-1 border-t border-border pt-3 font-mono text-sm text-muted-foreground">
              <p>cross_source_bonus: +{fmt(bd?.cross_source_bonus ?? 0)}</p>
              <p>sighting_bonus: +{fmt(bd?.sighting_bonus ?? 0)}</p>
              <p className="text-xs">formula_version: {bd?.formula_version ?? "unknown"}</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Sightings timeline</CardTitle>
          </CardHeader>
          <CardContent>
            {(detail.sightings ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">No sightings recorded.</p>
            ) : (
              <ol className="relative space-y-4 border-l border-border pl-4">
                {(detail.sightings ?? []).map((s, i) => (
                  <li key={i} className="relative">
                    <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-cyan-400" />
                    <p className="font-mono text-sm">{new Date(s.seen_at).toLocaleString()}</p>
                    {s.source && (
                      <p className="text-xs uppercase text-muted-foreground">{s.source}</p>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Enrichment</CardTitle>
          <div className="mt-2 flex flex-wrap gap-1">
            {enrichmentSources.map((src) => (
              <button
                key={src}
                onClick={() => setTab(src)}
                className={`rounded-md px-3 py-1.5 text-xs uppercase transition-colors ${
                  tab === src ? "bg-primary text-primary-foreground" : "bg-secondary text-secondary-foreground hover:bg-secondary/70"
                }`}
              >
                {src}
              </button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          {activeTab === null ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No data for this source.
            </p>
          ) : payload == null ? (
            <p className="py-6 text-center text-sm text-muted-foreground">No data.</p>
          ) : (
            <pre className="max-h-96 overflow-auto rounded-md bg-secondary/40 p-4 font-mono text-xs leading-relaxed">
              {JSON.stringify(payload, null, 2)}
            </pre>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
