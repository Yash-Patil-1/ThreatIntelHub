"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityPill } from "@/components/severity-pill";
import { useAuth } from "@/hooks/useAuth";
import { api, downloadFile } from "@/lib/api";
import type { IocSummary, IocType, Severity } from "@/lib/types";

const TYPES: IocType[] = ["ip", "domain", "url", "hash"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

interface ListResponse {
  items: IocSummary[];
  next_cursor?: string | null;
}

export default function IocsPage() {
  const { loading: authLoading } = useAuth();
  const [type, setType] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [data, setData] = useState<ListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  // ponytail: cursor history stack for Prev/Next — no page numbers exist server-side
  const [cursorStack, setCursorStack] = useState<string[]>([]);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q), 300);
    return () => clearTimeout(t);
  }, [q]);

  const params = useMemo(() => {
    const p = new URLSearchParams({ limit: "50" });
    if (type) p.set("type", type);
    if (severity) p.set("severity", severity);
    if (debouncedQ) p.set("q", debouncedQ);
    return p;
  }, [type, severity, debouncedQ]);

  const cursor = cursorStack.length > 0 ? cursorStack[cursorStack.length - 1] : "";
  if (cursor) params.set("cursor", cursor);

  const load = useCallback(async () => {
    setError(null);
    try {
      setData(await api<ListResponse>(`/api/iocs?${params.toString()}`));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load IOCs");
    }
  }, [params]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  function resetPaging() {
    setCursorStack([]);
  }

  function goNext() {
    if (data?.next_cursor) setCursorStack((s) => [...s, data.next_cursor!]);
  }

  function goPrev() {
    setCursorStack((s) => s.slice(0, -1));
  }

  function exportAs(format: "csv" | "json") {
    downloadFile(`/api/iocs/export?format=${format}`, `iocs.${format}`).catch((err) =>
      setError(err instanceof Error ? err.message : "Export failed"),
    );
  }

  if (authLoading) {
    return (
      <main className="flex min-h-screen items-center justify-center text-muted-foreground">Loading…</main>
    );
  }

  return (
    <main className="mx-auto max-w-6xl p-8">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="text-xl font-semibold tracking-tight">IOCs</h1>
        <Button asChild variant="ghost">
          <Link href="/">← Back to dashboard</Link>
        </Button>
      </header>

      <section className="mt-4 flex flex-wrap items-center gap-2">
        <select
          value={type}
          onChange={(e) => { setType(e.target.value); resetPaging(); }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-1 focus:ring-ring"
          aria-label="Filter by type"
        >
          <option value="">All types</option>
          {TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); resetPaging(); }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm capitalize outline-none focus:ring-1 focus:ring-ring"
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s} className="capitalize">{s}</option>
          ))}
        </select>
        <Input
          placeholder="Search value…"
          value={q}
          onChange={(e) => { setQ(e.target.value); resetPaging(); }}
          className="w-64 font-mono"
        />
        <div className="ml-auto flex gap-2">
          <Button variant="outline" size="sm" onClick={() => exportAs("csv")}>Export CSV</Button>
          <Button variant="outline" size="sm" onClick={() => exportAs("json")}>Export JSON</Button>
        </div>
      </section>

      {error && <p className="mt-3 text-sm text-red-500">{error}</p>}

      {!data && !error ? (
        <p className="mt-4 text-sm text-muted-foreground">Loading…</p>
      ) : data && data.items.length === 0 ? (
        <p className="mt-8 text-center text-muted-foreground">
          No IOCs match — waiting for feed ingestion or loosen the filters.
        </p>
      ) : data ? (
        <>
          <div className="mt-4 overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/40 text-xs uppercase tracking-wide text-muted-foreground">
                  <th className="px-4 py-2.5 font-medium">Value</th>
                  <th className="px-4 py-2.5 font-medium">Type</th>
                  <th className="px-4 py-2.5 font-medium">Severity</th>
                  <th className="px-4 py-2.5 font-medium">Score</th>
                  <th className="px-4 py-2.5 font-medium">Last seen</th>
                  <th className="px-4 py-2.5 font-medium">Sources</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((ioc) => (
                  <tr
                    key={ioc.id}
                    className="border-b border-border/60 transition-colors last:border-0 hover:bg-secondary/30"
                  >
                    <td className="max-w-[22rem] truncate px-4 py-2.5 font-mono">
                      <Link href={`/iocs/${ioc.id}`} className="hover:text-primary hover:underline">
                        {ioc.value_norm}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 uppercase">{ioc.type}</td>
                    <td className="px-4 py-2.5"><SeverityPill severity={ioc.severity} /></td>
                    <td className="px-4 py-2.5 tabular-nums">{ioc.threat_score}</td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-muted-foreground">
                      {ioc.last_seen ? new Date(ioc.last_seen).toLocaleString() : "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="flex flex-wrap gap-1">
                        {(ioc.sources ?? []).map((s) => (
                          <span key={s} className="rounded bg-secondary px-1.5 py-0.5 text-xs uppercase text-secondary-foreground">
                            {s}
                          </span>
                        ))}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">{data.items.length} shown</p>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={cursorStack.length === 0} onClick={goPrev}>
                ← Prev
              </Button>
              <Button variant="outline" size="sm" disabled={!data.next_cursor} onClick={goNext}>
                Next →
              </Button>
            </div>
          </div>
        </>
      ) : null}
    </main>
  );
}
