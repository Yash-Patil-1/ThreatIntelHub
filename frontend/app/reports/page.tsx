'use client';

import { useCallback, useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

type Artifact = { id: number; format: string; size_bytes: number | null };
type ReportRow = {
  id: string; kind: string; status: string;
  created_at: string; completed_at: string | null; artifacts: Artifact[];
};

const STATUS_STYLES: Record<string, string> = {
  pending: 'bg-amber-500/20 text-amber-400',
  generating: 'bg-cyan-500/20 text-cyan-400',
  ready: 'bg-green-500/20 text-green-400',
  failed: 'bg-red-600/20 text-red-400',
};
const FORMATS = ['pdf', 'csv', 'json', 'stix'];

export default function ReportsPage() {
  const { loading: authLoading } = useAuth();
  const [items, setItems] = useState<ReportRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setItems((await api<{ items: ReportRow[] }>('/api/reports')).items);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => { if (!authLoading) load(); }, [authLoading, load]);

  async function generate() {
    setBusy(true);
    setError(null);
    try {
      const { id } = await api<{ id: string }>('/api/reports', {
        method: 'POST',
        body: JSON.stringify({ kind: 'ondemand' }),
      });
      for (let i = 0; i < 30; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const r = await api<ReportRow>(`/api/reports/${id}`);
        if (r.status === 'ready' || r.status === 'failed') break;
      }
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (authLoading) return <div className="p-8 text-slate-400">Checking session…</div>;

  return (
    <main className="min-h-screen bg-slate-950 p-8">
      <div className="mx-auto max-w-4xl space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold text-slate-100">Reports</h1>
          <button
            onClick={generate}
            disabled={busy}
            className="rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            {busy ? 'Generating…' : 'Generate report'}
          </button>
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
        {items.length === 0 && (
          <Card className="border-slate-800 bg-slate-900">
            <CardContent className="py-10 text-center text-slate-400">
              No reports yet. Click “Generate report” to create one.
            </CardContent>
          </Card>
        )}
        {items.map((r) => (
          <Card key={r.id} className="border-slate-800 bg-slate-900">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="flex items-center gap-3 text-base text-slate-100">
                <Badge variant="outline" className="capitalize border-slate-700 text-slate-300">{r.kind}</Badge>
                <span className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[r.status] ?? ''}`}>{r.status}</span>
              </CardTitle>
              <span className="text-xs text-slate-500">{new Date(r.created_at).toLocaleString()}</span>
            </CardHeader>
            {r.status === 'ready' && (
              <CardContent className="flex flex-wrap gap-2 pt-0">
                {FORMATS.filter((f) => r.artifacts.some((a) => a.format === f)).map((f) => {
                  const a = r.artifacts.find((x) => x.format === f)!;
                  return (
                    <button
                      key={f}
                      onClick={() =>
                        fetch(`${process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'}/api/reports/${r.id}/artifacts/${a.id}/download`, { credentials: 'include' })
                          .then((res) => res.blob())
                          .then((blob) => {
                            const u = URL.createObjectURL(blob);
                            const el = document.createElement('a');
                            el.href = u;
                            el.download = `threatintelhub-report.${f}`;
                            el.click();
                            URL.revokeObjectURL(u);
                          })
                      }
                      className="rounded border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                    >
                      Download {f.toUpperCase()} ({Math.round((a.size_bytes ?? 0) / 1024)} KB)
                    </button>
                  );
                })}
              </CardContent>
            )}
          </Card>
        ))}
      </div>
    </main>
  );
}
