'use client';

import { useCallback, useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

type Sample = { id: string; sha256: string; filename: string | null; strings_extracted: number; uploaded_at: string };
type Rule = {
  id: string; sample_id: string; name: string; rule_text: string;
  compiled: boolean; corpus_fp_free: boolean; validation_report: string | null; created_at: string;
};

function download(url: string, filename: string) {
  fetch(url, { credentials: 'include' })
    .then((r) => r.blob())
    .then((blob) => {
      const u = URL.createObjectURL(blob);
      const el = document.createElement('a');
      el.href = u;
      el.download = filename;
      el.click();
      URL.revokeObjectURL(u);
    });
}

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export default function YaraPage() {
  const { loading: authLoading } = useAuth();
  const [samples, setSamples] = useState<Sample[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
  const [selectedSample, setSelectedSample] = useState<Sample | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, r] = await Promise.all([
        api<{ items: Sample[] }>('/api/yara/samples'),
        api<{ items: Rule[] }>('/api/yara/rules'),
      ]);
      setSamples(s.items);
      setRules(r.items);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => { if (!authLoading) load(); }, [authLoading, load]);

  async function upload() {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      await fetch(`${API}/api/yara/samples`, { method: 'POST', body: fd, credentials: 'include' });
      setFile(null);
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function generateRule(sample: Sample) {
    setBusy(true);
    setSelectedSample(sample);
    setError(null);
    try {
      const rule = await api<Rule>('/api/yara/rules/generate', {
        method: 'POST',
        body: JSON.stringify({ sample_id: sample.id }),
      });
      setSelectedRule(rule);
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
      <div className="mx-auto grid max-w-6xl gap-6 lg:grid-cols-2">
        {/* left: samples */}
        <section className="space-y-4">
          <h1 className="text-2xl font-semibold text-slate-100">YARA Studio</h1>
          <Card className="border-slate-800 bg-slate-900">
            <CardContent className="flex items-center gap-3 py-4">
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                className="text-sm text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-slate-800 file:px-3 file:py-1.5 file:text-slate-200"
              />
              <button
                onClick={upload}
                disabled={!file || busy}
                className="rounded-md bg-cyan-600 px-3 py-1.5 text-sm text-white hover:bg-cyan-500 disabled:opacity-50"
              >
                Upload sample
              </button>
            </CardContent>
          </Card>
          <div className="space-y-2">
            {samples.length === 0 && (
              <p className="py-4 text-sm text-slate-500">No samples uploaded yet.</p>
            )}
            {samples.map((s) => (
              <div key={s.id} className={`flex items-center justify-between rounded-lg border p-3 ${selectedSample?.id === s.id ? 'border-cyan-600 bg-cyan-950/30' : 'border-slate-800 bg-slate-900'}`}>
                <div className="min-w-0">
                  <p className="truncate font-mono text-sm text-slate-100">{s.filename ?? s.sha256.slice(0, 16)}</p>
                  <p className="text-xs text-slate-500">{s.strings_extracted} strings · {s.sha256.slice(0, 12)}…</p>
                </div>
                <button
                  onClick={() => generateRule(s)}
                  disabled={busy}
                  className="ml-3 shrink-0 rounded border border-cyan-700 px-3 py-1.5 text-xs font-medium text-cyan-300 hover:bg-cyan-950 disabled:opacity-50"
                >
                  Generate rule
                </button>
              </div>
            ))}
          </div>
        </section>

        {/* right: rules */}
        <section className="space-y-4">
          <h2 className="pt-10 text-lg font-semibold text-slate-200 lg:pt-[52px]">Generated rules</h2>
          {rules.length === 0 && (
            <p className="text-sm text-slate-500">No rules generated yet.</p>
          )}
          <div className="flex flex-wrap gap-2">
            {rules.map((r) => (
              <button
                key={r.id}
                onClick={() => setSelectedRule(r)}
                className={`rounded-lg border px-3 py-2 text-left ${selectedRule?.id === r.id ? 'border-cyan-600 bg-cyan-950/30' : 'border-slate-800 bg-slate-900 hover:border-slate-600'}`}
              >
                <span className="font-mono text-xs text-slate-100">{r.name}</span>
                <span className="ml-2 text-[10px]">
                  {r.compiled ? <Badge className="bg-green-500/20 text-green-400">compiled</Badge>
                               : <Badge className="bg-red-600/20 text-red-400">broken</Badge>}
                  {' '}
                  {r.corpus_fp_free ? <Badge className="bg-green-500/20 text-green-400">FP-free</Badge>
                                    : <Badge className="bg-amber-500/20 text-amber-400">has FP risk</Badge>}
                </span>
              </button>
            ))}
          </div>

          {selectedRule && (
            <Card className="border-slate-800 bg-slate-900">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="font-mono text-base text-slate-100">{selectedRule.name}</CardTitle>
                <button
                  onClick={() => download(`${API}/api/yara/rules/${selectedRule.id}/export`, `${selectedRule.name}.yar`)}
                  className="rounded border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                >
                  Export .yar
                </button>
              </CardHeader>
              <CardContent className="space-y-3 pt-0">
                {selectedRule.validation_report && (
                  <pre className="whitespace-pre-wrap rounded bg-slate-950 p-3 text-xs text-slate-300">
                    {selectedRule.validation_report}
                  </pre>
                )}
                <pre className="overflow-x-auto rounded bg-slate-950 p-3 font-mono text-xs leading-relaxed text-cyan-200">
                  {selectedRule.rule_text}
                </pre>
              </CardContent>
            </Card>
          )}
        </section>

        {error && <p className="lg:col-span-2 text-sm text-red-400">{error}</p>}
      </div>
    </main>
  );
}
