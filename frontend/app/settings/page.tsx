"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";

interface ProviderStatus {
  configured: boolean;
  hint?: string | null;
  validated_at?: string | null;
  updated_at?: string | null;
}

const PROVIDERS = ["otx", "virustotal", "abuseipdb", "shodan"] as const;

const DISPLAY_NAMES: Record<(typeof PROVIDERS)[number], string> = {
  otx: "OTX",
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  shodan: "Shodan",
};

type CardState = "idle" | "saving" | "saved" | "error";

function ProviderCard({
  provider,
  status,
  onSaved,
}: {
  provider: (typeof PROVIDERS)[number];
  status: ProviderStatus | null;
  onSaved: () => void;
}) {
  const [key, setKey] = useState("");
  const [state, setState] = useState<CardState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function save() {
    if (!key.trim()) return;
    setState("saving");
    setError(null);
    try {
      await api("/api/settings/api-keys", {
        method: "PUT",
        body: JSON.stringify({ provider, api_key: key.trim() }),
      });
      setKey("");
      setState("saved");
      onSaved();
      setTimeout(() => setState("idle"), 2000);
    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : "Failed to save key");
    }
  }

  async function remove() {
    setState("saving");
    setError(null);
    try {
      await api(`/api/settings/api-keys/${provider}`, { method: "DELETE" });
      setState("idle");
      onSaved();
    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : "Failed to remove key");
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
        <CardTitle className="text-base">{DISPLAY_NAMES[provider]}</CardTitle>
        <Badge variant={status?.configured ? "default" : "secondary"}>
          {status?.configured ? "Configured" : "Not configured"}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-3">
        {status?.configured && status.hint && (
          <p className="font-mono text-xs text-muted-foreground">
            Key: <span>{status.hint}</span>
            {status.updated_at && (
              <span className="ml-2">updated {new Date(status.updated_at).toLocaleDateString()}</span>
            )}
          </p>
        )}
        <div className="flex gap-2">
          <Input
            type="password"
            placeholder="Enter API key…"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && save()}
          />
          <Button onClick={save} disabled={state === "saving" || !key.trim()}>
            Save
          </Button>
          {status?.configured && (
            <Button variant="destructive" onClick={remove} disabled={state === "saving"}>
              Remove
            </Button>
          )}
        </div>
        {state === "saved" && <p className="text-xs text-emerald-500">Saved.</p>}
        {error && <p className="text-xs text-red-500">{error}</p>}
      </CardContent>
    </Card>
  );
}

export default function SettingsPage() {
  const { loading } = useAuth();
  const [statuses, setStatuses] = useState<Record<string, ProviderStatus> | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const data = await api<Record<string, ProviderStatus>>("/api/settings/api-keys");
      setStatuses(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings");
    }
  }

  useEffect(() => {
    if (!loading) load();
  }, [loading]);

  return (
    <main className="mx-auto max-w-6xl p-8">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <Button asChild variant="ghost">
          <Link href="/">← Back to dashboard</Link>
        </Button>
      </header>

      <section className="mt-6">
        <h2 className="text-sm font-medium uppercase tracking-wide text-muted-foreground">Feed Sources</h2>
        {error && <p className="mt-3 text-sm text-red-500">{error}</p>}
        {!statuses && !error ? (
          <p className="mt-3 text-sm text-muted-foreground">Loading…</p>
        ) : statuses ? (
          <div className="mt-3 grid grid-cols-1 gap-4 xl:grid-cols-2">
            {PROVIDERS.map((p) => (
              <ProviderCard
                key={p}
                provider={p}
                status={statuses[p] ?? null}
                onSaved={load}
              />
            ))}
          </div>
        ) : null}
      </section>
    </main>
  );
}
