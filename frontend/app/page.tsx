"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";

export default function DashboardPage() {
  const { user, loading, logout } = useAuth();

  if (loading) {
    return <main className="flex min-h-screen items-center justify-center text-muted-foreground">Loading…</main>;
  }

  return (
    <main className="mx-auto max-w-6xl p-8">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="text-xl font-semibold tracking-tight">ThreatIntelHub</h1>
        <div className="flex items-center gap-3">
          <Button asChild variant="ghost">
            <Link href="/settings">Settings</Link>
          </Button>
          <Button variant="outline" onClick={logout}>
            Log out
          </Button>
        </div>
      </header>
      <p className="mt-8 font-mono text-sm text-muted-foreground">
        Signed in as {user?.email} — dashboard coming in a later phase.
      </p>
    </main>
  );
}
