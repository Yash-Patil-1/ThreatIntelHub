"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import { api } from "@/lib/api";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function CommandPalette() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const lookup = useCallback(
    async (value: string) => {
      if (!value.trim()) return;
      setBusy(true);
      try {
        const data = await api<Record<string, unknown>>("/api/iocs/lookup", {
          method: "POST",
          body: JSON.stringify({ value: value.trim() }),
        });
        setOpen(false);
        let targetId: unknown = data.id;
        if ("ioc_id" in data && data.status === "pending") {
          targetId = data.ioc_id;
          // ponytail: fixed ~15s poll budget (8 × 2s), then navigate anyway — detail page shows what it has
          for (let i = 0; i < 8; i++) {
            await sleep(2000);
            try {
              const st = await api<{ status: string }>(`/api/iocs/${targetId}/enrichment-status`);
              if (st.status !== "pending") break;
            } catch {
              // keep polling until budget is exhausted
            }
          }
        }
        router.push(`/iocs/${String(targetId)}`);
      } catch {
        // leave dialog open; cmdk empty state covers no-results
      } finally {
        setBusy(false);
      }
    },
    [router],
  );

  return (
    <Command.Dialog
      open={open}
      onOpenChange={(next) => !busy && setOpen(next)}
      label="Lookup IOC"
      overlayClassName="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
      contentClassName="fixed left-1/2 top-[20vh] z-50 w-full max-w-lg -translate-x-1/2 rounded-xl border border-border bg-card shadow-2xl outline-none"
    >
      <Command.Input
        autoFocus
        placeholder="Lookup an IP, domain, URL or hash… (⌘K)"
        className="w-full border-b border-border bg-transparent px-4 py-3 font-mono text-sm outline-none placeholder:text-muted-foreground"
        onKeyDown={(e) => {
          if (e.key === "Enter") lookup(e.currentTarget.value);
        }}
      />
      <Command.List className="max-h-72 overflow-y-auto p-2 text-sm">
        <Command.Empty className="px-2 py-6 text-center text-muted-foreground">
          {busy ? "Enriching…" : "Press Enter to look up this value"}
        </Command.Empty>
        {!busy && (
          <>
            <Command.Group heading="Navigation" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:text-muted-foreground">
              <Command.Item onSelect={() => { setOpen(false); router.push("/"); }} className="cursor-pointer rounded-md px-2 py-2 aria-selected:bg-secondary">Go to Dashboard</Command.Item>
              <Command.Item onSelect={() => { setOpen(false); router.push("/iocs"); }} className="cursor-pointer rounded-md px-2 py-2 aria-selected:bg-secondary">Browse IOCs</Command.Item>
              <Command.Item onSelect={() => { setOpen(false); router.push("/settings"); }} className="cursor-pointer rounded-md px-2 py-2 aria-selected:bg-secondary">Settings</Command.Item>
            </Command.Group>
          </>
        )}
      </Command.List>
    </Command.Dialog>
  );
}
