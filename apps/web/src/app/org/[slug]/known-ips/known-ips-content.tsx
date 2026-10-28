"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";

// Known IPs: the addresses that are ours (servers automatically, plus whatever
// an admin adds). Daemons never ban them, and this page shows what each one
// did: attack traffic from a known IP is the choke point for a compromised box.

interface Activity { detections: number; last_24h: number; high_critical: number; last_seen: string | null; rules: string[]; servers: string[] }
interface Entry {
  id: string; type: "ip" | "cidr"; value: string; label: string | null; note: string | null;
  source: "manual" | "server"; server_id: string | null; created_at: string;
  server: { id: string; name: string; last_seen: string | null } | null;
  activity: Activity | null;
}
interface Organization { id: string; name: string; slug: string }

const ago = (iso: string | null) => {
  if (!iso) return "never";
  const m = Math.round((Date.now() - Date.parse(iso)) / 60000);
  return m < 60 ? `${m}m ago` : m < 1440 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago`;
};

export default function KnownIpsContent({ slug }: { slug: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [canEdit, setCanEdit] = useState(false);
  const [days, setDays] = useState(7);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ value: "", label: "", note: "" });
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState({ label: "", note: "" });

  const load = useCallback(async (orgId: string) => {
    const res = await fetch(`/api/orgs/${orgId}/known-ips?days=${days}`, { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data.error || `HTTP ${res.status}`); return; }
    setEntries(data.entries);
    setCanEdit(Boolean(data.can_edit));
    setError("");
  }, [days]);

  useEffect(() => {
    if (!signedIn || authLoading) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find((o) => o.slug === slug);
        if (!found) return;
        setOrg(found);
        await load(found.id);
      } finally {
        setLoading(false);
      }
    })();
  }, [signedIn, authLoading, slug, load]);

  const send = async (method: "POST" | "PATCH" | "DELETE", body?: unknown, entryId?: string) => {
    if (!org) return;
    const res = await fetch(`/api/orgs/${org.id}/allowlists${entryId ? `?entry_id=${entryId}` : ""}`, {
      method,
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data.error || `HTTP ${res.status}`); return false; }
    await load(org.id);
    return true;
  };

  const add = async () => {
    const value = form.value.trim();
    if (!value) return;
    const ok = await send("POST", { type: value.includes("/") ? "cidr" : "ip", value, label: form.label, note: form.note });
    if (ok) setForm({ value: "", label: "", note: "" });
  };

  if (authLoading || loading) return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  if (!org) return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Organization not found</div></div>;

  const flagged = entries.filter((e) => (e.activity?.high_critical ?? 0) > 0);

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
          <div className="flex items-center gap-3">
            <Link href={`/org/${slug}`} className="text-zinc-500 hover:text-zinc-300" aria-label="Back">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">Known IPs</h1>
              <p className="text-sm text-zinc-500">{org.name} · never banned by your daemons; attack traffic from one is flagged as a possible compromise</p>
            </div>
          </div>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Window"
            className="rounded bg-zinc-900 border border-zinc-700 px-2 py-1 text-sm text-zinc-200">
            {[1, 7, 30].map((d) => <option key={d} value={d}>Last {d === 1 ? "24 hours" : `${d} days`}</option>)}
          </select>
        </div>

        {flagged.length > 0 && (
          <div className="mb-6 rounded-lg border border-red-500/40 bg-red-500/10 p-4">
            <p className="text-red-300 font-medium">{flagged.length} known IP{flagged.length === 1 ? "" : "s"} triggered high or critical attack rules</p>
            <p className="text-sm text-red-200/80 mt-1">Your own address running exploits or scans means a compromised or misbehaving service there, or tooling you should label. Check: {flagged.map((e) => e.label || e.value).join(", ")}.</p>
          </div>
        )}
        {error && <p className="mb-4 text-sm text-red-400">{error}</p>}

        {canEdit && (
          <div className="mb-6 rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <p className="text-sm text-zinc-300 mb-3">Add an address or range that is yours (office, home, VPN, CI egress). Servers are added automatically.</p>
            <div className="flex flex-wrap gap-2">
              <input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder="203.0.113.7 or 203.0.113.0/24"
                className="flex-1 min-w-48 rounded bg-black border border-zinc-700 px-3 py-1.5 text-sm text-white" />
              <input value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="Label (e.g. office)"
                className="w-48 rounded bg-black border border-zinc-700 px-3 py-1.5 text-sm text-white" />
              <input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} placeholder="Note"
                className="flex-1 min-w-40 rounded bg-black border border-zinc-700 px-3 py-1.5 text-sm text-white" />
              <button onClick={add} className="rounded px-3 py-1.5 text-sm font-medium bg-green-500 text-black hover:bg-green-400">Add</button>
            </div>
          </div>
        )}

        <div className="rounded-lg bg-zinc-900 border border-zinc-800 divide-y divide-zinc-800">
          {entries.length === 0 && <p className="p-4 text-sm text-zinc-500">No known IPs yet. They appear as soon as a linked server reports in.</p>}
          {entries.map((e) => {
            const a = e.activity;
            const hot = (a?.high_critical ?? 0) > 0;
            return (
              <div key={e.id} className={`p-4 ${hot ? "bg-red-500/5" : ""}`}>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <code className="text-white">{e.value}</code>
                      <span className={`rounded px-1.5 py-0.5 text-[10px] uppercase ${e.source === "server" ? "bg-blue-500/20 text-blue-300" : "bg-zinc-700 text-zinc-300"}`}>
                        {e.source === "server" ? "server" : "added"}
                      </span>
                      {editing === e.id ? (
                        <input value={draft.label} onChange={(ev) => setDraft({ ...draft, label: ev.target.value })} placeholder="Label"
                          className="rounded bg-black border border-zinc-700 px-2 py-0.5 text-sm text-white" />
                      ) : <span className="text-zinc-200">{e.label || e.server?.name || <span className="text-zinc-500">no label</span>}</span>}
                    </div>
                    {editing === e.id ? (
                      <input value={draft.note} onChange={(ev) => setDraft({ ...draft, note: ev.target.value })} placeholder="Note"
                        className="mt-2 w-full rounded bg-black border border-zinc-700 px-2 py-1 text-xs text-zinc-200" />
                    ) : e.note && <p className="text-xs text-zinc-500 mt-1">{e.note}</p>}
                  </div>
                  <div className="text-right text-xs">
                    <p className={hot ? "text-red-400 font-medium" : a?.detections ? "text-yellow-400" : "text-zinc-500"}>
                      {a?.detections ? `${a.detections} detections · ${a.high_critical} high/critical · ${a.last_24h} in 24h` : "no attack traffic"}
                    </p>
                    {a?.detections ? <p className="text-zinc-500 mt-1">last {ago(a.last_seen)} · on {a.servers.join(", ") || "?"}</p> : null}
                  </div>
                </div>
                {a?.rules?.length ? <p className="mt-2 text-xs text-zinc-500 break-words">Rules: {a.rules.join(", ")}</p> : null}
                {canEdit && (
                  <div className="mt-2 flex gap-2">
                    {editing === e.id ? (
                      <>
                        <button onClick={async () => { if (await send("PATCH", draft, e.id)) setEditing(null); }} className="rounded px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 text-green-400">Save</button>
                        <button onClick={() => setEditing(null)} className="rounded px-2 py-1 text-xs text-zinc-500">Cancel</button>
                      </>
                    ) : (
                      <button onClick={() => { setEditing(e.id); setDraft({ label: e.label ?? "", note: e.note ?? "" }); }} className="rounded px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 text-zinc-300">Edit</button>
                    )}
                    {e.source === "manual" && (
                      <button onClick={() => { if (window.confirm(`Remove ${e.value}? Daemons will be able to ban it again.`)) void send("DELETE", undefined, e.id); }}
                        className="rounded px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 text-red-400">Remove</button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
