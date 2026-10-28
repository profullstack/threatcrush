"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";
import { useVisiblePolling } from "@/lib/use-visible-polling";
import { Centered, SeverityBadge, Shell, STATUS_CLS, useOrg, when } from "./shared";

// Incidents raised to humans: `threatcrush investigate --raise`, the daemon's
// critical detections, and the MCP incidents_raise tool. Same data as
// `threatcrush incidents` and the MCP incidents_* tools.

interface IncidentSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  source: string;
  host: string | null;
  team_name: string | null;
  findings_count: number;
  raise_count: number;
  last_seen_at: string;
  first_seen_at: string;
}

const TABS = [
  { key: "open,acknowledged", label: "Active" },
  { key: "open", label: "Open" },
  { key: "acknowledged", label: "Acknowledged" },
  { key: "resolved", label: "Resolved" },
  { key: "all", label: "All" },
];
const SOURCE_LABEL: Record<string, string> = { investigate: "investigate", watchdog: "watchdog", daemon: "daemon", manual: "manual" };

export default function IncidentsContent({ slug }: { slug: string }) {
  const { org, ready } = useOrg(slug);
  const [tab, setTab] = useState("open,acknowledged");
  const [rows, setRows] = useState<IncidentSummary[]>([]);
  const [counts, setCounts] = useState({ open: 0, acknowledged: 0, resolved: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!org) return;
    try {
      const res = await fetch(`/api/orgs/${org.id}/incidents?status=${encodeURIComponent(tab)}&limit=200`, { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setRows(data.incidents ?? []);
      setCounts(data.counts ?? { open: 0, acknowledged: 0, resolved: 0 });
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [org, tab]);

  useEffect(() => { void load(); }, [load]);
  useVisiblePolling(load, 30_000);

  if (!ready) return <Centered text="Loading..." />;
  if (!org) return <Centered text="Organization not found" />;

  const countFor = (key: string) =>
    key === "all" ? counts.open + counts.acknowledged + counts.resolved
      : key.split(",").reduce((n, k) => n + (counts[k as keyof typeof counts] ?? 0), 0);

  return (
    <Shell>
      <div className="flex items-center gap-3 mb-6">
        <Link href={`/org/${slug}`} className="text-zinc-500 hover:text-zinc-300" aria-label="Back">
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-white">Incidents</h1>
          <p className="text-sm text-zinc-500">{org.name}: raised by <code className="text-zinc-400">threatcrush investigate --raise</code> and critical daemon detections. Each new one pages its team by SMS and email.</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-4" role="tablist">
        {TABS.map((t) => (
          <button key={t.key} role="tab" aria-selected={tab === t.key} onClick={() => { setTab(t.key); setLoading(true); }}
            className={`rounded-full px-3 py-1 text-sm border ${tab === t.key ? "border-purple-500 text-white bg-purple-500/10" : "border-zinc-800 text-zinc-400 hover:text-zinc-200"}`}>
            {t.label} <span className="text-zinc-500">{countFor(t.key)}</span>
          </button>
        ))}
      </div>

      {error && <p className="mb-4 text-sm text-red-400">{error}</p>}
      {loading ? (
        <p className="text-zinc-500">Loading...</p>
      ) : rows.length === 0 ? (
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-10 text-center">
          <p className="text-zinc-300 mb-2">No incidents here.</p>
          <p className="text-sm text-zinc-500">Investigate a box with <code className="text-zinc-300">threatcrush investigate --since 6h --raise</code>.</p>
        </div>
      ) : (
        <ul className="divide-y divide-zinc-800 rounded-lg border border-zinc-800 bg-zinc-900">
          {rows.map((r) => (
            <li key={r.id}>
              <Link href={`/org/${slug}/incidents/${r.id}`} className="flex flex-col gap-1 p-4 hover:bg-zinc-800/50 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={r.severity} />
                    <span className="truncate font-medium text-white">{r.title}</span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">
                    {r.host ? `${r.host} · ` : ""}{r.team_name ?? "no team"} · {SOURCE_LABEL[r.source] ?? r.source} · {r.findings_count} finding{r.findings_count === 1 ? "" : "s"}
                    {r.raise_count > 1 ? ` · raised ${r.raise_count}×` : ""}
                  </p>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <span className={`capitalize ${STATUS_CLS[r.status] ?? "text-zinc-400"}`}>{r.status}</span>
                  <span className="text-zinc-500 whitespace-nowrap">{when(r.last_seen_at)}</span>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Shell>
  );
}
