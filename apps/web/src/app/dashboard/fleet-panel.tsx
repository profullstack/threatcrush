"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { authHeaders } from "@/lib/auth-client";
import type { FleetServer, FleetSummary } from "@/lib/fleet";

interface FleetResponse {
  servers: FleetServer[];
  summary: FleetSummary;
}

const REFRESH_MS = 30_000;

/**
 * Every ThreatCrush install across all of the user's organizations. Linked
 * daemons heartbeat every minute, so this refreshes on its own.
 */
export default function FleetPanel({ addServerHref }: { addServerHref: string }) {
  const [fleet, setFleet] = useState<FleetResponse | null>(null);
  const [error, setError] = useState("");
  const [orgFilter, setOrgFilter] = useState("all");

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch("/api/fleet", { headers: authHeaders(), cache: "no-store" });
        const data = (await res.json().catch(() => ({}))) as FleetResponse & { error?: string };
        if (!res.ok) throw new Error(data.error || "Failed to load fleet");
        if (!cancelled) { setFleet(data); setError(""); }
      } catch (err) {
        if (!cancelled) setError((err as Error).message);
      }
    };
    void load();
    const timer = setInterval(load, REFRESH_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  const orgs = useMemo(() => {
    const seen = new Map<string, string>();
    for (const s of fleet?.servers ?? []) seen.set(s.org_id, s.org_name);
    return [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [fleet]);

  const servers = (fleet?.servers ?? []).filter((s) => orgFilter === "all" || s.org_id === orgFilter);
  const summary = fleet?.summary;

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Fleet</h2>
          <p className="text-sm text-zinc-500">Every ThreatCrush install across your organizations.</p>
        </div>
        <div className="flex items-center gap-3">
          {orgs.length > 1 && (
            <select
              value={orgFilter}
              onChange={(e) => setOrgFilter(e.target.value)}
              aria-label="Filter by organization"
              className="rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-sm text-white focus:border-green-500 focus:outline-none"
            >
              <option value="all">All organizations</option>
              {orgs.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </select>
          )}
          <Link
            href={addServerHref}
            className="rounded-lg px-3 py-1.5 text-sm font-medium text-zinc-300 bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 transition-colors"
          >
            Add Server
          </Link>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 mb-4">
          <Tile label="Installs" value={summary.total} hint={`${summary.organizations} org${summary.organizations === 1 ? "" : "s"}`} />
          <Tile label="Online" value={summary.online} hint="seen in the last 3 min" tone={summary.online > 0 ? "good" : undefined} />
          <Tile label="Offline" value={summary.offline} hint="no recent heartbeat" tone={summary.offline > 0 ? "bad" : undefined} />
          <Tile
            label="Behind latest"
            value={summary.outdated}
            hint={summary.latest_version ? `latest in fleet: v${summary.latest_version}` : "no versions reported"}
            tone={summary.outdated > 0 ? "warn" : undefined}
          />
        </div>
      )}

      {!fleet && !error ? (
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-8 text-center text-sm text-zinc-400">Loading fleet…</div>
      ) : servers.length === 0 ? (
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-8 text-center">
          <h3 className="text-sm font-medium text-white">No installs yet</h3>
          <p className="mt-2 text-sm text-zinc-400">
            On each server: <code className="text-green-400">threatcrush login</code>, then{" "}
            <code className="text-green-400">threatcrush servers link</code>.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="min-w-full divide-y divide-zinc-800">
            <thead className="bg-zinc-900">
              <tr>
                {["Server", "Organization", "Status", "Version", "Bans", "Last seen"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="bg-zinc-950 divide-y divide-zinc-800">
              {servers.map((s) => (
                <tr key={s.id} className="hover:bg-zinc-900 transition-colors">
                  <td className="px-4 py-3 whitespace-nowrap">
                    <Link href={`/org/${s.org_slug}/servers/${s.id}`} className="text-sm font-medium text-white hover:text-green-400">
                      {s.name}
                    </Link>
                    <div className="text-xs text-zinc-500">{s.hostname || s.ip_address || "—"}</div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-zinc-300">
                    <Link href={`/org/${s.org_slug}`} className="hover:text-green-400">{s.org_name}</Link>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap"><ConnectionBadge state={s.connection} /></td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm">
                    <span className={s.outdated ? "text-yellow-400" : "text-zinc-300"}>
                      {s.threatcrushd_version ? `v${s.threatcrushd_version}` : "—"}
                    </span>
                    {s.outdated && <div className="text-xs text-yellow-500/80">behind</div>}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-zinc-400">
                    {s.remediation
                      ? <>max {String(s.remediation.max_ban ?? "default")} · memory {String(s.remediation.strike_memory ?? "default")}</>
                      : <span className="text-zinc-600">not saved</span>}
                    {s.config_saved_at && <div className="text-zinc-600">saved {timeAgo(s.config_saved_at)}</div>}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-zinc-400">
                    {s.last_seen ? timeAgo(s.last_seen) : "Never"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Tile({ label, value, hint, tone }: { label: string; value: number; hint: string; tone?: "good" | "bad" | "warn" }) {
  const color = tone === "good" ? "text-green-400" : tone === "bad" ? "text-red-400" : tone === "warn" ? "text-yellow-400" : "text-white";
  return (
    <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
      <div className="text-xs uppercase tracking-wider text-zinc-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
      <div className="mt-1 text-xs text-zinc-500">{hint}</div>
    </div>
  );
}

function ConnectionBadge({ state }: { state: "online" | "offline" }) {
  const online = state === "online";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${online ? "bg-green-500/10 text-green-400" : "bg-zinc-700 text-zinc-400"}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${online ? "bg-green-400" : "bg-zinc-500"}`} />
      {state}
    </span>
  );
}

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
