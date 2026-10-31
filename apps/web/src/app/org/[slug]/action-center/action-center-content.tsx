"use client";

import AttackMap from "@/components/AttackMap";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { authHeaders } from "@/lib/auth-client";
import { listServers, type Server } from "@/lib/organizations";
import { serverConnectionState } from "@/lib/server-status";
import { useVisiblePolling } from "@/lib/use-visible-polling";
import { actionCenterNextStep, filterActionCenterDetections } from "@/lib/action-center";
import { Centered, Shell, SeverityBadge, useOrg, when } from "../incidents/shared";

interface Detection {
  id: string;
  server_id: string;
  severity: string;
  title: string;
  description: string | null;
  source_ip: string | null;
  username: string | null;
  detected_at: string;
  status: string;
}

interface ActionServer extends Server {
  fleet_id?: string | null;
}

interface Remediation {
  id: string;
  server_id: string;
  action_type: string;
  target_value: string;
  status: string;
  created_at: string;
}

interface Fleet { id: string; name: string; }
interface BoardData {
  servers: ActionServer[];
  detections: Detection[];
  actions: Remediation[];
  fleets: Fleet[];
}

const EMPTY: BoardData = { servers: [], detections: [], actions: [], fleets: [] };
const severities = ["critical", "high", "medium", "low", "info"];

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: authHeaders(), cache: "no-store" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof body.error === "string" ? body.error : `Request failed (${response.status})`);
  return body as T;
}

export default function ActionCenterContent({ slug }: { slug: string }) {
  const { org, ready } = useOrg(slug);
  const [data, setData] = useState<BoardData>(EMPTY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("all");
  const [fleetId, setFleetId] = useState("all");
  const [serverId, setServerId] = useState("all");
  const [ipQuery, setIpQuery] = useState("");

  const load = useCallback(async () => {
    if (!org) return;
    const [serverResult, detectionResult, actionResult, fleetResult] = await Promise.allSettled([
      listServers(org.id),
      getJson<{ detections?: Detection[] }>(`/api/orgs/${org.id}/detections?limit=200`),
      getJson<{ remediations?: Remediation[] }>(`/api/orgs/${org.id}/remediations?limit=200`),
      getJson<{ fleets?: Fleet[] }>(`/api/orgs/${org.id}/fleets`),
    ]);
    const failures = [serverResult, detectionResult, actionResult, fleetResult].filter((r) => r.status === "rejected");
    setData({
      servers: serverResult.status === "fulfilled" ? serverResult.value.servers as unknown as ActionServer[] : [],
      detections: detectionResult.status === "fulfilled" ? detectionResult.value.detections ?? [] : [],
      actions: actionResult.status === "fulfilled" ? actionResult.value.remediations ?? [] : [],
      fleets: fleetResult.status === "fulfilled" ? fleetResult.value.fleets ?? [] : [],
    });
    setError(failures.length ? "Some Action Center data could not be loaded. Try refreshing." : "");
    setLoading(false);
  }, [org]);

  useEffect(() => { void load(); }, [load]);
  useVisiblePolling(load, 30_000, !!org);

  const serverById = useMemo(() => new Map(data.servers.map((server) => [server.id, server])), [data.servers]);
  const filtered = useMemo(() => filterActionCenterDetections(data.detections, data.servers, {
    severity, fleetId, serverId, ipQuery,
  }), [data.detections, data.servers, fleetId, ipQuery, serverId, severity]);

  if (!ready || loading) return <Centered text="Loading Action Center..." />;
  if (!org) return <Centered text="Organization not found" />;

  const online = data.servers.filter((server) => serverConnectionState(server.last_seen) === "online").length;
  const activeDetections = data.detections.filter((detection) => detection.status === "new").length;
  const queuedActions = data.actions.filter((action) => action.status === "pending" || action.status === "executing");
  const fleetNames = new Map(data.fleets.map((fleet) => [fleet.id, fleet.name]));

  return (
    <Shell>
      <header className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <Link href={`/org/${slug}`} className="mt-1 text-zinc-500 hover:text-zinc-300" aria-label="Back to organization">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
          </Link>
          <div>
            <p className="text-xs uppercase tracking-widest text-green-400">{org.name}</p>
            <h1 className="text-2xl font-bold text-white">Action Center</h1>
            <p className="mt-1 text-sm text-zinc-500">Live events, server health and queued response actions.</p>
          </div>
        </div>
        <nav className="flex flex-wrap gap-2 text-sm" aria-label="Organization security pages">
          <Link className="rounded border border-zinc-700 px-3 py-1.5 text-zinc-300 hover:bg-zinc-800" href={`/org/${slug}/detections`}>All detections</Link>
          <Link className="rounded border border-zinc-700 px-3 py-1.5 text-zinc-300 hover:bg-zinc-800" href={`/org/${slug}/findings`}>Findings</Link>
          <Link className="rounded border border-zinc-700 px-3 py-1.5 text-zinc-300 hover:bg-zinc-800" href={`/org/${slug}/incidents`}>Incidents</Link>
          <Link className="rounded border border-zinc-700 px-3 py-1.5 text-zinc-300 hover:bg-zinc-800" href={`/org/${slug}/remediations`}>Response queue</Link>
        </nav>
      </header>

      {error && <p role="status" className="mb-4 rounded border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300">{error}</p>}

      <section className="mb-6 grid gap-3 sm:grid-cols-3" aria-label="Fleet summary">
        <Summary label="Servers online" value={`${online} / ${data.servers.length}`} />
        <Summary label="New detections" value={String(activeDetections)} />
        <Summary label="Actions waiting" value={String(queuedActions.length)} />
      </section>

      <div className="mb-6">
        <AttackMap source="account" orgId={org.id} title={`Live attacks on ${org.name}`} refreshMs={10_000} compact />
      </div>

      <section className="mb-6 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Watchdog events</h2>
            <p className="text-sm text-zinc-500">Showing {filtered.length} of the latest {data.detections.length} detections.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <label className="sr-only" htmlFor="action-severity">Severity</label>
            <select id="action-severity" value={severity} onChange={(event) => setSeverity(event.target.value)} className="rounded border border-zinc-700 bg-black px-3 py-2 text-sm text-white">
              <option value="all">All severities</option>
              {severities.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <label className="sr-only" htmlFor="action-fleet">Fleet</label>
            <select id="action-fleet" value={fleetId} onChange={(event) => { setFleetId(event.target.value); setServerId("all"); }} className="max-w-48 rounded border border-zinc-700 bg-black px-3 py-2 text-sm text-white">
              <option value="all">All fleets</option>
              {data.fleets.map((fleet) => <option key={fleet.id} value={fleet.id}>{fleet.name}</option>)}
            </select>
            <label className="sr-only" htmlFor="action-server">Server</label>
            <select id="action-server" value={serverId} onChange={(event) => setServerId(event.target.value)} className="max-w-48 rounded border border-zinc-700 bg-black px-3 py-2 text-sm text-white">
              <option value="all">All servers</option>
              {data.servers.filter((server) => fleetId === "all" || server.fleet_id === fleetId).map((server) => <option key={server.id} value={server.id}>{server.name}</option>)}
            </select>
            <label className="sr-only" htmlFor="action-ip">Filter by source IP</label>
            <input id="action-ip" value={ipQuery} onChange={(event) => setIpQuery(event.target.value)} placeholder="Source IP" className="w-36 rounded border border-zinc-700 bg-black px-3 py-2 text-sm text-white placeholder:text-zinc-600" />
          </div>
        </div>

        {filtered.length === 0 ? (
          <p className="rounded-lg border border-zinc-800 p-6 text-center text-sm text-zinc-500">
            {data.detections.length === 0
              ? "No watchdog detections reported yet. Linked server daemons will add events here."
              : "No detections match these filters."}
          </p>
        ) : (
          <ul className="space-y-2">
            {filtered.map((detection) => (
              <li key={detection.id} className="rounded-lg border border-zinc-800 bg-black/40 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={detection.severity} />
                      <Link href={`/org/${slug}/detections?detection=${detection.id}`} className="font-medium text-white hover:text-green-300">{detection.title}</Link>
                      <span className="text-xs text-zinc-500">{detection.status}</span>
                    </div>
                    <p className="mt-1 text-xs text-zinc-500">
                      <Link href={`/org/${slug}/servers/${detection.server_id}`} className="text-zinc-300 hover:underline">{serverById.get(detection.server_id)?.name ?? "Unknown server"}</Link>
                      {serverById.get(detection.server_id)?.fleet_id && ` · ${fleetNames.get(serverById.get(detection.server_id)!.fleet_id!) ?? "Fleet"}`}
                      {detection.source_ip && <> · IP <code className="text-zinc-300">{detection.source_ip}</code></>}
                      {detection.username && <> · user <code className="text-zinc-300">{detection.username}</code></>}
                      {` · ${when(detection.detected_at)}`}
                    </p>
                    <p className="mt-2 text-sm text-zinc-400">Next step: {actionCenterNextStep(detection.severity)}</p>
                  </div>
                  <Link href={`/org/${slug}/detections?detection=${detection.id}`} className="shrink-0 rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">Review event</Link>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div><h2 className="text-lg font-semibold text-white">Servers</h2><p className="text-sm text-zinc-500">Current heartbeat status across this organization.</p></div>
            <Link href={`/org/${slug}/findings`} className="text-xs text-zinc-400 hover:text-white">Host findings →</Link>
          </div>
          {data.servers.length === 0 ? <p className="p-5 text-center text-sm text-zinc-500">No servers linked to this organization.</p> : (
            <ul className="divide-y divide-zinc-800">
              {data.servers.map((server) => {
                const state = serverConnectionState(server.last_seen);
                return <li key={server.id} className="flex items-center justify-between gap-3 py-3">
                  <div className="min-w-0"><Link href={`/org/${slug}/servers/${server.id}`} className="truncate font-medium text-white hover:underline">{server.name}</Link><p className="truncate text-xs text-zinc-500">{server.hostname || server.ip_address || "No host name"}{server.fleet_id ? ` · ${fleetNames.get(server.fleet_id) ?? "Fleet"}` : ""}</p></div>
                  <span className={`shrink-0 text-xs ${state === "online" ? "text-green-400" : "text-zinc-500"}`}><span aria-hidden="true">● </span>{state}</span>
                </li>;
              })}
            </ul>
          )}
        </section>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
          <div className="mb-3 flex items-center justify-between gap-3"><div><h2 className="text-lg font-semibold text-white">Queued actions</h2><p className="text-sm text-zinc-500">Actions waiting for a linked daemon to apply them.</p></div><Link href={`/org/${slug}/remediations`} className="text-xs text-zinc-400 hover:text-white">Response history →</Link></div>
          {queuedActions.length === 0 ? <p className="p-5 text-center text-sm text-zinc-500">No queued actions.</p> : (
            <ul className="divide-y divide-zinc-800">
              {queuedActions.slice(0, 10).map((action) => <li key={action.id} className="flex items-center justify-between gap-3 py-3 text-sm">
                <div className="min-w-0"><p className="truncate text-white">{action.action_type} <code className="text-zinc-300">{action.target_value}</code></p><p className="text-xs text-zinc-500">{serverById.get(action.server_id)?.name ?? "Unknown server"} · {when(action.created_at)}</p></div>
                <span className={action.status === "pending" ? "shrink-0 text-yellow-400" : "shrink-0 text-blue-300"}>{action.status}</span>
              </li>)}
            </ul>
          )}
        </section>
      </div>

      <p className="mt-6 text-xs text-zinc-600">Shell-history snapshots remain on each host; the dashboard only receives an alert if protection detects tampering.</p>
    </Shell>
  );
}

function Summary({ label, value }: { label: string; value: string }) {
  return <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4"><p className="text-sm text-zinc-500">{label}</p><p className="mt-1 text-2xl font-bold text-white">{value}</p></div>;
}
