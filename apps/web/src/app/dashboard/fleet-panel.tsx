"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { authHeaders } from "@/lib/auth-client";
import { jobStatus, TERMINAL, type JobAction, type JobItem, type JobPhase, type JobStatus } from "@/lib/daemon-job";
import type { FleetPatches, FleetServer, FleetSummary } from "@/lib/fleet";

interface FleetResponse {
  servers: FleetServer[];
  summary: FleetSummary;
}

const REFRESH_MS = 30_000;
/** While an update/restart is in flight. Kept modest: our own dashboard polling once got a box banned. */
const JOB_POLL_MS = 3_000;
const JOB_MAX_MS = 15 * 60_000;
/** Server machines themselves (reboots, deploys, OS) are managed there, not here. */
const W3BS_FLEET_URL = "https://w3bs.org/fleet";

interface Job {
  intent: "restart" | "update";
  started: number;
  items: JobItem[];
  actions: Record<string, JobAction>;
  done: boolean;
}

interface QueuedAction { id: string; server_id: string; action_type: "restart" | "update" }

/**
 * Every ThreatCrush install across all of the user's organizations. Linked
 * daemons heartbeat every minute, so this refreshes on its own.
 */
export default function FleetPanel({ addServerHref }: { addServerHref: string }) {
  const [fleet, setFleet] = useState<FleetResponse | null>(null);
  const [error, setError] = useState("");
  const [orgFilter, setOrgFilter] = useState("all");
  const [restarting, setRestarting] = useState(false);
  const [restartNote, setRestartNote] = useState("");
  const [updating, setUpdating] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [now, setNow] = useState(() => Date.now());

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
  const serverById = useMemo(() => new Map((fleet?.servers ?? []).map((s) => [s.id, s])), [fleet]);

  const jobStatuses: JobStatus[] = job
    ? job.items.map((i) => jobStatus(i, job.actions[i.action_id], serverById.get(i.server_id), now))
    : [];
  const jobRunning = !!job && !job.done;
  const jobFinished = !!job && jobStatuses.every((st) => TERMINAL.has(st.phase));

  useEffect(() => {
    if (job && !job.done && (jobFinished || now - job.started > JOB_MAX_MS)) setJob({ ...job, done: true });
  }, [job, jobFinished, now]);

  // Live progress: follow each queued action and each server's heartbeat until all settle.
  const jobKey = jobRunning ? job.started : null;
  useEffect(() => {
    if (jobKey === null || !job) return;
    let cancelled = false;
    const byOrg = new Map<string, string[]>();
    for (const i of job.items) byOrg.set(i.org_id, [...(byOrg.get(i.org_id) ?? []), i.action_id]);
    const tick = async () => {
      try {
        const [fleetRes, ...actionRes] = await Promise.all([
          fetch("/api/fleet", { headers: authHeaders(), cache: "no-store" }),
          ...[...byOrg].map(([orgId, ids]) =>
            fetch(`/api/orgs/${orgId}/remediations?ids=${ids.join(",")}&limit=200`, { headers: authHeaders(), cache: "no-store" })),
        ]);
        const latest = fleetRes.ok ? (await fleetRes.json()) as FleetResponse : null;
        const rows: JobAction[] = [];
        for (const r of actionRes) {
          if (r.ok) rows.push(...(((await r.json()) as { remediations?: JobAction[] }).remediations ?? []));
        }
        if (cancelled) return;
        if (latest) setFleet(latest);
        setJob((j) => j && j.started === jobKey
          ? { ...j, actions: { ...j.actions, ...Object.fromEntries(rows.map((a) => [a.id, a])) } }
          : j);
      } catch {
        // A dropped poll is fine: the next one catches up.
      }
    };
    void tick();
    const poll = setInterval(tick, JOB_POLL_MS);
    const clock = setInterval(() => setNow(Date.now()), 1_000);
    return () => { cancelled = true; clearInterval(poll); clearInterval(clock); };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one poller per job, keyed by its start time
  }, [jobKey]);

  const startJob = (intent: Job["intent"], queued: Array<QueuedAction & { org_id: string }>) => {
    const started = Date.now();
    setNow(started);
    setJob({
      intent,
      started,
      done: false,
      actions: {},
      items: queued.map((a) => {
        const s = serverById.get(a.server_id);
        return {
          action_id: a.id,
          org_id: a.org_id,
          server_id: a.server_id,
          server_name: s?.name ?? a.server_id.slice(0, 8),
          action_type: a.action_type,
          intent,
          from_version: s?.threatcrushd_version ?? null,
        };
      }),
    });
  };

  const restartAll = async () => {
    const scope = orgFilter === "all" ? "every organization" : "this organization";
    if (!window.confirm(`Restart the ThreatCrush daemon (threatcrushd) on every server you administer in ${scope}?\n\nOnly the ThreatCrush daemon restarts, for a few seconds each. The servers themselves are not rebooted: manage those at ${W3BS_FLEET_URL}.`)) return;
    setRestarting(true);
    setRestartNote("");
    setError("");
    try {
      const orgIds = [...new Set(servers.filter((s) => s.agent).map((s) => s.org_id))];
      const queued: Array<QueuedAction & { org_id: string }> = [];
      for (const orgId of orgIds) {
        const res = await fetch(`/api/orgs/${orgId}/restart-all`, { method: "POST", headers: authHeaders() });
        const data = (await res.json().catch(() => ({}))) as { actions?: QueuedAction[]; error?: string };
        if (res.ok) queued.push(...(data.actions ?? []).map((a) => ({ ...a, org_id: orgId })));
        // A 403 (no admin servers in that org) is not fatal across many orgs.
        else if (res.status !== 403) throw new Error(data.error || `Restart failed (${res.status})`);
      }
      if (queued.length > 0) startJob("restart", queued);
      else setRestartNote("No servers you administer to restart.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRestarting(false);
    }
  };

  const updateAll = async () => {
    const behind = servers.filter((s) => s.agent && s.outdated);
    if (!window.confirm(`Update the ThreatCrush daemon on ${behind.length} server${behind.length === 1 ? "" : "s"} behind v${summary?.latest_version}?\n\nEach ThreatCrush daemon installs the release and restarts (a few seconds without protection). The servers themselves are not updated or rebooted: manage those at ${W3BS_FLEET_URL}.`)) return;
    setUpdating(true);
    setRestartNote("");
    setError("");
    try {
      const orgIds = [...new Set(behind.map((s) => s.org_id))];
      const queued: Array<QueuedAction & { org_id: string }> = [];
      for (const orgId of orgIds) {
        const res = await fetch(`/api/orgs/${orgId}/update-all`, { method: "POST", headers: authHeaders() });
        const data = (await res.json().catch(() => ({}))) as { actions?: QueuedAction[]; error?: string };
        if (res.ok) queued.push(...(data.actions ?? []).map((a) => ({ ...a, org_id: orgId })));
        else if (res.status !== 403) throw new Error(data.error || `Update failed (${res.status})`);
      }
      if (queued.length > 0) startJob("update", queued);
      else setRestartNote("Every ThreatCrush daemon you administer is already on the latest release.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h2 className="text-lg font-semibold text-white">ThreatCrush command &amp; control</h2>
          <p className="text-sm text-zinc-500">
            Every ThreatCrush install across your organizations
            {summary && summary.inventories > 0 ? ", plus every machine in your OpenDevice inventory." : "."}
          </p>
          <p className="text-xs text-zinc-600">
            Update and restart act on the ThreatCrush daemon only, never the server. Manage the servers themselves at{" "}
            <a href={W3BS_FLEET_URL} target="_blank" rel="noopener noreferrer" className="text-zinc-400 underline hover:text-green-400">w3bs.org/fleet</a>.
          </p>
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
          {servers.some((s) => s.agent && s.outdated) && (
            <button
              type="button"
              onClick={updateAll}
              disabled={updating || jobRunning}
              title="Install the newest ThreatCrush daemon on every server behind it that you administer. The server itself is not updated."
              className="rounded-lg px-3 py-1.5 text-sm font-medium text-black bg-green-500 hover:bg-green-400 transition-colors disabled:opacity-50"
            >
              {updating ? "Queueing…" : `Update ThreatCrush (${servers.filter((s) => s.agent && s.outdated).length})`}
            </button>
          )}
          <button
            type="button"
            onClick={restartAll}
            disabled={restarting || jobRunning || !servers.some((s) => s.agent)}
            title="Restart the ThreatCrush daemon on every server you administer (in the current filter). The server itself is not rebooted."
            className="rounded-lg px-3 py-1.5 text-sm font-medium text-zinc-300 bg-zinc-800 border border-zinc-700 hover:border-yellow-500/50 hover:bg-zinc-700 transition-colors disabled:opacity-50"
          >
            {restarting ? "Queueing…" : "Restart ThreatCrush"}
          </button>
          <Link
            href={addServerHref}
            className="rounded-lg px-3 py-1.5 text-sm font-medium text-zinc-300 bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 transition-colors"
          >
            Add Server
          </Link>
        </div>
      </div>

      {job && <JobProgress job={job} statuses={jobStatuses} now={now} onDismiss={() => setJob(null)} />}

      {restartNote && (
        <div className="mb-4 rounded-lg bg-green-500/10 border border-green-500/20 px-4 py-3">
          <p className="text-sm text-green-400">{restartNote}</p>
        </div>
      )}

      {error && (
        <div className="mb-4 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6 mb-4">
          <Tile
            label="Installs"
            value={summary.installs}
            hint={summary.no_agent > 0
              ? `${summary.no_agent} more without a daemon`
              : `${summary.organizations} org${summary.organizations === 1 ? "" : "s"}`}
            tone={summary.no_agent > 0 ? "warn" : undefined}
          />
          <Tile label="Online" value={summary.online} hint="seen in the last 3 min" tone={summary.online > 0 ? "good" : undefined} />
          <Tile label="Offline" value={summary.offline} hint="no recent heartbeat" tone={summary.offline > 0 ? "bad" : undefined} />
          <Tile
            label="Behind latest"
            value={summary.outdated}
            hint={summary.latest_version ? `latest: v${summary.latest_version}` : "no versions reported"}
            tone={summary.outdated > 0 ? "warn" : undefined}
          />
          <Tile
            label="Pending security fixes"
            value={summary.patch_hosts_with_fixes}
            hint={summary.patch_reported === 0
              ? "no server has reported yet"
              : `${summary.patch_cves} CVE${summary.patch_cves === 1 ? "" : "s"} · ${summary.patch_critical_high} high/critical`}
            tone={summary.patch_critical_high > 0 ? "bad" : summary.patch_hosts_with_fixes > 0 ? "warn" : summary.patch_reported > 0 ? "good" : undefined}
          />
          <Tile
            label="Monthly cost"
            value={summary.inventories > 0 ? summary.monthly_total_label : "—"}
            hint={summary.inventories === 0
              ? "import an inventory: threatcrush fleet import"
              : `${summary.cost_counted} counted${summary.cost_unstated > 0 ? ` · ${summary.cost_unstated} unstated` : ""}`}
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
                {["Server", "Organization", "Status", "$/mo", "Version", "Patches", "Bans", "Last seen"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="bg-zinc-950 divide-y divide-zinc-800">
              {servers.map((s) => (
                <tr key={s.id} className="hover:bg-zinc-900 transition-colors">
                  <td className="px-4 py-3 whitespace-nowrap">
                    {s.agent ? (
                      <Link href={`/org/${s.org_slug}/servers/${s.id}`} className="text-sm font-medium text-white hover:text-green-400">
                        {s.name}
                      </Link>
                    ) : (
                      <span className="text-sm font-medium text-zinc-300">{s.name}</span>
                    )}
                    <div className="text-xs text-zinc-500">
                      {s.hostname || s.ip_address || (s.device ? s.device.profile : "—")}
                      {s.device?.provider && <span className="text-zinc-600"> · {s.device.provider}</span>}
                      {s.device && s.device.status !== "active" && <span className="text-yellow-500/80"> · {s.device.status}</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-zinc-300">
                    <Link href={`/org/${s.org_slug}`} className="hover:text-green-400">{s.org_name}</Link>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <ConnectionBadge state={s.connection} />
                    {!s.agent && (
                      <div className="mt-1 text-xs text-zinc-600" title="threatcrush login, then threatcrush servers link">
                        Install daemon: <code className="text-zinc-500">threatcrush servers link</code>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm">
                    {!s.device
                      ? <span className="text-xs text-zinc-600">—</span>
                      : s.device.monthly.amount == null
                        ? <span className="text-xs text-zinc-600" title="The inventory does not state what this costs">{s.device.monthly_label}</span>
                        : <span className="text-zinc-300">{s.device.monthly_label}</span>}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm">
                    <span className={s.outdated ? "text-yellow-400" : "text-zinc-300"}>
                      {s.threatcrushd_version ? `v${s.threatcrushd_version}` : "—"}
                    </span>
                    {s.outdated && <div className="text-xs text-yellow-500/80">behind</div>}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm">{s.agent ? <PatchCell patches={s.patches} /> : <span className="text-xs text-zinc-600">—</span>}</td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-zinc-400">
                    {!s.agent
                      ? <span className="text-zinc-600">—</span>
                      : s.remediation
                      ? <>max {String(s.remediation.max_ban ?? "default")} · memory {String(s.remediation.strike_memory ?? "default")}</>
                      : <span className="text-zinc-600">not saved</span>}
                    {s.config_saved_at && <div className="text-zinc-600">saved {timeAgo(s.config_saved_at)}</div>}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-zinc-400">
                    {s.last_seen ? timeAgo(s.last_seen) : s.agent ? "Never" : "—"}
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

const PHASE_STYLE: Record<JobPhase, { label: string; className: string }> = {
  queued: { label: "queued", className: "bg-zinc-700 text-zinc-300" },
  running: { label: "running", className: "bg-blue-500/15 text-blue-300" },
  restarting: { label: "restarting", className: "bg-yellow-500/15 text-yellow-300" },
  online: { label: "back online", className: "bg-green-500/15 text-green-400" },
  failed: { label: "failed", className: "bg-red-500/15 text-red-400" },
  expired: { label: "not reached", className: "bg-red-500/15 text-red-400" },
  stalled: { label: "no heartbeat", className: "bg-red-500/15 text-red-400" },
};

/** Live per-server progress of an "Update ThreatCrush" / "Restart ThreatCrush" run. */
function JobProgress({ job, statuses, now, onDismiss }: { job: Job; statuses: JobStatus[]; now: number; onDismiss: () => void }) {
  const total = statuses.length;
  const ok = statuses.filter((s) => s.phase === "online").length;
  const bad = statuses.filter((s) => TERMINAL.has(s.phase) && s.phase !== "online").length;
  const elapsed = Math.max(0, Math.floor((now - job.started) / 1000));
  const verb = job.intent === "update" ? "Updating" : "Restarting";
  const title = job.done
    ? `ThreatCrush daemon ${job.intent} finished: ${ok} of ${total} back online${bad ? `, ${bad} need attention` : ""}`
    : `${verb} the ThreatCrush daemon on ${total} server${total === 1 ? "" : "s"}: ${ok} of ${total} back`;
  const tone = !job.done ? "border-yellow-500/30" : bad ? "border-red-500/30" : "border-green-500/30";

  return (
    <div className={`mb-4 rounded-lg border bg-zinc-900 p-4 ${tone}`} aria-live="polite">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-medium text-white">
          {!job.done && <span className="h-3 w-3 animate-spin rounded-full border-2 border-yellow-400 border-t-transparent" aria-hidden />}
          {title}
        </div>
        <div className="flex items-center gap-3 text-xs text-zinc-500">
          <span>{Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, "0")}</span>
          {job.done && <button type="button" onClick={onDismiss} className="text-zinc-400 hover:text-white">Dismiss</button>}
        </div>
      </div>
      <div className="mt-3 flex h-1.5 overflow-hidden rounded-full bg-zinc-800">
        <div className="bg-green-500 transition-all" style={{ width: `${(ok / total) * 100}%` }} />
        <div className="bg-red-500 transition-all" style={{ width: `${(bad / total) * 100}%` }} />
      </div>
      <ul className="mt-3 divide-y divide-zinc-800/70">
        {job.items.map((item, i) => {
          const st = statuses[i];
          const style = PHASE_STYLE[st.phase];
          return (
            <li key={item.action_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5 text-sm">
              <span className="min-w-32 font-medium text-zinc-200">{item.server_name}</span>
              <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${style.className}`}>{style.label}</span>
              <span className="text-xs text-zinc-400">{st.detail}</span>
            </li>
          );
        })}
      </ul>
      <p className="mt-3 text-xs text-zinc-600">
        Only the ThreatCrush daemon is touched. Reboots, deploys and OS updates for these servers live at{" "}
        <a href={W3BS_FLEET_URL} target="_blank" rel="noopener noreferrer" className="text-zinc-400 underline hover:text-green-400">w3bs.org/fleet</a>.
      </p>
    </div>
  );
}

function Tile({ label, value, hint, tone }: { label: string; value: number | string; hint: string; tone?: "good" | "bad" | "warn" }) {
  const color = tone === "good" ? "text-green-400" : tone === "bad" ? "text-red-400" : tone === "warn" ? "text-yellow-400" : "text-white";
  return (
    <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
      <div className="text-xs uppercase tracking-wider text-zinc-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
      <div className="mt-1 text-xs text-zinc-500">{hint}</div>
    </div>
  );
}

/** `threatcrush patches` as the daemon last reported it (daily). */
function PatchCell({ patches }: { patches: FleetPatches | null }) {
  if (!patches) return <span className="text-xs text-zinc-600">not reported</span>;
  if (patches.unsupported) return <span className="text-xs text-zinc-600">unsupported OS</span>;
  const urgent = patches.critical + patches.high;
  return (
    <>
      {patches.packages === 0
        ? <span className="text-green-400">up to date</span>
        : (
          <span className={urgent > 0 ? "text-red-400" : "text-yellow-400"}>
            {patches.packages} pkg · {patches.cves} CVE{patches.cves === 1 ? "" : "s"}
          </span>
        )}
      <div className="text-xs text-zinc-600">
        {urgent > 0 && <span className="text-red-500/80">{urgent} high/critical · </span>}
        {patches.lists_stale ? <span className="text-yellow-500/80">apt lists stale · </span> : null}
        checked {timeAgo(patches.observed_at)}
      </div>
    </>
  );
}

function ConnectionBadge({ state }: { state: FleetServer["connection"] }) {
  if (state === "no-agent") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium border border-dashed border-zinc-700 text-zinc-500">
        no agent
      </span>
    );
  }
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
