"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

interface Endpoint {
  id: string;
  url: string;
  events: string[];
  description: string;
  enabled: boolean;
  failures: number;
  disabled_reason: string | null;
}

interface Delivery {
  id: string;
  event_type: string;
  status: "pending" | "delivered" | "failed";
  attempts: number;
  last_status: number | null;
  last_error: string | null;
  created_at: string;
}

/**
 * The org's webhook endpoints, via /api/v1/webhooks (the same API the CLI and
 * MCP use). Endpoints behind a Webhook alert destination show up here too:
 * alert rules route to those; the others get every event they subscribe to.
 */
export default function WebhookEndpoints({ orgId }: { orgId: string }) {
  const base = `/api/v1/webhooks`;
  const q = `?org_id=${encodeURIComponent(orgId)}`;
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<string[]>([]);
  const [secret, setSecret] = useState<{ id: string; value: string } | null>(null);
  const [log, setLog] = useState<{ id: string; rows: Delivery[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const call = useCallback(
    async (path: string, init: RequestInit = {}) => {
      const res = await fetch(`${base}${path}${q}`, {
        ...init,
        headers: { ...authHeaders(), ...(init.body ? { "Content-Type": "application/json" } : {}) },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    },
    [base, q],
  );

  const load = useCallback(async () => {
    try {
      const data = await call("");
      setEndpoints(data.endpoints ?? []);
      setEventTypes(data.event_types ?? []);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [call]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (fn: () => Promise<void>) => {
    try {
      await fn();
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const add = () =>
    act(async () => {
      const data = await call("", { method: "POST", body: JSON.stringify({ url, events: events.length ? events : ["*"] }) });
      setSecret({ id: data.endpoint.id, value: data.secret });
      setUrl("");
      setEvents([]);
      await load();
    });

  return (
    <div className="mt-10">
      <h2 className="text-lg font-semibold text-white mb-1">Webhook endpoints</h2>
      <p className="text-sm text-zinc-500 mb-4">
        Signed (Standard Webhooks), retried for about three days, logged. Endpoints added here get every event they subscribe
        to (at most 60 an hour); Webhook destinations above follow your alert rules. Also at <code>/api/v1/webhooks</code>,{" "}
        <code>threatcrush webhooks</code> and MCP.
      </p>

      {error && <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 mb-4 text-sm text-red-400">{error}</div>}

      {secret && (
        <div className="rounded-lg bg-green-500/10 border border-green-500/20 p-4 mb-4 text-sm">
          <p className="text-green-400 mb-2">Signing secret for {secret.id}. Copy it now: it is shown once.</p>
          <code className="block break-all text-white bg-zinc-900 rounded px-2 py-1">{secret.value}</code>
          <button onClick={() => setSecret(null)} className="mt-2 text-xs text-zinc-400 hover:text-zinc-300">Done</button>
        </div>
      )}

      <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 mb-4 space-y-3">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/threatcrush" type="url"
          className="w-full rounded-lg bg-zinc-800 border border-zinc-700 text-white px-3 py-2 text-sm" />
        <div className="flex flex-wrap gap-3 text-sm text-zinc-300">
          {eventTypes.map((t) => (
            <label key={t} className="flex items-center gap-1">
              <input type="checkbox" checked={events.includes(t)}
                onChange={(e) => setEvents(e.target.checked ? [...events, t] : events.filter((x) => x !== t))} />
              {t}
            </label>
          ))}
          <span className="text-zinc-600">(none ticked = all)</span>
        </div>
        <div className="flex justify-end">
          <button onClick={add} disabled={!url}
            className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-40">Add endpoint</button>
        </div>
      </div>

      <div className="space-y-3">
        {endpoints.length === 0 ? (
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-6 text-center text-zinc-500 text-sm">No webhook endpoints yet</div>
        ) : endpoints.map((e) => (
          <div key={e.id} className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-white font-medium break-all">{e.url}</div>
                <div className="text-xs text-zinc-500 mt-1">
                  {e.description && <span className="mr-2">{e.description}</span>}
                  {e.events.join(", ")}
                  <span className={`ml-2 ${e.enabled ? "text-green-400" : "text-zinc-600"}`}>{e.enabled ? "Active" : "Off"}</span>
                  {e.disabled_reason && <span className="ml-2 text-red-400">{e.disabled_reason}</span>}
                </div>
              </div>
              <div className="flex flex-wrap gap-2 shrink-0">
                <button onClick={() => act(async () => {
                  const r = await call(`/${e.id}/test`, { method: "POST" });
                  alert(r.ok ? `Test delivered (HTTP ${r.status})` : `Test failed: ${r.error ?? `HTTP ${r.status}`}`);
                })} className="rounded px-3 py-1 text-xs bg-zinc-800 text-blue-400 border border-zinc-700 hover:bg-zinc-700">Test</button>
                <button onClick={() => act(async () => {
                  const r = await call(`/${e.id}/deliveries`);
                  setLog(log?.id === e.id ? null : { id: e.id, rows: r.deliveries ?? [] });
                })} className="rounded px-3 py-1 text-xs bg-zinc-800 text-zinc-300 border border-zinc-700 hover:bg-zinc-700">Log</button>
                <button onClick={() => act(async () => {
                  await call(`/${e.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !e.enabled }) });
                  await load();
                })} className="rounded px-3 py-1 text-xs bg-zinc-800 text-zinc-300 border border-zinc-700 hover:bg-zinc-700">{e.enabled ? "Turn off" : "Turn on"}</button>
                <button onClick={() => act(async () => {
                  if (!confirm("Rotate the signing secret? The old one stops working at once.")) return;
                  const r = await call(`/${e.id}/rotate`, { method: "POST" });
                  setSecret({ id: e.id, value: r.secret });
                })} className="rounded px-3 py-1 text-xs bg-zinc-800 text-yellow-400 border border-zinc-700 hover:bg-zinc-700">Rotate</button>
                <button onClick={() => act(async () => {
                  if (!confirm("Remove this webhook endpoint?")) return;
                  await call(`/${e.id}`, { method: "DELETE" });
                  await load();
                })} className="rounded px-3 py-1 text-xs bg-zinc-800 text-red-400 border border-zinc-700 hover:bg-zinc-700">Remove</button>
              </div>
            </div>
            {log?.id === e.id && (
              <div className="mt-3 border-t border-zinc-800 pt-3 text-xs text-zinc-400 space-y-1">
                {log.rows.length === 0 ? <div>No deliveries yet</div> : log.rows.map((d) => (
                  <div key={d.id} className="flex gap-2">
                    <span className="text-zinc-600">{d.created_at.slice(0, 19).replace("T", " ")}</span>
                    <span>{d.event_type}</span>
                    <span className={d.status === "delivered" ? "text-green-400" : d.status === "failed" ? "text-red-400" : "text-yellow-400"}>{d.status}</span>
                    <span>{d.attempts} tries{d.last_status ? `, HTTP ${d.last_status}` : ""}</span>
                    {d.last_error && <span className="text-red-400 truncate">{d.last_error}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
