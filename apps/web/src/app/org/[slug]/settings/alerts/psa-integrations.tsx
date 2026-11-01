"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

interface Integration {
  id: string;
  name: string;
  provider: "halopsa" | "connectwise" | "autotask";
  enabled: boolean;
  config: {
    api_url: string;
    auth_url: string;
    ticket_type_id: number;
    default_client_id: number | null;
    client_mappings: Record<string, number>;
    open_status_id: number | null;
    resolved_status_id: number | null;
    auto_close: boolean;
    board_id?: number;
    priority_id?: number | null;
    ticket_category_id?: number | null;
    queue_id?: number | null;
  };
  recent_links?: Array<{ incident_id: string | null; detection_id: string | null; external_ticket_id: string | null; sync_status: string; last_error: string | null; last_synced_at: string | null }>;
}

const EMPTY = {
  name: "", provider: "halopsa" as Integration["provider"], api_url: "", auth_url: "", client_id: "", client_secret: "",
  company_id: "", public_key: "", private_key: "", username: "", secret: "", integration_code: "",
  ticket_type_id: "", board_id: "", priority_id: "", ticket_category_id: "", queue_id: "",
  default_client_id: "", open_status_id: "", resolved_status_id: "", auto_close: false, client_mappings: "{}",
};
type Form = typeof EMPTY;

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { ...init, headers: authHeaders(init?.headers as Record<string, string> | undefined) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body as T;
}

export default function PsaIntegrations({ orgId }: { orgId: string }) {
  const [items, setItems] = useState<Integration[]>([]);
  const [canManage, setCanManage] = useState(false);
  const [form, setForm] = useState<Form>(EMPTY);
  const [editing, setEditing] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await request<{ integrations: Integration[]; can_manage: boolean }>(`/api/orgs/${orgId}/psa-integrations`);
      setItems(data.integrations ?? []);
      setCanManage(data.can_manage === true);
    } catch (cause) {
      setError((cause as Error).message || "Could not load PSA integrations");
    }
  }, [orgId]);

  useEffect(() => { void load(); }, [load]);

  const edit = (item: Integration) => {
    setEditing(item.id);
    setShowForm(true);
    setError(""); setMessage("");
    setForm({
      ...EMPTY,
      name: item.name,
      provider: item.provider,
      api_url: item.config.api_url,
      auth_url: item.config.auth_url,
      ticket_type_id: String(item.config.ticket_type_id),
      board_id: item.config.board_id == null ? "" : String(item.config.board_id),
      priority_id: item.config.priority_id == null ? "" : String(item.config.priority_id),
      ticket_category_id: item.config.ticket_category_id == null ? "" : String(item.config.ticket_category_id),
      queue_id: item.config.queue_id == null ? "" : String(item.config.queue_id),
      default_client_id: item.config.default_client_id == null ? "" : String(item.config.default_client_id),
      open_status_id: item.config.open_status_id == null ? "" : String(item.config.open_status_id),
      resolved_status_id: item.config.resolved_status_id == null ? "" : String(item.config.resolved_status_id),
      auto_close: item.config.auto_close,
      client_mappings: JSON.stringify(item.config.client_mappings, null, 2),
    });
  };

  const save = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      let clientMappings: unknown;
      try { clientMappings = JSON.parse(form.client_mappings); }
      catch { throw new Error("Team/fleet mappings must be valid JSON."); }
      const credentials = form.provider === "halopsa"
        ? (form.client_id || form.client_secret ? { client_id: form.client_id, client_secret: form.client_secret } : undefined)
        : form.provider === "connectwise"
          ? (form.company_id || form.public_key || form.private_key || form.client_id ? { company_id: form.company_id, public_key: form.public_key, private_key: form.private_key, client_id: form.client_id } : undefined)
          : (form.username || form.secret || form.integration_code ? { username: form.username, secret: form.secret, integration_code: form.integration_code } : undefined);
      const payload = {
        provider: form.provider,
        name: form.name,
        config: {
          api_url: form.api_url,
          ...(form.provider === "halopsa" ? { auth_url: form.auth_url, ticket_type_id: form.ticket_type_id } : {}),
          ...(form.provider === "connectwise" ? { board_id: form.board_id } : {}),
          ...(form.provider !== "halopsa" ? { priority_id: form.priority_id || null } : {}),
          ...(form.provider === "autotask" ? { ticket_category_id: form.ticket_category_id || null, queue_id: form.queue_id || null } : {}),
          default_client_id: form.default_client_id || null, open_status_id: form.open_status_id || null,
          resolved_status_id: form.resolved_status_id || null, auto_close: form.auto_close, client_mappings: clientMappings,
        },
        ...(credentials ? { credentials } : {}),
      };
      const path = `/api/orgs/${orgId}/psa-integrations${editing ? `/${editing}` : ""}`;
      await request(path, { method: editing ? "PATCH" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      setForm(EMPTY); setEditing(null); setShowForm(false); setMessage("PSA integration saved."); await load();
    } catch (cause) { setError((cause as Error).message || "Could not save integration"); }
    finally { setBusy(false); }
  };

  const runTest = async (id: string) => {
    setBusy(true); setError(""); setMessage("");
    try {
      const data = await request<{ message: string }>(`/api/orgs/${orgId}/psa-integrations/${id}/test`, { method: "POST" });
      setMessage(data.message);
    } catch (cause) { setError((cause as Error).message || "PSA test failed"); }
    finally { setBusy(false); }
  };

  const remove = async (id: string) => {
    if (!window.confirm("Delete this PSA integration and its ticket links?")) return;
    setBusy(true); setError(""); setMessage("");
    try { await request(`/api/orgs/${orgId}/psa-integrations/${id}`, { method: "DELETE" }); setMessage("Integration deleted."); await load(); }
    catch (cause) { setError((cause as Error).message || "Could not delete integration"); }
    finally { setBusy(false); }
  };

  const retry = async (integrationId: string, kind: "incident" | "detection", recordId: string) => {
    setBusy(true); setError(""); setMessage("");
    try {
      const data = await request<{ link: { sync_status: string; external_ticket_id: string | null; last_error: string | null } | null }>(`/api/orgs/${orgId}/psa-integrations/${integrationId}/sync`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(kind === "incident" ? { incident_id: recordId } : { detection_id: recordId }),
      });
      if (data.link?.sync_status === "synced") setMessage(data.link.external_ticket_id ? `PSA ticket ${data.link.external_ticket_id} synced.` : "PSA ticket synced.");
      else setError(data.link?.last_error || "The retry did not complete. Check the integration and incident mapping.");
      await load();
    } catch (cause) { setError((cause as Error).message || "PSA retry failed"); }
    finally { setBusy(false); }
  };

  const set = <K extends keyof Form>(key: K, value: Form[K]) => setForm((current) => ({ ...current, [key]: value }));

  return <section className="mt-8 rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="text-lg font-semibold text-white">PSA ticket integrations</h2><p className="text-sm text-zinc-500">Create deduplicated tickets for incidents and low-severity alerts, update incident tickets as they change, and optionally close them when resolved.</p></div>
      {canManage && <button onClick={() => { setShowForm(!showForm); setEditing(null); setForm(EMPTY); setError(""); }} className="rounded border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800">{showForm ? "Cancel" : "Add PSA integration"}</button>}
    </div>
    <p className="mb-4 text-xs text-zinc-500">Credentials are encrypted with SETTINGS_ENCRYPTION_KEY and never returned by this API. Team mappings take priority, then fleet mappings, then the default client. Mapping keys use team:&lt;UUID&gt; or fleet:&lt;UUID&gt;.</p>
    {error && <p role="alert" className="mb-3 text-sm text-red-400">{error}</p>}{message && <p role="status" className="mb-3 text-sm text-green-400">{message}</p>}
    {showForm && <div className="mb-4 grid gap-3 rounded-lg border border-zinc-800 bg-black/30 p-4 sm:grid-cols-2">
      <label className="text-xs text-zinc-400">Name<input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Production PSA" className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      <label className="text-xs text-zinc-400">Provider<select disabled={!!editing} value={form.provider} onChange={(e) => set("provider", e.target.value as Integration["provider"])} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white"><option value="halopsa">HaloPSA</option><option value="connectwise">ConnectWise Manage</option><option value="autotask">Autotask</option></select></label>
      <label className="text-xs text-zinc-400 sm:col-span-2">{form.provider === "halopsa" ? "Halo API resource URL" : form.provider === "connectwise" ? "ConnectWise API 3.0 base URL" : "Autotask REST API v1.0 base URL"}<input value={form.api_url} onChange={(e) => set("api_url", e.target.value)} placeholder={form.provider === "halopsa" ? "https://your-halo.example/api" : form.provider === "connectwise" ? "https://api-na.myconnectwise.net/v4_6_release/apis/3.0" : "https://webservicesN.autotask.net/atservicesrest/v1.0"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      {form.provider === "halopsa" && <>
        <label className="text-xs text-zinc-400">OAuth token URL<input value={form.auth_url} onChange={(e) => set("auth_url", e.target.value)} placeholder="https://your-halo.example/auth/token" className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">OAuth client ID<input value={form.client_id} onChange={(e) => set("client_id", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "Client ID"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">OAuth client secret<input type="password" autoComplete="new-password" value={form.client_secret} onChange={(e) => set("client_secret", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "Client secret"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">Halo ticket type ID<input inputMode="numeric" value={form.ticket_type_id} onChange={(e) => set("ticket_type_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      </>}
      {form.provider === "connectwise" && <>
        <label className="text-xs text-zinc-400">Company ID<input value={form.company_id} onChange={(e) => set("company_id", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "ConnectWise company"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">API public key<input value={form.public_key} onChange={(e) => set("public_key", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "Public key"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">API private key<input type="password" autoComplete="new-password" value={form.private_key} onChange={(e) => set("private_key", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "Private key"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">ConnectWise client ID<input value={form.client_id} onChange={(e) => set("client_id", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "Developer client ID"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">Service board ID<input inputMode="numeric" value={form.board_id} onChange={(e) => set("board_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">Priority ID (optional)<input inputMode="numeric" value={form.priority_id} onChange={(e) => set("priority_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      </>}
      {form.provider === "autotask" && <>
        <label className="text-xs text-zinc-400">API username<input value={form.username} onChange={(e) => set("username", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "API-only username"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">API secret<input type="password" autoComplete="new-password" value={form.secret} onChange={(e) => set("secret", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "Secret"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">API integration code<input value={form.integration_code} onChange={(e) => set("integration_code", e.target.value)} placeholder={editing ? "Leave blank to keep current" : "Integration code"} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">Ticket category ID (optional)<input inputMode="numeric" value={form.ticket_category_id} onChange={(e) => set("ticket_category_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">Queue ID (optional)<input inputMode="numeric" value={form.queue_id} onChange={(e) => set("queue_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
        <label className="text-xs text-zinc-400">Priority ID (optional)<input inputMode="numeric" value={form.priority_id} onChange={(e) => set("priority_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      </>}
      <label className="text-xs text-zinc-400">Default PSA client/company ID (optional)<input inputMode="numeric" value={form.default_client_id} onChange={(e) => set("default_client_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      <label className="text-xs text-zinc-400">Open status ID (optional)<input inputMode="numeric" value={form.open_status_id} onChange={(e) => set("open_status_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      <label className="text-xs text-zinc-400">Resolved status ID (optional)<input inputMode="numeric" value={form.resolved_status_id} onChange={(e) => set("resolved_status_id", e.target.value)} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 text-sm text-white" /></label>
      <label className="flex items-center gap-2 text-sm text-zinc-300"><input type="checkbox" checked={form.auto_close} onChange={(e) => set("auto_close", e.target.checked)} className="accent-purple-500" />Close the PSA ticket when the ThreatCrush incident is resolved</label>
      <label className="text-xs text-zinc-400 sm:col-span-2">Team/fleet client mapping JSON<textarea value={form.client_mappings} onChange={(e) => set("client_mappings", e.target.value)} rows={4} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2 font-mono text-xs text-white" /></label>
      <div className="flex justify-end gap-2 sm:col-span-2"><button disabled={busy} onClick={() => { setShowForm(false); setEditing(null); setForm(EMPTY); }} className="rounded px-3 py-2 text-sm text-zinc-400">Cancel</button><button disabled={busy || !form.name} onClick={() => void save()} className="rounded bg-green-500 px-4 py-2 text-sm font-medium text-black disabled:opacity-50">{busy ? "Saving…" : editing ? "Update integration" : "Save integration"}</button></div>
    </div>}
    {items.length === 0 ? <p className="rounded-lg border border-zinc-800 p-5 text-center text-sm text-zinc-500">No PSA integrations configured.</p> : <ul className="space-y-2">{items.map((item) => {
      const failed = item.recent_links?.filter((link) => link.sync_status === "failed").slice(0, 3) ?? [];
      const latest = item.recent_links?.[0];
      return <li key={item.id} className="rounded-lg border border-zinc-800 bg-black/30 p-3">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="font-medium text-white">{item.name}<span className={`ml-2 text-xs ${item.enabled ? "text-green-400" : "text-zinc-500"}`}>{item.enabled ? "Active" : "Disabled"}</span></p><p className="text-xs text-zinc-500">{item.provider === "halopsa" ? "HaloPSA" : item.provider === "connectwise" ? "ConnectWise Manage" : "Autotask"} · {item.config.auto_close ? "auto-close on resolution" : "manual close"}</p>{latest && <p className="mt-1 text-xs text-zinc-500">Latest {latest.detection_id ? "alert" : "incident"} sync: <span className={latest.sync_status === "synced" ? "text-green-400" : latest.sync_status === "failed" ? "text-red-300" : "text-zinc-300"}>{latest.sync_status}</span>{latest.external_ticket_id && ` · ticket ${latest.external_ticket_id}`}</p>}</div>{canManage && <div className="flex gap-2"><button disabled={busy} onClick={() => void runTest(item.id)} className="rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 disabled:opacity-50">Test</button><button disabled={busy} onClick={() => edit(item)} className="rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 disabled:opacity-50">Edit</button><button disabled={busy} onClick={() => void remove(item.id)} className="rounded border border-red-900 px-3 py-1.5 text-xs text-red-300 disabled:opacity-50">Delete</button></div>}</div>
        {failed.length > 0 && <ul className="mt-3 space-y-2 border-t border-zinc-800 pt-3">{failed.map((link) => { const kind = link.detection_id ? "detection" : "incident"; const recordId = link.detection_id ?? link.incident_id; return <li key={recordId} className="flex flex-wrap items-center justify-between gap-2 text-xs"><span className="text-red-300">Sync failed: {link.last_error || "Unknown error"}</span>{canManage && recordId && <button disabled={busy} onClick={() => void retry(item.id, kind, recordId)} className="rounded border border-zinc-700 px-2 py-1 text-zinc-300 disabled:opacity-50">Retry {kind}</button>}</li>; })}</ul>}
      </li>;
    })}</ul>}
  </section>;
}
