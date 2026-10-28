"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

// Tracked findings from `threatcrush scan`, `pentest` and `ai-scan` (uploaded
// by the CLI when signed in, or by property runs). Same data and actions as
// `threatcrush findings` and the desktop app.

interface ScanFinding {
  id: string;
  source: "scan" | "pentest" | "ai-scan";
  type: string;
  severity: string;
  message: string;
  location: string | null;
  status: string;
  note: string | null;
  first_seen_at: string;
  last_seen_at: string;
  times_seen: number;
  status_source: string;
  properties?: { name: string; kind: string; target: string } | null;
  details?: Record<string, unknown>;
}

const STATUSES = [
  { key: "open,acknowledged", label: "Needs a decision" },
  { key: "open", label: "Open" },
  { key: "acknowledged", label: "Acknowledged" },
  { key: "fixed", label: "Fixed" },
  { key: "false_positive", label: "False positive" },
  { key: "ignored", label: "Ignored" },
  { key: "all", label: "All" },
];
const ACTIONS = [
  { status: "acknowledged", label: "Acknowledge", cls: "text-yellow-400" },
  { status: "fixed", label: "Fixed", cls: "text-green-400" },
  { status: "false_positive", label: "False positive", cls: "text-zinc-300" },
  { status: "ignored", label: "Ignore", cls: "text-zinc-400" },
  { status: "open", label: "Reopen", cls: "text-red-400" },
];
const SEV_CLS: Record<string, string> = {
  critical: "bg-red-600 text-white", high: "bg-red-500/20 text-red-400", medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-blue-500/20 text-blue-400", info: "bg-zinc-700 text-zinc-300",
};
const SOURCE_LABEL: Record<string, string> = { scan: "Code scan", pentest: "Pentest", "ai-scan": "AI red-team" };
const day = (iso: string) => new Date(iso).toLocaleDateString();

export default function ScanFindingsPanel({ orgId, canTriage }: { orgId: string; canTriage: boolean }) {
  const [status, setStatus] = useState("open,acknowledged");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [rows, setRows] = useState<ScanFinding[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState<string | null>(null);
  const [detail, setDetail] = useState<Record<string, ScanFinding>>({});
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    const qs = new URLSearchParams({ status, limit: "200" });
    if (severity) qs.set("severity", severity);
    if (source) qs.set("source", source);
    try {
      const res = await fetch(`/api/orgs/${orgId}/scan-findings?${qs}`, { headers: authHeaders() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setRows(data.findings);
      setCounts(data.counts || {});
      setTotal(data.total || 0);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [orgId, status, severity, source]);

  useEffect(() => { load(); setSelected(new Set()); }, [load]);

  const expand = async (id: string) => {
    setOpen(open === id ? null : id);
    setNote(rows.find((r) => r.id === id)?.note ?? "");
    if (detail[id]) return;
    const res = await fetch(`/api/orgs/${orgId}/scan-findings/${id}`, { headers: authHeaders() });
    if (res.ok) {
      const { finding } = await res.json();
      setDetail((d) => ({ ...d, [id]: finding }));
    }
  };

  const triage = async (ids: string[], next: string | null, withNote?: string) => {
    const body: Record<string, unknown> = { ids };
    if (next) body.status = next;
    if (withNote !== undefined) body.note = withNote;
    const res = await fetch(`/api/orgs/${orgId}/scan-findings`, {
      method: "PATCH",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.error || `HTTP ${res.status}`);
      return;
    }
    setSelected(new Set());
    await load();
  };

  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const needs = (counts.open ?? 0) + (counts.acknowledged ?? 0);
  const countFor = (key: string) => key === "all" ? Object.values(counts).reduce((a, b) => a + b, 0) : key.split(",").reduce((a, k) => a + (counts[k] ?? 0), 0);

  return (
    <section className="mb-10">
      <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
        <div>
          <h2 className="text-xl font-semibold text-white">Scan, pentest and AI red-team findings</h2>
          <p className="text-sm text-zinc-500">{needs} need a decision · tracked across runs; a finding that stops showing up is marked fixed automatically</p>
        </div>
        <div className="flex gap-2">
          <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source"
            className="rounded bg-zinc-900 border border-zinc-700 px-2 py-1 text-sm text-zinc-200">
            <option value="">All sources</option>
            <option value="scan">Code scan</option>
            <option value="pentest">Pentest</option>
            <option value="ai-scan">AI red-team</option>
          </select>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity"
            className="rounded bg-zinc-900 border border-zinc-700 px-2 py-1 text-sm text-zinc-200">
            <option value="">All severities</option>
            <option value="critical,high">Critical + high</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-4" role="tablist">
        {STATUSES.map((s) => (
          <button key={s.key} role="tab" aria-selected={status === s.key} onClick={() => setStatus(s.key)}
            className={`rounded-full px-3 py-1 text-xs border ${status === s.key ? "bg-zinc-200 text-black border-zinc-200" : "bg-zinc-900 text-zinc-300 border-zinc-700 hover:border-zinc-500"}`}>
            {s.label} <span className="opacity-60">{countFor(s.key)}</span>
          </button>
        ))}
      </div>

      {canTriage && selected.size > 0 && (
        <div className="sticky top-2 z-10 flex flex-wrap items-center gap-2 mb-3 rounded-lg bg-zinc-800 border border-zinc-700 p-2">
          <span className="text-sm text-zinc-300 px-1">{selected.size} selected</span>
          {ACTIONS.map((a) => (
            <button key={a.status} onClick={() => triage([...selected], a.status)}
              className={`rounded px-2 py-1 text-xs bg-zinc-900 border border-zinc-700 hover:bg-zinc-700 ${a.cls}`}>{a.label}</button>
          ))}
          <button onClick={() => setSelected(new Set())} className="ml-auto text-xs text-zinc-500 hover:text-zinc-300 px-2">Clear</button>
        </div>
      )}

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}

      <div className="rounded-lg bg-zinc-900 border border-zinc-800 divide-y divide-zinc-800">
        {loading && rows.length === 0 && <p className="p-4 text-sm text-zinc-500">Loading…</p>}
        {!loading && rows.length === 0 && (
          countFor("all") === 0 ? (
            <div className="p-6 text-sm text-zinc-400">
              <p className="mb-2">No scan findings yet. Sign in once from the CLI and every run is saved here:</p>
              <pre className="rounded bg-black p-3 text-xs text-zinc-300 overflow-x-auto">threatcrush login{"\n"}threatcrush scan .{"\n"}threatcrush ai-scan https://your-llm-endpoint</pre>
            </div>
          ) : <p className="p-4 text-sm text-zinc-500">Nothing in this view.</p>
        )}
        {rows.map((f) => {
          const d = detail[f.id]?.details ?? {};
          return (
            <div key={f.id} className="p-3 sm:p-4">
              <div className="flex items-start gap-3">
                {canTriage && (
                  <input type="checkbox" checked={selected.has(f.id)} onChange={() => toggle(f.id)} aria-label="Select finding"
                    className="mt-1.5 h-4 w-4 accent-zinc-300" />
                )}
                <button onClick={() => expand(f.id)} className="flex-1 min-w-0 text-left">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${SEV_CLS[f.severity] ?? SEV_CLS.info}`}>{f.severity}</span>
                    <span className="text-white font-medium break-words">{f.message}</span>
                  </div>
                  <p className="text-xs text-zinc-500 mt-1 break-all">
                    {SOURCE_LABEL[f.source] ?? f.source} · {f.properties?.name ?? "?"}{f.location ? ` · ${f.location}` : ""} · seen {f.times_seen}× · last {day(f.last_seen_at)}
                    {f.status !== "open" && <> · <span className="text-zinc-300">{f.status.replace("_", " ")}</span>{f.status_source === "sync" && f.status === "fixed" ? " (gone from the last run)" : ""}</>}
                  </p>
                </button>
              </div>
              {open === f.id && (
                <div className="mt-3 sm:ml-7 space-y-2 text-sm">
                  {typeof d.snippet === "string" && <pre className="rounded bg-black p-2 text-xs text-zinc-300 overflow-x-auto">{d.snippet}</pre>}
                  {typeof d.remediation === "string" && <p className="text-zinc-300"><span className="text-zinc-500">Fix: </span>{d.remediation}</p>}
                  {typeof d.evidence === "string" && <p className="text-zinc-400 break-words"><span className="text-zinc-500">Evidence: </span>{d.evidence}</p>}
                  <p className="text-xs text-zinc-500">First seen {day(f.first_seen_at)} · {f.type} · {f.properties?.target}</p>
                  {canTriage ? (
                    <>
                      <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Note (why it is fixed, ignored, a false positive…)"
                        className="w-full rounded bg-black border border-zinc-700 p-2 text-sm text-zinc-200" />
                      <div className="flex flex-wrap gap-2">
                        {ACTIONS.filter((a) => a.status !== f.status).map((a) => (
                          <button key={a.status} onClick={() => triage([f.id], a.status, note)}
                            className={`rounded px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 ${a.cls}`}>{a.label}</button>
                        ))}
                        {note !== (f.note ?? "") && (
                          <button onClick={() => triage([f.id], null, note)} className="rounded px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 text-zinc-200">Save note</button>
                        )}
                      </div>
                    </>
                  ) : f.note ? <p className="text-zinc-400"><span className="text-zinc-500">Note: </span>{f.note}</p> : null}
                </div>
              )}
            </div>
          );
        })}
      </div>
      {total > rows.length && <p className="mt-2 text-xs text-zinc-500">Showing {rows.length} of {total}. Narrow the filters to see the rest.</p>}
    </section>
  );
}
