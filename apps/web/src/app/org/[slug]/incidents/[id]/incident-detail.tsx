"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";
import { Centered, SeverityBadge, Shell, STATUS_CLS, useOrg, when } from "../shared";

interface Finding { id: string; module: string; severity: string; title: string; detail?: string; evidence: "evidence" | "inference"; at?: string }
interface TimelineEntry { at: string; module: string; summary: string; evidence: boolean; ref?: string }
interface Recommendation { action: string; target?: string; priority: "now" | "soon" | "later" }
interface Incident {
  id: string; short_code: string; human_code: string; title: string; severity: string; status: string; source: string; host: string | null;
  summary: string; verdict: string | null; team_id: string | null; team_name: string | null;
  assignee_id: string | null; assignee_name: string | null; raise_count: number;
  findings: Finding[]; timeline: TimelineEntry[]; recommendations: Recommendation[];
  first_seen_at: string; last_seen_at: string; acknowledged_at: string | null; resolved_at: string | null;
}
interface Detail {
  incident: Incident;
  role: "read" | "write" | "admin";
  members: Array<{ user_id: string; name: string }>;
  notes: Array<{ id: string; author_name: string | null; body: string; created_at: string }>;
  notifications: Array<{ id: string; user_name: string | null; channel: string; status: string; detail: string | null; created_at: string }>;
}

const PRIORITY_CLS: Record<string, string> = { now: "text-red-400", soon: "text-yellow-400", later: "text-zinc-400" };

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-6 rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">{title}</h2>
      {children}
    </section>
  );
}

function FindingList({ items }: { items: Finding[] }) {
  if (!items.length) return <p className="text-sm text-zinc-500">None.</p>;
  return (
    <ul className="space-y-2">
      {items.map((f) => (
        <li key={f.id} className="rounded border border-zinc-800 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <span className="text-xs text-zinc-500">{f.module}</span>
            <span className="text-white">{f.title}</span>
            {f.at && <span className="text-xs text-zinc-500">{when(f.at)}</span>}
          </div>
          {f.detail && <p className="mt-1 whitespace-pre-line text-sm text-zinc-400">{f.detail}</p>}
        </li>
      ))}
    </ul>
  );
}

export default function IncidentDetail({ slug, incidentId }: { slug: string; incidentId: string }) {
  const { org, ready } = useOrg(slug);
  const [data, setData] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!org) return;
    const res = await fetch(`/api/orgs/${org.id}/incidents/${incidentId}`, { headers: authHeaders() });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error || `HTTP ${res.status}`); return; }
    setData(body as Detail);
    setError(null);
  }, [org, incidentId]);

  useEffect(() => { void load(); }, [load]);

  const patch = async (body: Record<string, unknown>) => {
    if (!org) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/orgs/${org.id}/incidents/${incidentId}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body),
      });
      const out = await res.json().catch(() => ({}));
      if (!res.ok) setError(out.error || `HTTP ${res.status}`);
      await load();
    } finally {
      setBusy(false);
    }
  };

  if (!ready) return <Centered text="Loading..." />;
  if (!org) return <Centered text="Organization not found" />;
  if (!data) return <Centered text={error ?? "Loading..."} />;

  const inc = data.incident;
  const canWrite = data.role === "write" || data.role === "admin";
  const evidence = inc.findings.filter((f) => f.evidence === "evidence");
  const inference = inc.findings.filter((f) => f.evidence === "inference");
  const timeline = [...inc.timeline].sort((a, b) => a.at.localeCompare(b.at));

  return (
    <Shell>
      <div className="mb-6 flex items-start gap-3">
        <Link href={`/org/${slug}/incidents`} className="mt-1 text-zinc-500 hover:text-zinc-300" aria-label="Back to incidents">
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
        </Link>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={inc.severity} />
            <span className={`text-sm capitalize ${STATUS_CLS[inc.status] ?? ""}`}>{inc.status}</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold text-white break-words">{inc.title}</h1>
          <p className="text-xs text-zinc-500">
            Short link: <Link href={`/ic/${inc.human_code}`} className="font-mono text-zinc-300 hover:text-white">threatcrush.com/ic/{inc.human_code}</Link>
          </p>
          <p className="text-sm text-zinc-500">
            {inc.host ? `${inc.host} · ` : ""}{inc.team_name ?? "no team"} · {inc.source} · first {when(inc.first_seen_at)} · last {when(inc.last_seen_at)}
            {inc.raise_count > 1 ? ` · raised ${inc.raise_count}×` : ""}
          </p>
        </div>
      </div>

      {error && <p className="mb-4 text-sm text-red-400">{error}</p>}

      {canWrite && (
        <div className="mb-6 flex flex-wrap items-center gap-2">
          {inc.status !== "acknowledged" && inc.status !== "resolved" && (
            <button disabled={busy} onClick={() => patch({ status: "acknowledged" })} className="rounded bg-yellow-500 px-3 py-1.5 text-sm font-medium text-black hover:bg-yellow-400 disabled:opacity-50">Acknowledge</button>
          )}
          {inc.status !== "resolved" && (
            <button disabled={busy} onClick={() => patch({ status: "resolved" })} className="rounded bg-green-500 px-3 py-1.5 text-sm font-medium text-black hover:bg-green-400 disabled:opacity-50">Resolve</button>
          )}
          {inc.status !== "open" && (
            <button disabled={busy} onClick={() => patch({ status: "open" })} className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:border-zinc-500 disabled:opacity-50">Reopen</button>
          )}
          <label className="ml-auto flex items-center gap-2 text-sm text-zinc-400">
            Assignee
            <select disabled={busy} value={inc.assignee_id ?? ""} onChange={(e) => patch({ assignee_id: e.target.value || null })}
              className="rounded border border-zinc-700 bg-black px-2 py-1 text-zinc-200">
              <option value="">Nobody</option>
              {data.members.map((m) => <option key={m.user_id} value={m.user_id}>{m.name}</option>)}
            </select>
          </label>
        </div>
      )}
      {!canWrite && inc.assignee_name && <p className="mb-6 text-sm text-zinc-400">Assigned to {inc.assignee_name}</p>}

      {(inc.verdict || inc.summary) && (
        <Section title="Verdict">
          {inc.verdict && <p className="mb-2 whitespace-pre-line text-white">{inc.verdict}</p>}
          {inc.summary && <p className="whitespace-pre-line text-sm text-zinc-400">{inc.summary}</p>}
        </Section>
      )}

      {inc.recommendations.length > 0 && (
        <Section title="Recommended actions">
          <ul className="space-y-1">
            {inc.recommendations.map((r, i) => (
              <li key={i} className="text-sm text-zinc-200">
                <span className={`mr-2 text-xs font-semibold uppercase ${PRIORITY_CLS[r.priority]}`}>{r.priority}</span>
                {r.action}{r.target ? <span className="text-zinc-400">: {r.target}</span> : null}
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title="Timeline">
        {timeline.length === 0 ? <p className="text-sm text-zinc-500">No timeline entries.</p> : (
          <ol className="relative border-l border-zinc-800 pl-4">
            {timeline.map((t, i) => (
              <li key={`${t.at}-${i}`} className="mb-3">
                <span className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ${t.evidence ? "bg-red-500" : "border border-zinc-500 bg-black"}`} />
                <p className="text-xs text-zinc-500">{when(t.at)} · {t.module} · {t.evidence ? "evidence" : "inference"}</p>
                <p className="text-sm text-zinc-200 break-words">{t.summary}</p>
                {t.ref && <p className="text-xs text-zinc-600 break-all">{t.ref}</p>}
              </li>
            ))}
          </ol>
        )}
      </Section>

      <Section title={`Evidence (${evidence.length})`}><FindingList items={evidence} /></Section>
      <Section title={`Inference (${inference.length})`}>
        <p className="mb-2 text-xs text-zinc-500">What the investigation concluded from the evidence; check before acting.</p>
        <FindingList items={inference} />
      </Section>

      <Section title="Notes">
        {data.notes.length === 0 && <p className="mb-3 text-sm text-zinc-500">No notes yet.</p>}
        <ul className="mb-3 space-y-2">
          {data.notes.map((n) => (
            <li key={n.id} className="rounded border border-zinc-800 p-3">
              <p className="text-xs text-zinc-500">{n.author_name ?? "agent"} · {when(n.created_at)}</p>
              <p className="whitespace-pre-line text-sm text-zinc-200">{n.body}</p>
            </li>
          ))}
        </ul>
        {canWrite && (
          <form onSubmit={(e) => { e.preventDefault(); if (note.trim()) void patch({ note }).then(() => setNote("")); }} className="flex flex-col gap-2 sm:flex-row">
            <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={4000} placeholder="Add a note (never paste keys or seed phrases)"
              className="flex-1 rounded border border-zinc-700 bg-black p-2 text-sm text-zinc-200" />
            <button disabled={busy || !note.trim()} className="rounded bg-purple-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-purple-500 disabled:opacity-50">Add note</button>
          </form>
        )}
      </Section>

      <Section title="Who was paged">
        {data.notifications.length === 0 ? <p className="text-sm text-zinc-500">Nobody yet.</p> : (
          <ul className="space-y-1 text-sm">
            {data.notifications.map((n) => (
              <li key={n.id} className="text-zinc-300">
                <span className="text-zinc-500">{when(n.created_at)}</span> · {n.user_name ?? "member"} · {n.channel} ·{" "}
                <span className={n.status === "sent" ? "text-green-400" : n.status === "failed" ? "text-red-400" : "text-zinc-400"}>{n.status}</span>
                {n.detail ? <span className="text-zinc-500"> ({n.detail})</span> : null}
              </li>
            ))}
          </ul>
        )}
      </Section>
    </Shell>
  );
}
