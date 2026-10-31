"use client";

import Link from "next/link";
import type { forensicEvidence } from "@/lib/incidents/forensics";
import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";
import { Centered, SeverityBadge, Shell, STATUS_CLS, useOrg, when } from "../shared";

interface Finding { id: string; module: string; severity: string; title: string; detail?: string; evidence: "evidence" | "inference"; at?: string }
interface TimelineEntry { at: string; module: string; summary: string; evidence: boolean; ref?: string }
interface Recommendation { action: string; target?: string; priority: "now" | "soon" | "later" }
type FixStatus = "unassigned" | "assigned" | "in_progress" | "blocked" | "pr_open" | "testing" | "tested" | "fixed" | "false_positive";
type FixTestStatus = "not_run" | "running" | "passed" | "failed" | "skipped";
interface FixWorkForm { status: FixStatus; pr_url: string; test_status: FixTestStatus; test_summary: string; test_url: string; verification: string; blocked_reason: string }
interface Incident {
  id: string; short_code: string; human_code: string; title: string; severity: string; status: string; source: string; host: string | null;
  summary: string; verdict: string | null; team_id: string | null; team_name: string | null;
  assignee_id: string | null; assignee_name: string | null; raise_count: number;
  assignees: Array<{ user_id: string; name: string; email: string | null; assigned_at: string }>;
  fix_status: FixStatus; fix_pr_url: string | null; fix_test_status: FixTestStatus; fix_test_summary: string | null;
  fix_test_url: string | null; fix_verification: string | null; fix_blocked_reason: string | null; fix_updated_at: string | null;
  findings: Finding[]; timeline: TimelineEntry[]; recommendations: Recommendation[];
  resolution?: { reason: string; action: string; verification: string; actor_user_id: string | null; actor_agent_key_id: string | null; at: string } | null;
  first_seen_at: string; last_seen_at: string; acknowledged_at: string | null; resolved_at: string | null;
}
interface Detail {
  incident: Incident;
  forensics?: ReturnType<typeof forensicEvidence>[];
  resolution_actor_name?: string | null;
  role: "read" | "write" | "admin";
  members: Array<{ user_id: string; name: string; email: string | null }>;
  fix_events: Array<{ id: string; actor_label: string; event_type: string; details: Record<string, unknown>; created_at: string }>;
  notes: Array<{ id: string; author_name: string | null; body: string; created_at: string }>;
  notifications: Array<{ id: string; user_name: string | null; channel: string; status: string; detail: string | null; created_at: string }>;
}

const PRIORITY_CLS: Record<string, string> = { now: "text-red-400", soon: "text-yellow-400", later: "text-zinc-400" };
const FIX_STATUS_LABEL: Record<FixStatus, string> = {
  unassigned: "Unassigned", assigned: "Assigned", in_progress: "In progress", blocked: "Blocked", pr_open: "PR open",
  testing: "Testing", tested: "Tested", fixed: "Fixed", false_positive: "False positive",
};
const TEST_STATUS_LABEL: Record<FixTestStatus, string> = { not_run: "Not run", running: "Running", passed: "Passed", failed: "Failed", skipped: "Skipped" };

function eventSummary(event: Detail["fix_events"][number]): string {
  if (event.event_type === "assignees_changed") {
    const details = event.details as { added?: Array<{ name?: string; email?: string | null }>; removed?: Array<{ name?: string; email?: string | null }> };
    const added = (details.added ?? []).map((x) => x.email || x.name || "member");
    const removed = (details.removed ?? []).map((x) => x.email || x.name || "member");
    return [added.length ? `Assigned ${added.join(", ")}` : "", removed.length ? `Removed ${removed.join(", ")}` : ""].filter(Boolean).join(" · ");
  }
  const changes = (event.details.changes ?? {}) as Record<string, { from?: unknown; to?: unknown }>;
  const labels: Record<string, string> = { status: "Work", pr_url: "PR", test_status: "Tests", test_summary: "Test evidence", test_url: "Test run", verification: "Verification", blocked_reason: "Blocker" };
  return Object.entries(changes).map(([key, value]) => {
    const fmt = (x: unknown) => typeof x === "string" ? x : x == null ? "—" : JSON.stringify(x);
    return `${labels[key] ?? key}: ${fmt(value.from)} → ${fmt(value.to)}`;
  }).join(" · ") || "Updated fix progress";
}

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
  const [message, setMessage] = useState<string | null>(null);
  const [closing, setClosing] = useState(false);
  const [resolution, setResolution] = useState({ reason: "", action: "", verification: "" });
  const [selectedAssigneeIds, setSelectedAssigneeIds] = useState<string[]>([]);
  const [fixWork, setFixWork] = useState<FixWorkForm>({ status: "unassigned", pr_url: "", test_status: "not_run", test_summary: "", test_url: "", verification: "", blocked_reason: "" });

  const load = useCallback(async () => {
    if (!org) return;
    const res = await fetch(`/api/orgs/${org.id}/incidents/${incidentId}`, { headers: authHeaders() });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error || `HTTP ${res.status}`); return; }
    setData(body as Detail);
    const incident = (body as Detail).incident;
    setSelectedAssigneeIds(incident.assignees.map((x) => x.user_id));
    setFixWork({
      status: incident.fix_status,
      pr_url: incident.fix_pr_url ?? "",
      test_status: incident.fix_test_status,
      test_summary: incident.fix_test_summary ?? "",
      test_url: incident.fix_test_url ?? "",
      verification: incident.fix_verification ?? "",
      blocked_reason: incident.fix_blocked_reason ?? "",
    });
    setError(null);
  }, [org, incidentId]);

  useEffect(() => { void load(); }, [load]);

  const patch = async (body: Record<string, unknown>) => {
    if (!org) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const res = await fetch(`/api/orgs/${org.id}/incidents/${incidentId}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body),
      });
      const out = await res.json().catch(() => ({}));
      if (!res.ok) { setError(out.error || `HTTP ${res.status}`); return false; }
      await load();
      setMessage(body.status === "resolved" ? "Resolution saved with action, verification and operator." : body.fix_work || body.assignee_ids ? "Fix progress and assignments saved." : "Incident updated.");
      return true;
    } catch {
      setError("Could not save the incident. Your input is preserved; try again.");
      return false;
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

      {error && <p role="alert" className="mb-4 text-sm text-red-400">{error}</p>}
      {message && <p role="status" className="mb-4 text-sm text-green-400">{message}</p>}

      {canWrite && (
        <div className="mb-6 flex flex-wrap items-center gap-2">
          {inc.status !== "acknowledged" && inc.status !== "resolved" && (
            <button disabled={busy} onClick={() => patch({ status: "acknowledged" })} className="rounded bg-yellow-500 px-3 py-1.5 text-sm font-medium text-black hover:bg-yellow-400 disabled:opacity-50">Acknowledge</button>
          )}
          {inc.status !== "resolved" && (
            <button disabled={busy} onClick={() => setClosing(true)} className="rounded bg-green-500 px-3 py-1.5 text-sm font-medium text-black hover:bg-green-400 disabled:opacity-50">Resolve</button>
          )}
          {inc.status !== "open" && (
            <button disabled={busy} onClick={() => patch({ status: "open" })} className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:border-zinc-500 disabled:opacity-50">Reopen</button>
          )}
        </div>
      )}

      <Section title="Fix workflow">
        <p className="mb-4 text-sm text-zinc-400">ThreatCrush catalogs the incident. Assigned agents or people do the remediation and report progress here or through MCP. Closing requires a recorded outcome and verification.</p>
        <div className="mb-5">
          <h3 className="mb-2 text-sm font-medium text-white">Assigned people</h3>
          <p className="mb-2 text-xs text-zinc-500">Assignment gives each selected person write access to this incident so they can update the fix record.</p>
          {canWrite ? data.members.length ? (
            <div className="grid gap-2 sm:grid-cols-2">
              {data.members.map((m) => (
                <label key={m.user_id} className="flex items-start gap-2 rounded border border-zinc-800 p-2 text-sm text-zinc-200">
                  <input type="checkbox" checked={selectedAssigneeIds.includes(m.user_id)} disabled={busy}
                    onChange={(e) => setSelectedAssigneeIds((current) => e.target.checked ? [...current, m.user_id] : current.filter((id) => id !== m.user_id))}
                    className="mt-1 accent-purple-500" />
                  <span>{m.name}{m.email && <span className="block text-xs text-zinc-500">{m.email}</span>}</span>
                </label>
              ))}
            </div>
          ) : <p className="text-sm text-zinc-500">No active team members are available to assign.</p> : (
            <p className="text-sm text-zinc-300">{inc.assignees.length ? inc.assignees.map((a) => a.email || a.name).join(", ") : "Nobody assigned"}</p>
          )}
        </div>

        {canWrite ? (
          <form className="space-y-3" onSubmit={(e) => {
            e.preventDefault();
            void patch({ assignee_ids: selectedAssigneeIds, fix_work: fixWork });
          }}>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block text-sm text-zinc-300">Fix status
                <select value={fixWork.status} disabled={busy} onChange={(e) => setFixWork({ ...fixWork, status: e.target.value as FixStatus })} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2">
                  {Object.entries(FIX_STATUS_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
              </label>
              <label className="block text-sm text-zinc-300">Pull request
                <input type="url" inputMode="url" maxLength={2000} placeholder="https://github.com/org/repo/pull/123" value={fixWork.pr_url} disabled={busy} onChange={(e) => setFixWork({ ...fixWork, pr_url: e.target.value })} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2" />
              </label>
              <label className="block text-sm text-zinc-300">Test status
                <select value={fixWork.test_status} disabled={busy} onChange={(e) => setFixWork({ ...fixWork, test_status: e.target.value as FixTestStatus })} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2">
                  {Object.entries(TEST_STATUS_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
              </label>
              <label className="block text-sm text-zinc-300">Test run URL (optional)
                <input type="url" inputMode="url" maxLength={2000} placeholder="CI run or test report" value={fixWork.test_url} disabled={busy} onChange={(e) => setFixWork({ ...fixWork, test_url: e.target.value })} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2" />
              </label>
            </div>
            <label className="block text-sm text-zinc-300">Test evidence
              <textarea maxLength={4000} value={fixWork.test_summary} disabled={busy} onChange={(e) => setFixWork({ ...fixWork, test_summary: e.target.value })} placeholder="What ran and what passed or failed? Required for passed, failed or skipped." rows={2} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2" />
            </label>
            {fixWork.status === "blocked" && <label className="block text-sm text-zinc-300">What is blocking the fix?
              <textarea required maxLength={2000} value={fixWork.blocked_reason} disabled={busy} onChange={(e) => setFixWork({ ...fixWork, blocked_reason: e.target.value })} rows={2} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2" />
            </label>}
            <label className="block text-sm text-zinc-300">Verification
              <textarea maxLength={2000} value={fixWork.verification} disabled={busy} onChange={(e) => setFixWork({ ...fixWork, verification: e.target.value })} placeholder="Observed result after the fix, or why this is a false positive" rows={2} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2" />
            </label>
            <button disabled={busy} className="rounded bg-purple-600 px-3 py-2 text-sm font-medium text-white hover:bg-purple-500 disabled:opacity-50">Save assignments and progress</button>
          </form>
        ) : (
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <div><dt className="text-zinc-500">Fix status</dt><dd className="text-zinc-200">{FIX_STATUS_LABEL[inc.fix_status]}</dd></div>
            <div><dt className="text-zinc-500">Tests</dt><dd className="text-zinc-200">{TEST_STATUS_LABEL[inc.fix_test_status]}</dd></div>
            {inc.fix_pr_url && <div><dt className="text-zinc-500">Pull request</dt><dd><a className="break-all text-purple-300 underline" href={inc.fix_pr_url} target="_blank" rel="noreferrer">{inc.fix_pr_url}</a></dd></div>}
            {inc.fix_test_url && <div><dt className="text-zinc-500">Test run</dt><dd><a className="break-all text-purple-300 underline" href={inc.fix_test_url} target="_blank" rel="noreferrer">{inc.fix_test_url}</a></dd></div>}
            {inc.fix_test_summary && <div className="sm:col-span-2"><dt className="text-zinc-500">Test evidence</dt><dd className="whitespace-pre-wrap text-zinc-200">{inc.fix_test_summary}</dd></div>}
            {inc.fix_blocked_reason && <div className="sm:col-span-2"><dt className="text-zinc-500">Blocker</dt><dd className="whitespace-pre-wrap text-zinc-200">{inc.fix_blocked_reason}</dd></div>}
            {inc.fix_verification && <div className="sm:col-span-2"><dt className="text-zinc-500">Verification</dt><dd className="whitespace-pre-wrap text-zinc-200">{inc.fix_verification}</dd></div>}
          </dl>
        )}

        <div className="mt-5 border-t border-zinc-800 pt-4">
          <h3 className="mb-2 text-sm font-medium text-white">Progress history</h3>
          {data.fix_events.length ? <ol className="space-y-2">
            {data.fix_events.map((event) => <li key={event.id} className="rounded border border-zinc-800 p-2 text-sm">
              <p className="text-xs text-zinc-500">{event.actor_label} · {when(event.created_at)}</p>
              <p className="break-words text-zinc-300">{eventSummary(event)}</p>
            </li>)}
          </ol> : <p className="text-sm text-zinc-500">No fix progress recorded yet.</p>}
        </div>
        {inc.fix_updated_at && <p className="mt-3 text-xs text-zinc-600">Last progress update {when(inc.fix_updated_at)}</p>}
      </Section>

      {closing && canWrite && inc.status !== "resolved" && (
        <Section title="Record resolution">
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); void patch({ status: "resolved", resolution, fix_work: { ...fixWork, verification: fixWork.verification || resolution.verification } }).then((ok) => { if (ok) setClosing(false); }); }}>
            <p className="text-sm text-zinc-400">Choose Fixed with passing tests and verification, or False positive with a reason. The incident cannot close until the recorded fix state is verified. Resolving records your assessment; it does not run a fix.</p>
            {([ ["reason", "Conclusion and reason for closing"], ["action", "Action taken or reason no action was needed"], ["verification", "Verification and observed outcome"] ] as const).map(([key, label]) => (
              <label key={key} className="block text-sm text-zinc-300">{label}
                <textarea required maxLength={2000} value={resolution[key]} onChange={(e) => setResolution({ ...resolution, [key]: e.target.value })} className="mt-1 block w-full rounded border border-zinc-700 bg-black p-2" />
              </label>
            ))}
            <button disabled={busy} className="rounded bg-green-600 px-3 py-2 text-sm text-white disabled:opacity-50">Save resolution</button>
            <button type="button" disabled={busy} onClick={() => setClosing(false)} className="ml-3 text-sm text-zinc-400">Cancel</button>
          </form>
        </Section>
      )}

      <Section title="Who did what">
        <p className="mb-3 text-sm text-zinc-400">A logging process account is not the remote actor. Missing fields mean the collector did not establish them.</p>
        {!data.forensics?.length && <p className="text-sm text-zinc-400">No linked detection evidence is available. Actor, action and outcome cannot be established from the incident summary alone.</p>}
        {data.forensics?.map((f) => (
          <div key={f.detection_id} className="mb-3 rounded border border-zinc-800 p-3 text-sm">
            <p className="mb-3 text-amber-300">{f.attribution}</p>
            <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {Object.entries({ "Observed at": f.at, "Remote address": f.source_ip, "Address evidence": f.source_ip_basis, "Target account": f.target_account, "Logging account": f.logging_account ?? f.logging_uid, "Process / PID": [f.process, f.pid].filter(Boolean).join(" / ") || null, "Service": f.unit, "SSH key fingerprint": f.key_fingerprint, "Recorded command": f.command, "Journal boot": f.boot_id, "Journal cursor": f.journal_cursor }).map(([label, value]) => (
                <div key={label} className="min-w-0"><dt className="text-zinc-500">{label}</dt><dd className="break-all text-zinc-200">{value || "Not captured"}</dd></div>
              ))}
            </dl>
            {f.message && <pre className="mt-3 whitespace-pre-wrap break-all text-xs text-zinc-300">{f.message}</pre>}
            <p className="mt-2 break-all text-xs text-zinc-500">Evidence: {f.detection_id} · rule {f.rule_id ?? "unknown"}</p>
            <h3 className="mb-1 mt-4 font-medium text-white">Investigation and remediation</h3>
            <ol className="list-decimal space-y-1 pl-5 text-zinc-400">{f.next_steps.map((step) => <li key={step}>{step}</li>)}</ol>
          </div>
        ))}
      </Section>

      <Section title={inc.status === "resolved" ? "Resolution" : "Last recorded resolution"}>
        {inc.resolution ? <div className="space-y-2 text-sm text-zinc-300">
          <p className="text-zinc-500">Recorded by {data.resolution_actor_name ?? (inc.resolution.actor_agent_key_id ? `agent key ${inc.resolution.actor_agent_key_id}` : inc.resolution.actor_user_id ?? "unknown operator")} · {when(inc.resolution.at)}</p>
          <p className="whitespace-pre-wrap"><strong>Conclusion:</strong> {inc.resolution.reason}</p>
          <p className="whitespace-pre-wrap"><strong>Action:</strong> {inc.resolution.action}</p>
          <p className="whitespace-pre-wrap"><strong>Verification:</strong> {inc.resolution.verification}</p>
        </div> : <p className="text-sm text-zinc-400">{inc.status === "resolved" ? "Closed without a recorded remediation or verification. Resolved status alone does not establish that the underlying issue was fixed." : "No resolution has been recorded."}</p>}
      </Section>

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
          <form onSubmit={(e) => { e.preventDefault(); if (note.trim()) void patch({ note }).then((ok) => { if (ok) setNote(""); }); }} className="flex flex-col gap-2 sm:flex-row">
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
