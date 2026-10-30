"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

type Repository = { id: string; org_id: string; team_id: string | null; full_name: string; silence_warnings: boolean; silence_examples: boolean; last_report_at: string | null; last_counts: { critical: number; warnings: number; silenced: number } | null };
type Org = { id: string; name: string; slug: string };
type Team = { id: string; name: string; org_id: string };
const input = "w-full rounded border border-tc-border bg-tc-darker p-2 text-white";
const button = "rounded border border-tc-green/40 px-3 py-2 text-sm text-tc-green disabled:opacity-40";

export default function RepositoryAlertsCard() {
  const { signedIn } = useAuth();
  const [repos, setRepos] = useState<Repository[]>([]), [orgs, setOrgs] = useState<Org[]>([]), [teams, setTeams] = useState<Team[]>([]);
  const [orgId, setOrgId] = useState(""), [name, setName] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [notice, setNotice] = useState<string | null>(null);
  const [connection, setConnection] = useState<{ name: string; token: string } | null>(null);
  useEffect(() => {
    if (!signedIn) return;
    fetch("/api/github/repositories", { headers: authHeaders(), cache: "no-store" }).then(async (r) => {
      const d = await r.json(); if (!r.ok) throw new Error(d.error || "Could not load repository settings");
      setRepos(d.repositories); setOrgs(d.organizations); setTeams(d.teams); setOrgId(d.organizations[0]?.id ?? "");
    }).catch((e) => setError(e.message));
  }, [signedIn]);

  async function save(body: Record<string, unknown>, create = false) {
    if (busy) return;
    setBusy(true); setError(null); setNotice(null);
    try {
      const r = await fetch("/api/github/repositories", { method: create ? "POST" : "PATCH", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(body) });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || "Could not save repository settings");
      setRepos((list) => create ? [...list, d.repository] : list.map((repo) => repo.id === d.repository.id ? d.repository : repo));
      if (d.token) setConnection({ name: d.repository.full_name, token: d.token });
      if (create) setName("");
      setNotice(`${d.repository.full_name}: settings saved. Critical findings remain visible and page the assigned team.`);
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  if (!signedIn) return null;
  return <section id="repository-alerts" className="mx-auto max-w-3xl px-6 pb-12 scroll-mt-24">
    <div className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
      <h2 className="text-xl font-semibold text-white">Repository warnings &amp; critical pages</h2>
      <p className="text-sm text-tc-text-dim">Manage each repository&apos;s scan warnings here. Tests, documentation and example environment files are labelled as warnings. Critical findings stay visible even when warnings are silenced, and raise a deduplicated incident that pages the assigned team through its existing notification settings.</p>
      <p className="text-sm text-tc-text-dim">Organization owners and admins can connect repositories. Add the connection token as the repository&apos;s <code>THREATCRUSH_REPO_TOKEN</code> GitHub Actions secret. The scan workflow must submit its report to ThreatCrush; settings apply on its next run. Fork PRs scan locally without your connection secret.</p>
      {error && <p role="alert" className="text-red-400">{error}</p>}
      {notice && <p role="status" className="text-tc-green">{notice}</p>}
      {connection && <div className="border border-tc-green/30 p-3 space-y-2">
        <label className="block text-sm text-white" htmlFor="repository-connection-token">New connection token for {connection.name} — shown once</label>
        <input id="repository-connection-token" type="password" readOnly value={connection.token} className={input} onFocus={(e) => e.target.select()} />
        <button className={button} onClick={async () => { try { await navigator.clipboard.writeText(connection.token); setNotice("Connection token copied."); } catch { setError("Could not copy; select and copy the token field."); } }}>Copy token</button>{" "}
        <button className={button} onClick={() => setConnection(null)}>Hide token</button>
      </div>}
      {repos.map((repo) => {
        const org = orgs.find((o) => o.id === repo.org_id);
        return <div key={repo.id} className="border-t border-tc-border pt-4 space-y-3">
          <h3 className="text-white font-mono break-all">{repo.full_name}</h3>
          <p className="text-xs text-tc-text-dim">{org?.name} · {repo.last_report_at ? `Last connected report: ${new Date(repo.last_report_at).toLocaleString()}` : "Awaiting first connected workflow report"}</p>
          {repo.last_counts && <p className="text-sm text-tc-text-dim">{repo.last_counts.critical} critical · {repo.last_counts.warnings} warnings · {repo.last_counts.silenced} silenced</p>}
          <label className="flex gap-3 text-sm text-white"><input type="checkbox" checked={repo.silence_examples} disabled={busy} onChange={(e) => save({ id: repo.id, org_id: repo.org_id, silence_examples: e.target.checked })} />Silence test, documentation and example warnings</label>
          <label className="flex gap-3 text-sm text-white"><input type="checkbox" checked={repo.silence_warnings} disabled={busy} onChange={(e) => save({ id: repo.id, org_id: repo.org_id, silence_warnings: e.target.checked })} />Silence all noncritical warnings for this repository</label>
          <label className="block text-sm text-white">Critical paging team
            <select aria-label={`Critical paging team for ${repo.full_name}`} className={`${input} mt-1`} value={repo.team_id ?? ""} disabled={busy} onChange={(e) => save({ id: repo.id, org_id: repo.org_id, team_id: e.target.value || null })}>
              <option value="">Organization owners and admins</option>
              {teams.filter((t) => t.org_id === repo.org_id).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </label>
          <div className="flex flex-wrap gap-3 items-center">
            <button className={button} disabled={busy} onClick={() => save({ id: repo.id, org_id: repo.org_id, rotate_token: true })}>Replace connection token</button>
            {org && <Link className="text-sm text-tc-green underline" href={`/org/${org.slug}/incidents`}>View critical incidents</Link>}
          </div>
        </div>;
      })}
      {orgs.length > 0 ? <form className="border-t border-tc-border pt-4 space-y-3" onSubmit={(e) => { e.preventDefault(); save({ org_id: orgId, full_name: name.trim() }, true); }}>
        <h3 className="font-semibold text-white">Connect a repository</h3>
        <label className="block text-sm text-white">Organization<select className={input} value={orgId} disabled={busy} onChange={(e) => setOrgId(e.target.value)}>{orgs.map((o) => <option value={o.id} key={o.id}>{o.name}</option>)}</select></label>
        <label className="block text-sm text-white">GitHub owner/repository<input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="your-org/your-repository" required disabled={busy} /></label>
        <button className={button} disabled={busy || !name.trim()}>{busy ? "Saving…" : "Connect repository"}</button>
      </form> : <p className="text-sm text-tc-text-dim">Your account needs an organization owner or admin role to manage repository alerts.</p>}
    </div>
  </section>;
}
