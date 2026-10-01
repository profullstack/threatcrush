"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, listServers } from "@/lib/organizations";
import { ROLE_HELP, ROLE_LABEL, teamsApi, type TeamDetail, type TeamRole } from "@/lib/teams-client";

interface Organization { id: string; name: string; slug: string; user_role: string }
interface ServerRow { id: string; name: string; hostname: string | null; fleet_id: string | null; my_role: TeamRole | null }

const ROLES = Object.keys(ROLE_LABEL) as TeamRole[];
const input = "rounded-lg bg-zinc-900 border border-zinc-700 px-3 py-2 text-sm text-white focus:border-green-500 focus:outline-none";
const primary = "rounded-lg px-3 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-50";
const ghost = "rounded px-2 py-1 text-xs border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50";

function RoleSelect({ value, onChange, disabled, label }: { value: TeamRole; onChange: (r: TeamRole) => void; disabled?: boolean; label: string }) {
  return (
    <select
      value={value}
      disabled={disabled}
      aria-label={label}
      onChange={(e) => onChange(e.target.value as TeamRole)}
      className="rounded-md bg-zinc-800 border border-zinc-700 px-2 py-1 text-xs text-white focus:border-green-500 focus:outline-none"
    >
      {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
    </select>
  );
}

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg bg-zinc-900 border border-zinc-800 p-5 mb-6">
      <h2 className="text-lg font-semibold text-white">{title}</h2>
      {hint && <p className="text-sm text-zinc-500 mt-1 mb-4">{hint}</p>}
      {children}
    </section>
  );
}

export default function TeamContent({ slug, teamId }: { slug: string; teamId: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [detail, setDetail] = useState<TeamDetail | null>(null);
  const [servers, setServers] = useState<ServerRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // Forms
  const [fleetName, setFleetName] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState<TeamRole>("read");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<TeamRole>("read");
  const [inviteLink, setInviteLink] = useState<{ url: string; emailed: boolean } | null>(null);
  const [agentName, setAgentName] = useState("");
  const [agentRole, setAgentRole] = useState<TeamRole>("read");
  const [newKey, setNewKey] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !signedIn) window.location.href = `/auth/login?next=${encodeURIComponent(`/org/${slug}/teams/${teamId}`)}`;
  }, [authLoading, signedIn, slug, teamId]);

  const reload = useCallback(async (orgId: string) => {
    const [d, s] = await Promise.all([teamsApi.get(orgId, teamId), listServers(orgId)]);
    setDetail(d);
    setServers(s.servers as unknown as ServerRow[]);
  }, [teamId]);

  useEffect(() => {
    if (!signedIn) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find((o) => o.slug === slug) ?? null;
        setOrg(found);
        if (found) await reload(found.id);
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setLoading(false);
      }
    })();
  }, [signedIn, slug, reload]);

  /** Run a change, show any error, then refresh the page's data. */
  const act = async (fn: () => Promise<unknown>, done?: string) => {
    if (!org) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
      if (done) setNotice(done);
      await reload(org.id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (authLoading || loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  }
  if (!org || !detail) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">{error || "Team not found"}</div>
      </div>
    );
  }

  const isAdmin = detail.team.my_role === "admin";
  const orgAdmin = org.user_role === "owner" || org.user_role === "admin";
  const teamFleetIds = new Set(detail.fleets.map((f) => f.id));
  // What this page can move: servers in this team's fleets, and (for org admins) loose servers.
  const movable = servers.filter((s) => (s.fleet_id && teamFleetIds.has(s.fleet_id)) || (!s.fleet_id && orgAdmin));

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
          <div className="flex items-center gap-3">
            <Link href={`/org/${slug}/teams`} className="text-zinc-500 hover:text-zinc-300" aria-label="Back to teams">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">{detail.team.name}</h1>
              <p className="text-sm text-zinc-500">{org.name} · your role: {ROLE_LABEL[detail.team.my_role]}</p>
            </div>
          </div>
          <div className="flex gap-2">
            {isAdmin && (
              <button
                type="button"
                className={`${ghost} text-zinc-300`}
                disabled={busy}
                onClick={() => {
                  const name = window.prompt("Rename team", detail.team.name);
                  if (name && name.trim()) void act(() => teamsApi.rename(org.id, teamId, name.trim()), "Team renamed.");
                }}
              >
                Rename
              </button>
            )}
            {orgAdmin && (
              <button
                type="button"
                className={`${ghost} text-red-400`}
                disabled={busy}
                onClick={async () => {
                  if (!window.confirm(`Delete ${detail.team.name}? Its fleets are deleted; their servers stay, in no fleet.`)) return;
                  setBusy(true);
                  try {
                    await teamsApi.remove(org.id, teamId);
                    window.location.href = `/org/${slug}/teams`;
                  } catch (err) {
                    setError((err as Error).message);
                    setBusy(false);
                  }
                }}
              >
                Delete team
              </button>
            )}
          </div>
        </div>

        {error && <div role="alert" className="mb-4 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-400">{error}</div>}
        {notice && <div role="status" className="mb-4 rounded-lg bg-green-500/10 border border-green-500/20 px-4 py-3 text-sm text-green-400">{notice}</div>}

        {/* Fleets */}
        <Section title="Fleets" hint="Named groups of servers this team owns. Team roles apply to every server in them.">
          {isAdmin && (
            <form
              className="flex gap-2 mb-4"
              onSubmit={(e) => {
                e.preventDefault();
                if (fleetName.trim()) void act(() => teamsApi.createFleet(org.id, teamId, fleetName.trim()).then(() => setFleetName("")), "Fleet created.");
              }}
            >
              <input className={`${input} flex-1`} value={fleetName} onChange={(e) => setFleetName(e.target.value)} placeholder="New fleet, e.g. production" maxLength={100} aria-label="New fleet name" />
              <button type="submit" className={primary} disabled={busy || !fleetName.trim()}>Create fleet</button>
            </form>
          )}
          {detail.fleets.length === 0 ? (
            <p className="text-sm text-zinc-500">No fleets yet.</p>
          ) : (
            <ul className="divide-y divide-zinc-800">
              {detail.fleets.map((f) => (
                <li key={f.id} className="flex items-center justify-between py-2">
                  <span className="text-sm text-white">{f.name} <span className="text-zinc-500">· {f.server_count} server{f.server_count === 1 ? "" : "s"}</span></span>
                  {isAdmin && (
                    <span className="flex gap-2">
                      <button type="button" className={`${ghost} text-zinc-300`} disabled={busy}
                        onClick={() => {
                          const name = window.prompt("Rename fleet", f.name);
                          if (name && name.trim()) void act(() => teamsApi.renameFleet(org.id, f.id, name.trim()), "Fleet renamed.");
                        }}>Rename</button>
                      <button type="button" className={`${ghost} text-red-400`} disabled={busy}
                        onClick={() => {
                          if (window.confirm(`Delete fleet ${f.name}? Its servers stay, in no fleet.`)) void act(() => teamsApi.removeFleet(org.id, f.id), "Fleet deleted.");
                        }}>Delete</button>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}

          {isAdmin && detail.fleets.length > 0 && movable.length > 0 && (
            <div className="mt-5">
              <h3 className="text-sm font-medium text-white mb-2">Servers</h3>
              <ul className="divide-y divide-zinc-800">
                {movable.map((s) => (
                  <li key={s.id} className="flex items-center justify-between py-2">
                    <span className="text-sm text-zinc-300">{s.name} <span className="text-zinc-600">{s.hostname && s.hostname !== s.name ? s.hostname : ""}</span></span>
                    <select
                      value={s.fleet_id ?? ""}
                      disabled={busy}
                      aria-label={`Fleet for ${s.name}`}
                      onChange={(e) => void act(() => teamsApi.moveServer(org.id, s.id, e.target.value || null), "Server moved.")}
                      className="rounded-md bg-zinc-800 border border-zinc-700 px-2 py-1 text-xs text-white focus:border-green-500 focus:outline-none"
                    >
                      <option value="" disabled={!orgAdmin}>No fleet</option>
                      {detail.fleets.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
                    </select>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Section>

        {/* Members */}
        <Section title="Members" hint="People on this team. Organization owners and admins are admins of every team without being listed.">
          {detail.members.length === 0 ? (
            <p className="text-sm text-zinc-500 mb-4">No members yet.</p>
          ) : (
            <ul className="divide-y divide-zinc-800 mb-4">
              {detail.members.map((m) => (
                <li key={m.user_id} className="flex items-center justify-between py-2">
                  <span className="text-sm text-white">{m.display_name || m.email || m.user_id}{m.display_name && m.email ? <span className="text-zinc-500"> · {m.email}</span> : null}</span>
                  {isAdmin ? (
                    <span className="flex items-center gap-2">
                      <RoleSelect value={m.role} disabled={busy} label={`Role for ${m.email ?? m.user_id}`}
                        onChange={(r) => void act(() => teamsApi.setMemberRole(org.id, teamId, m.user_id, r), "Role changed.")} />
                      <button type="button" className={`${ghost} text-red-400`} disabled={busy}
                        onClick={() => void act(() => teamsApi.removeMember(org.id, teamId, m.user_id), "Removed from the team.")}>Remove</button>
                    </span>
                  ) : (
                    <span className="text-xs text-zinc-400">{ROLE_LABEL[m.role]}</span>
                  )}
                </li>
              ))}
            </ul>
          )}
          {isAdmin && (
            <form className="flex flex-wrap gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  const res = await teamsApi.addMember(org.id, teamId, memberEmail.trim(), memberRole);
                  setMemberEmail("");
                  // New email with no account: an invite was created, show its link.
                  if (res.invited && res.url) setInviteLink({ url: res.url, emailed: Boolean(res.emailed) });
                }, "Member added or invited.");
              }}>
              <input className={`${input} flex-1 min-w-[12rem]`} type="email" value={memberEmail} onChange={(e) => setMemberEmail(e.target.value)} placeholder="Email — they're invited if they have no account yet" aria-label="Member email" />
              <RoleSelect value={memberRole} onChange={setMemberRole} label="Role for new member" />
              <button type="submit" className={primary} disabled={busy || !memberEmail.trim()}>Add</button>
            </form>
          )}
        </Section>

        {isAdmin && (
          <Section title="Invites" hint="Invite anyone by email. They join the organization as a guest and this team with the role you pick. Links work once and expire in 14 days.">
            <form className="flex flex-wrap gap-2 mb-4"
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  const res = await teamsApi.invite(org.id, teamId, inviteEmail.trim(), inviteRole);
                  setInviteLink(res);
                  setInviteEmail("");
                });
              }}>
              <input className={`${input} flex-1 min-w-[12rem]`} type="email" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="name@example.com" aria-label="Invite email" />
              <RoleSelect value={inviteRole} onChange={setInviteRole} label="Role for invite" />
              <button type="submit" className={primary} disabled={busy || !inviteEmail.trim()}>Send invite</button>
            </form>
            {inviteLink && (
              <div className="mb-4 rounded-lg bg-zinc-950 border border-zinc-800 p-3 text-sm">
                <p className="text-zinc-300">{inviteLink.emailed ? "Invite emailed. You can also share this link:" : "Email could not be sent. Share this link yourself:"}</p>
                <div className="mt-2 flex gap-2">
                  <input readOnly value={inviteLink.url} onFocus={(e) => e.currentTarget.select()} aria-label="Invite link" className="flex-1 min-w-0 rounded bg-zinc-900 border border-zinc-700 px-2 py-1 text-xs text-zinc-200 font-mono" />
                  <button type="button" className={`${ghost} text-zinc-200`} onClick={() => void navigator.clipboard.writeText(inviteLink.url)}>Copy</button>
                </div>
              </div>
            )}
            {(detail.invites ?? []).length > 0 && (
              <ul className="divide-y divide-zinc-800">
                {(detail.invites ?? []).map((i) => (
                  <li key={i.id} className="flex items-center justify-between py-2 text-sm">
                    <span className="text-zinc-300">{i.email} <span className="text-zinc-500">· {ROLE_LABEL[i.role]} · expires {new Date(i.expires_at).toLocaleDateString()}</span></span>
                    <button type="button" className={`${ghost} text-red-400`} disabled={busy}
                      onClick={() => void act(() => teamsApi.revokeInvite(org.id, teamId, i.id), "Invite revoked.")}>Revoke</button>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        )}

        {isAdmin && (
          <Section title="Agent keys" hint="For AI agents, scripts and CI. A key acts on this team's fleets with its role and nothing else. A read-only key is the safe way to let an AI read your findings.">
            <form className="flex flex-wrap gap-2 mb-4"
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  const res = await teamsApi.createAgentKey(org.id, teamId, agentName.trim(), agentRole);
                  setNewKey(res.key);
                  setAgentName("");
                });
              }}>
              <input className={`${input} flex-1 min-w-[12rem]`} value={agentName} onChange={(e) => setAgentName(e.target.value)} placeholder="Name, e.g. claude-ops or github-actions" maxLength={100} aria-label="Agent key name" />
              <RoleSelect value={agentRole} onChange={setAgentRole} label="Role for agent key" />
              <button type="submit" className={primary} disabled={busy || !agentName.trim()}>Create key</button>
            </form>
            {newKey && (
              <div className="mb-4 rounded-lg bg-zinc-950 border border-yellow-500/30 p-3 text-sm">
                <p className="text-yellow-400">Copy this key now. It will not be shown again.</p>
                <div className="mt-2 flex gap-2">
                  <input readOnly value={newKey} onFocus={(e) => e.currentTarget.select()} aria-label="New agent key" className="flex-1 min-w-0 rounded bg-zinc-900 border border-zinc-700 px-2 py-1 text-xs text-zinc-200 font-mono" />
                  <button type="button" className={`${ghost} text-zinc-200`} onClick={() => void navigator.clipboard.writeText(newKey)}>Copy</button>
                </div>
                <p className="mt-3 text-xs text-zinc-500">Use it as a bearer token against the same API the dashboard uses, for example:</p>
                <pre className="mt-1 overflow-x-auto rounded bg-zinc-900 p-2 text-xs text-zinc-300">{`curl -H "Authorization: Bearer ${newKey.slice(0, 15)}…" \\\n  https://threatcrush.com/api/orgs/${org.id}/report`}</pre>
              </div>
            )}
            {(detail.agent_keys ?? []).length === 0 ? (
              <p className="text-sm text-zinc-500">No agent keys.</p>
            ) : (
              <ul className="divide-y divide-zinc-800">
                {(detail.agent_keys ?? []).map((k) => (
                  <li key={k.id} className="flex items-center justify-between py-2 text-sm">
                    <span className="text-zinc-300">
                      {k.name} <span className="text-zinc-500 font-mono">· {k.key_prefix}…</span>
                      <span className="text-zinc-500"> · {ROLE_LABEL[k.role]} · {k.last_used_at ? `used ${new Date(k.last_used_at).toLocaleString()}` : "never used"}</span>
                    </span>
                    <button type="button" className={`${ghost} text-red-400`} disabled={busy}
                      onClick={() => { if (window.confirm(`Revoke ${k.name}? Anything using it stops working.`)) void act(() => teamsApi.revokeAgentKey(org.id, teamId, k.id), "Key revoked."); }}>Revoke</button>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        )}

        <p className="text-xs text-zinc-600">{ROLES.map((r) => `${ROLE_LABEL[r]}: ${ROLE_HELP[r]}.`).join(" ")}</p>
      </div>
    </div>
  );
}
