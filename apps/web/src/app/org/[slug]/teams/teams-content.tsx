"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations } from "@/lib/organizations";
import { ROLE_HELP, ROLE_LABEL, teamsApi, type TeamRole, type TeamSummary } from "@/lib/teams-client";

interface Organization { id: string; name: string; slug: string; user_role: string }

export default function TeamsContent({ slug }: { slug: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [teams, setTeams] = useState<TeamSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!authLoading && !signedIn) window.location.href = `/auth/login?next=${encodeURIComponent(`/org/${slug}/teams`)}`;
  }, [authLoading, signedIn, slug]);

  const load = useCallback(async (orgId: string) => {
    const { teams: list } = await teamsApi.list(orgId);
    setTeams(list);
  }, []);

  useEffect(() => {
    if (!signedIn) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find((o) => o.slug === slug) ?? null;
        setOrg(found);
        if (found) await load(found.id);
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setLoading(false);
      }
    })();
  }, [signedIn, slug, load]);

  const canCreate = org?.user_role === "owner" || org?.user_role === "admin";

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!org || !name.trim()) return;
    setBusy(true);
    setError("");
    try {
      await teamsApi.create(org.id, name.trim());
      setName("");
      await load(org.id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (authLoading || loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  }
  if (!org) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Organization not found</div></div>;
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex items-center gap-3 mb-2">
          <Link href={`/org/${slug}`} className="text-zinc-500 hover:text-zinc-300" aria-label="Back to organization">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Teams</h1>
            <p className="text-sm text-zinc-500">{org.name}</p>
          </div>
        </div>
        <p className="text-sm text-zinc-400 mb-6 max-w-3xl">
          A team owns fleets (groups of servers) and gives its people and agent keys one of three roles on them.
          Organization owners and admins can do everything in every team. Servers in no fleet stay visible to every
          organization member, as before.
        </p>

        <div className="grid gap-3 sm:grid-cols-3 mb-8">
          {(Object.keys(ROLE_LABEL) as TeamRole[]).map((r) => (
            <div key={r} className="rounded-lg bg-zinc-900 border border-zinc-800 p-3">
              <p className="text-sm font-medium text-white">{ROLE_LABEL[r]}</p>
              <p className="text-xs text-zinc-500 mt-1">{ROLE_HELP[r]}</p>
            </div>
          ))}
        </div>

        {error && (
          <div className="mb-4 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {canCreate && (
          <form onSubmit={create} className="flex gap-2 mb-6">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="New team name, e.g. Ops"
              maxLength={100}
              aria-label="New team name"
              className="flex-1 rounded-lg bg-zinc-900 border border-zinc-700 px-3 py-2 text-sm text-white focus:border-green-500 focus:outline-none"
            />
            <button
              type="submit"
              disabled={busy || !name.trim()}
              className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-50"
            >
              Create team
            </button>
          </form>
        )}

        {teams.length === 0 ? (
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-8 text-center text-sm text-zinc-400">
            {canCreate ? "No teams yet. Create one to start grouping servers into fleets." : "You are not on any team in this organization yet."}
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {teams.map((t) => (
              <Link
                key={t.id}
                href={`/org/${slug}/teams/${t.id}`}
                className="block rounded-lg bg-zinc-900 border border-zinc-800 p-5 hover:border-zinc-700 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <h3 className="text-base font-medium text-white">{t.name}</h3>
                  <span className="rounded-full px-2 py-0.5 text-xs font-medium bg-zinc-800 text-zinc-300">{ROLE_LABEL[t.my_role]}</span>
                </div>
                <p className="text-sm text-zinc-500 mt-2">
                  {t.member_count} member{t.member_count === 1 ? "" : "s"} · {t.fleet_count} fleet{t.fleet_count === 1 ? "" : "s"}
                </p>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
