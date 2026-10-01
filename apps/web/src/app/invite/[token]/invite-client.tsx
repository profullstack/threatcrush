"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { authHeaders } from "@/lib/auth-client";
import { useAuth } from "@/lib/auth-context";
import { ROLE_HELP, ROLE_LABEL, type TeamRole } from "@/lib/teams-client";

interface Invite {
  org_name: string | null;
  team_name: string | null;
  email: string;
  role: TeamRole;
  expires_at: string;
  status: "pending" | "accepted" | "revoked" | "expired";
}

export default function InviteClient({ token }: { token: string }) {
  const { signedIn, loading: authLoading, profile } = useAuth();
  const [invite, setInvite] = useState<Invite | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch(`/api/invites/${encodeURIComponent(token)}`, { cache: "no-store" })
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as { invite?: Invite; error?: string };
        if (!res.ok || !data.invite) throw new Error(data.error || "This invite link is not valid");
        setInvite(data.invite);
      })
      .catch((err: Error) => setError(err.message));
  }, [token]);

  const accept = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await fetch(`/api/invites/${encodeURIComponent(token)}`, { method: "POST", headers: authHeaders() });
      const data = (await res.json().catch(() => ({}))) as { org_slug?: string; team_id?: string; error?: string };
      if (!res.ok) throw new Error(data.error || "Could not accept the invite");
      window.location.href = data.org_slug && data.team_id ? `/org/${data.org_slug}/teams/${data.team_id}` : "/dashboard";
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  const here = `/invite/${token}`;

  return (
    <div className="min-h-screen bg-tc-darker flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="text-2xl font-bold text-tc-green glow-green font-mono">⚡ ThreatCrush</Link>
          <h1 className="text-2xl font-bold text-white mt-4">Team invite</h1>
        </div>

        <div className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
          {error && (
            <div role="alert" className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">{error}</div>
          )}

          {invite && (
            <>
              <p className="text-tc-text">
                You are invited to <span className="text-white font-semibold">{invite.team_name ?? "a team"}</span> in{" "}
                <span className="text-white font-semibold">{invite.org_name ?? "an organization"}</span> with{" "}
                <span className="text-tc-green font-semibold">{ROLE_LABEL[invite.role]}</span> access.
              </p>
              <p className="text-sm text-tc-text-dim">{ROLE_HELP[invite.role]}.</p>
              <p className="text-xs text-tc-text-dim">Sent to {invite.email}.</p>

              {invite.status !== "pending" ? (
                <p className="text-sm text-yellow-400">
                  This invite has {invite.status === "accepted" ? "already been used" : invite.status === "revoked" ? "been revoked" : "expired"}.
                  Ask the team admin for a new one.
                </p>
              ) : authLoading ? null : signedIn ? (
                <>
                  {profile?.email && profile.email.toLowerCase() !== invite.email.toLowerCase() && (
                    <p className="text-xs text-yellow-400">You are signed in as {profile.email}. Accepting adds this account.</p>
                  )}
                  <button
                    type="button"
                    onClick={accept}
                    disabled={busy}
                    className="w-full bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50"
                  >
                    {busy ? "Joining..." : "Accept and join"}
                  </button>
                </>
              ) : (
                <div className="flex gap-3">
                  <Link href={`/auth/login?next=${encodeURIComponent(here)}`} className="flex-1 text-center bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim">Log in to accept</Link>
                  <Link href={`/auth/signup?next=${encodeURIComponent(here)}`} className="flex-1 text-center border border-tc-border text-tc-text font-bold py-3 rounded-lg hover:border-tc-green">Sign up</Link>
                </div>
              )}
            </>
          )}

          {!invite && !error && <p className="text-sm text-tc-text-dim">Loading invite…</p>}
        </div>
      </div>
    </div>
  );
}
