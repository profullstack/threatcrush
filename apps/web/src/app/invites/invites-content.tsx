"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

type Invite = {
  id: string;
  createdAt: number;
  expiresAt: number | null;
  note: string;
  status: "open" | "used" | "expired" | "revoked";
  usedByEmail?: string | null;
  bonus?: "granted" | "pending";
};

type Overview = {
  quota: { total: number; used: number; left: number };
  invites: Invite[];
  canInvite: boolean;
  blockedReason: string | null;
  unlocksAt: string | null;
  bonusCredits: number;
};

const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export default function InvitesContent({ quota, bonus }: { quota: number; bonus: number }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [fresh, setFresh] = useState<{ code: string; url: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    const res = await fetch("/api/credits/invites", { headers: authHeaders(), cache: "no-store" });
    const body = await res.json().catch(() => ({}));
    if (res.ok) setData(body as Overview);
    else setError((body as { error?: string }).error ?? "Could not load invites.");
  }, []);

  useEffect(() => {
    if (signedIn) void load();
  }, [signedIn, load]);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/credits/invites", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ note }),
      });
      const body = (await res.json().catch(() => ({}))) as { code?: string; url?: string; error?: string };
      if (!res.ok || !body.code || !body.url) {
        setError(body.error ?? "Could not create an invite.");
        return;
      }
      setFresh({ code: body.code, url: body.url });
      setNote("");
      setCopied(false);
      await load();
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!confirm("Withdraw this invite? It will not come back to your count.")) return;
    const res = await fetch(`/api/credits/invites/${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
    if (!res.ok) setError(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "Could not withdraw it.");
    await load();
  }

  if (!authLoading && !signedIn) {
    return (
      <main className="pt-24 pb-16 min-h-screen">
        <div className="mx-auto max-w-3xl px-4 sm:px-6 text-center">
          <h1 className="text-3xl font-bold text-white mb-4">Invites</h1>
          <p className="text-tc-text-dim mb-6">Sign in to see your invites.</p>
          <Link href="/auth/login?next=/invites" className="inline-block rounded-lg bg-tc-green px-5 py-2 text-sm font-bold text-black hover:bg-tc-green-dim">
            Sign in
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="pt-24 pb-16 min-h-screen">
      <div className="mx-auto max-w-3xl px-4 sm:px-6 space-y-6">
        <div>
          <p className="font-mono text-sm text-tc-green mb-2 tracking-wider">// INVITES</p>
          <h1 className="text-3xl sm:text-4xl font-bold text-white">
            Your <span className="text-tc-green">invites</span>
          </h1>
          <p className="text-tc-text-dim mt-2">
            Every account gets {quota}. Each one works once. When someone new joins on yours and confirms their
            email, you both get {bonus} credits (${bonus.toFixed(2)}).
          </p>
        </div>

        <div className="rounded-xl border border-tc-green/30 bg-tc-card p-6">
          <p className="text-sm text-tc-text-dim font-mono mb-1">Invites left</p>
          <p className="text-4xl font-black text-tc-green font-mono">
            {data ? `${data.quota.left} / ${data.quota.total}` : "—"}
          </p>
          {data && !data.canInvite && (
            <p className="text-sm text-yellow-400 mt-3">
              {data.unlocksAt
                ? `Invites unlock on ${data.unlocksAt.slice(0, 10)}.`
                : data.blockedReason === "email not confirmed"
                  ? "Confirm your email address to send invites."
                  : "This account cannot send invites."}
            </p>
          )}
          {data?.canInvite && data.quota.left > 0 && (
            <div className="mt-4 flex flex-col sm:flex-row gap-3">
              <label htmlFor="invite-note" className="sr-only">Who is it for?</label>
              <input
                id="invite-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Who is it for? (only you see this)"
                maxLength={200}
                className="flex-1 min-w-0 rounded-lg border border-tc-border bg-tc-darker px-4 py-2 text-sm text-white placeholder:text-tc-text-dim focus:border-tc-green focus:outline-none"
              />
              <button
                type="button"
                onClick={create}
                disabled={busy}
                className="rounded-lg bg-tc-green px-5 py-2 text-sm font-bold text-black hover:bg-tc-green-dim disabled:opacity-50"
              >
                {busy ? "Creating..." : "Create invite"}
              </button>
            </div>
          )}
          {fresh && (
            <div className="mt-4 rounded-lg border border-tc-border bg-tc-darker p-4">
              <p className="text-sm text-white mb-2">Send this link. It is shown once.</p>
              <div className="flex flex-col sm:flex-row gap-2">
                <code className="flex-1 min-w-0 break-all font-mono text-sm text-tc-green">{fresh.url}</code>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard?.writeText(fresh.url);
                    setCopied(true);
                  }}
                  className="rounded-lg border border-tc-green/40 px-3 py-1 text-sm text-tc-green hover:bg-tc-green/10"
                >
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
          )}
          {error && <p role="alert" className="mt-3 text-sm text-red-400">{error}</p>}
        </div>

        {data && data.invites.length > 0 && (
          <div className="rounded-xl border border-tc-border bg-tc-card p-6">
            <h2 className="text-lg font-semibold text-white mb-3">Sent</h2>
            <ul className="divide-y divide-tc-border">
              {data.invites.map((i) => (
                <li key={i.id} className="py-3 flex flex-wrap items-center justify-between gap-2 text-sm">
                  <div className="min-w-0">
                    <p className="text-white truncate">{i.note || "Invite"}</p>
                    <p className="text-tc-text-dim">
                      {day(i.createdAt)}
                      {i.status === "used" && i.usedByEmail ? ` · joined: ${i.usedByEmail}` : ""}
                      {i.status === "open" && i.expiresAt ? ` · expires ${day(i.expiresAt)}` : ""}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs uppercase text-tc-text-dim">
                      {i.status === "used" ? (i.bonus === "granted" ? "joined · credits paid" : "joined · credits pending") : i.status}
                    </span>
                    {i.status === "open" && (
                      <button type="button" onClick={() => revoke(i.id)} className="text-xs text-red-400 hover:underline">
                        Withdraw
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}

        <p className="text-sm text-tc-text-dim">
          Looking for the paid referral program? That is separate:{" "}
          <Link href="/affiliates" className="text-tc-green hover:underline">Affiliates</Link>. Have a credit code?{" "}
          <Link href="/dashboard/billing" className="text-tc-green hover:underline">Redeem it</Link>.
        </p>
      </div>
    </main>
  );
}
