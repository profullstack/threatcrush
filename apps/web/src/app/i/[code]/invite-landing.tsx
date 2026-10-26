"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

const COOKIE = "tc_invite";

/** Keeps the code in a cookie through signup, or accepts it for a signed-in (new) account. */
export default function InviteLanding({ code }: { code: string }) {
  const { signedIn, loading } = useAuth();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!code) return;
    const secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${COOKIE}=${encodeURIComponent(code)}; Max-Age=${60 * 60 * 24 * 30}; path=/; SameSite=Lax${secure}`;
  }, [code]);

  async function accept() {
    setBusy(true);
    try {
      const res = await fetch("/api/credits/invites/accept", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ code }),
      });
      const body = (await res.json().catch(() => ({}))) as { message?: string; error?: string };
      setMsg({ ok: res.ok, text: body.message ?? body.error ?? "Done." });
    } catch {
      setMsg({ ok: false, text: "Network error. Try again." });
    } finally {
      setBusy(false);
    }
  }

  if (!code) return <p className="text-sm text-red-400">That invite link is incomplete.</p>;
  if (loading) return <p className="text-sm text-tc-text-dim">Loading…</p>;

  if (signedIn) {
    return (
      <div className="space-y-3">
        <button
          type="button"
          onClick={accept}
          disabled={busy || msg?.ok}
          className="w-full rounded-lg bg-tc-green px-5 py-2 text-sm font-bold text-black hover:bg-tc-green-dim disabled:opacity-50"
        >
          {busy ? "Accepting..." : "Accept invite"}
        </button>
        {msg && (
          <p role="status" className={`text-sm ${msg.ok ? "text-tc-green" : "text-red-400"}`}>
            {msg.text}
          </p>
        )}
        <Link href="/invites" className="block text-sm text-tc-green hover:underline">
          Go to your invites
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <Link
        href={`/auth/signup?invite=${encodeURIComponent(code)}`}
        className="block w-full rounded-lg bg-tc-green px-5 py-2 text-sm font-bold text-black hover:bg-tc-green-dim"
      >
        Create your account
      </Link>
      <p className="text-sm text-tc-text-dim">
        Already have an account?{" "}
        <Link href={`/auth/login?next=${encodeURIComponent(`/i/${code}`)}`} className="text-tc-green hover:underline">
          Sign in
        </Link>{" "}
        to accept it.
      </p>
    </div>
  );
}
