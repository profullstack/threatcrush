"use client";

import { useState } from "react";
import { authHeaders } from "@/lib/auth-client";

/** "Have a code?": redeems a credit code into the account's credit balance. */
export default function RedeemCodeCard({ onRedeemed }: { onRedeemed?: (balanceUsd: number | null) => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!code.trim()) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/credits/redeem", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ code }),
      });
      const body = (await res.json().catch(() => ({}))) as { message?: string; error?: string; balance_usd?: number };
      setMsg({ ok: res.ok, text: body.message ?? body.error ?? (res.ok ? "Done." : "Could not redeem the code.") });
      if (res.ok) {
        setCode("");
        onRedeemed?.(typeof body.balance_usd === "number" ? body.balance_usd : null);
      }
    } catch {
      setMsg({ ok: false, text: "Network error. Try again." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-xl border border-tc-border bg-tc-card p-6">
      <h2 className="text-lg font-semibold text-white mb-1">Have a code?</h2>
      <p className="text-sm text-tc-text-dim mb-4">
        Redeem a ThreatCrush credit code. Each credit adds $1.00 to your credit balance.
      </p>
      <form onSubmit={submit} className="flex flex-col sm:flex-row gap-3">
        <label htmlFor="credit-code" className="sr-only">Credit code</label>
        <input
          id="credit-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="CR-XXXX-XXXX-XXXX-XXXX"
          autoComplete="off"
          spellCheck={false}
          maxLength={64}
          className="flex-1 min-w-0 rounded-lg border border-tc-border bg-tc-darker px-4 py-2 font-mono text-sm text-white placeholder:text-tc-text-dim focus:border-tc-green focus:outline-none"
        />
        <button
          type="submit"
          disabled={busy || !code.trim()}
          className="rounded-lg bg-tc-green px-5 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim disabled:opacity-50"
        >
          {busy ? "Redeeming..." : "Redeem"}
        </button>
      </form>
      {msg && (
        <p role="status" className={`mt-3 text-sm ${msg.ok ? "text-tc-green" : "text-red-400"}`}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
