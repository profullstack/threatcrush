"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

type Code = {
  id: string;
  label: string;
  grant: { unit: string; amount: number };
  maxRedemptions: number;
  redemptions: number;
  expiresAt: number | null;
  createdAt: number;
  revokedAt: number | null;
};

const day = (ms: number | null) => (ms ? new Date(ms).toISOString().slice(0, 10) : "—");

/** Mint, list and revoke credit codes (1 credit = $1.00 of credit balance). */
export default function CreditCodesPanel() {
  const [codes, setCodes] = useState<Code[]>([]);
  const [credits, setCredits] = useState("25");
  const [label, setLabel] = useState("");
  const [maxRedemptions, setMaxRedemptions] = useState("1");
  const [expiresInDays, setExpiresInDays] = useState("");
  const [minted, setMinted] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const res = await fetch("/api/admin/credit-codes", { headers: authHeaders(), cache: "no-store" });
    if (res.ok) setCodes(((await res.json()) as { codes: Code[] }).codes);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function mint(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMinted(null);
    try {
      const res = await fetch("/api/admin/credit-codes", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          credits: Number(credits),
          label,
          maxRedemptions: Number(maxRedemptions || 1),
          expiresInDays: expiresInDays ? Number(expiresInDays) : 0,
        }),
      });
      const body = (await res.json().catch(() => ({}))) as { code?: string; error?: string };
      if (!res.ok || !body.code) setError(body.error ?? "Could not mint.");
      else setMinted(body.code);
      await load();
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!confirm("Revoke this code? Credits already redeemed stay.")) return;
    await fetch(`/api/admin/credit-codes/${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
    await load();
  }

  const input =
    "rounded border border-tc-border bg-tc-darker px-3 py-1.5 text-sm text-white focus:border-tc-green focus:outline-none";

  return (
    <section className="mt-8 rounded-lg border border-tc-border/50 bg-tc-dark p-6">
      <h2 className="text-lg font-semibold text-white mb-1">Credit codes</h2>
      <p className="text-sm text-tc-text-dim mb-4">
        Mint a code to hand to someone. 1 credit = $1.00 of credit balance. The code is shown once; only its hash is
        stored.
      </p>
      <form onSubmit={mint} className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-tc-text-dim">
          Credits
          <input className={`${input} block w-24`} value={credits} onChange={(e) => setCredits(e.target.value)} inputMode="numeric" />
        </label>
        <label className="text-xs text-tc-text-dim">
          Label
          <input className={`${input} block w-56`} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Who it is for" />
        </label>
        <label className="text-xs text-tc-text-dim">
          Uses
          <input className={`${input} block w-20`} value={maxRedemptions} onChange={(e) => setMaxRedemptions(e.target.value)} inputMode="numeric" />
        </label>
        <label className="text-xs text-tc-text-dim">
          Expires in (days)
          <input className={`${input} block w-24`} value={expiresInDays} onChange={(e) => setExpiresInDays(e.target.value)} inputMode="numeric" placeholder="never" />
        </label>
        <button type="submit" disabled={busy} className="rounded bg-tc-green px-4 py-1.5 text-sm font-bold text-black disabled:opacity-50">
          {busy ? "Minting..." : "Mint code"}
        </button>
      </form>
      {minted && (
        <p className="mt-3 text-sm text-white">
          New code: <code className="font-mono text-tc-green select-all">{minted}</code>
        </p>
      )}
      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      {codes.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-tc-text-dim">
              <tr>
                <th className="py-1 pr-3">Label</th>
                <th className="py-1 pr-3">Credits</th>
                <th className="py-1 pr-3">Used</th>
                <th className="py-1 pr-3">Created</th>
                <th className="py-1 pr-3">Expires</th>
                <th className="py-1" />
              </tr>
            </thead>
            <tbody>
              {codes.map((c) => (
                <tr key={c.id} className="border-t border-tc-border/50 text-white">
                  <td className="py-1 pr-3">{c.label}</td>
                  <td className="py-1 pr-3 font-mono">{c.grant.amount}</td>
                  <td className="py-1 pr-3 font-mono">{c.redemptions}/{c.maxRedemptions}</td>
                  <td className="py-1 pr-3">{day(c.createdAt)}</td>
                  <td className="py-1 pr-3">{day(c.expiresAt)}</td>
                  <td className="py-1 text-right">
                    {c.revokedAt ? (
                      <span className="text-xs text-tc-text-dim">revoked</span>
                    ) : (
                      <button type="button" onClick={() => revoke(c.id)} className="text-xs text-red-400 hover:underline">
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
