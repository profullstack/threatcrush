"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";
import RedeemCodeCard from "@/components/credits/RedeemCodeCard";

export default function BillingContent() {
  const { signedIn, loading: authLoading } = useAuth();
  const [balance, setBalance] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/usage", { headers: authHeaders(), cache: "no-store" });
      if (!res.ok) return;
      const data = (await res.json()) as { balance_usd?: number };
      if (typeof data.balance_usd === "number") setBalance(data.balance_usd);
    } catch {
      // the card still works without the balance
    }
  }, []);

  useEffect(() => {
    if (signedIn) void load();
  }, [signedIn, load]);

  if (!authLoading && !signedIn) {
    return (
      <main className="pt-24 pb-16 min-h-screen">
        <div className="mx-auto max-w-3xl px-4 sm:px-6 text-center">
          <h1 className="text-3xl font-bold text-white mb-4">Credits &amp; Codes</h1>
          <p className="text-tc-text-dim mb-6">Sign in to see your credit balance and redeem a code.</p>
          <Link
            href="/auth/login?next=/dashboard/billing"
            className="inline-block rounded-lg bg-tc-green px-5 py-2 text-sm font-bold text-black hover:bg-tc-green-dim"
          >
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
          <p className="font-mono text-sm text-tc-green mb-2 tracking-wider">// BILLING</p>
          <h1 className="text-3xl sm:text-4xl font-bold text-white">
            Credits <span className="text-tc-green">&amp; Codes</span>
          </h1>
        </div>

        <div className="rounded-xl border border-tc-green/30 bg-tc-card p-6">
          <p className="text-sm text-tc-text-dim font-mono mb-1">Credit balance</p>
          <p className="text-4xl font-black text-tc-green font-mono">
            {balance === null ? "—" : `$${balance.toFixed(2)}`}
          </p>
          <p className="text-sm text-tc-text-dim mt-2">
            Spending history and payments are on{" "}
            <Link href="/usage" className="text-tc-green hover:underline">Usage</Link>. Plans and the $400 scan are on{" "}
            <Link href="/pricing" className="text-tc-green hover:underline">Pricing</Link>.
          </p>
        </div>

        <RedeemCodeCard onRedeemed={(b) => (b === null ? void load() : setBalance(b))} />

        <div className="rounded-xl border border-tc-border bg-tc-card p-6">
          <h2 className="text-lg font-semibold text-white mb-1">Invites</h2>
          <p className="text-sm text-tc-text-dim mb-3">
            You have three invites. When someone new joins on one, you both get free credits.
          </p>
          <Link href="/invites" className="text-tc-green hover:underline text-sm">Your invites →</Link>
        </div>
      </div>
    </main>
  );
}
