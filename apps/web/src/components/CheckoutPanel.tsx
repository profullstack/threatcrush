"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

export interface CheckoutPlanView {
  id: string;
  name: string;
  months: number | null;
  amount_usd: number;
}

export interface CheckoutMethodView {
  id: string;
  label: string;
}

const selectClass =
  "w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-sm text-tc-text focus:border-tc-green focus:outline-none";

function planLabel(p: CheckoutPlanView): string {
  if (p.months === null) return `$${p.amount_usd} one-time`;
  return `$${p.amount_usd} / ${p.months === 1 ? "month" : `${p.months} months`}`;
}

/**
 * Buy one product: pick a plan and a way to pay (CoinPay checkout when it is
 * up, otherwise any coin or PayPal), then go to CoinPay. Signed-out visitors
 * are sent to log in and brought back here.
 */
export function CheckoutPanel({
  product,
  plans,
  methods,
  enabled,
  askTarget = false,
  cta = "Check out",
  returnPath,
}: {
  product: string;
  plans: CheckoutPlanView[];
  methods: CheckoutMethodView[];
  enabled: boolean;
  /** The scan: ask what to scan. */
  askTarget?: boolean;
  cta?: string;
  /** Where log-in brings the buyer back to. */
  returnPath: string;
}) {
  const { signedIn, loading } = useAuth();
  const [plan, setPlan] = useState(plans[0]?.id ?? "");
  const [method, setMethod] = useState(methods[0]?.id ?? "");
  const [target, setTarget] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (!enabled) {
    return <p className="text-sm text-tc-text-dim">Not on sale right now.</p>;
  }

  if (!loading && !signedIn) {
    const next = encodeURIComponent(returnPath);
    return (
      <div className="space-y-2">
        <a
          href={`/auth/signup?next=${next}`}
          className="block w-full rounded-lg bg-tc-green px-4 py-2.5 text-center text-sm font-bold text-black hover:opacity-90"
        >
          Create a free account to buy
        </a>
        <p className="text-center text-xs text-tc-text-dim">
          Have one?{" "}
          <a className="text-tc-green underline" href={`/auth/login?next=${next}`}>
            Log in
          </a>
        </p>
      </div>
    );
  }

  async function go() {
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/checkout", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          product,
          plan,
          method,
          ...(askTarget ? { target, notes } : {}),
        }),
      });
      const data = (await res.json().catch(() => ({}))) as { url?: string; error?: string };
      if (!res.ok || !data.url) throw new Error(data.error || "Could not start the payment");
      window.location.href = data.url;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start the payment");
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      {plans.length > 1 && (
        <label className="block text-sm text-tc-text-dim">
          Plan
          <select className={`${selectClass} mt-1`} value={plan} onChange={(e) => setPlan(e.target.value)}>
            {plans.map((p) => (
              <option key={p.id} value={p.id}>
                {planLabel(p)}
              </option>
            ))}
          </select>
        </label>
      )}
      {askTarget && (
        <>
          <label className="block text-sm text-tc-text-dim">
            What should we scan? (repo URL, domain or app)
            <input
              className={`${selectClass} mt-1`}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://github.com/you/app"
              maxLength={500}
            />
          </label>
          <label className="block text-sm text-tc-text-dim">
            Anything we should know (optional)
            <textarea
              className={`${selectClass} mt-1`}
              rows={2}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              maxLength={4000}
            />
          </label>
        </>
      )}
      <label className="block text-sm text-tc-text-dim">
        Pay with
        <select className={`${selectClass} mt-1`} value={method} onChange={(e) => setMethod(e.target.value)}>
          {methods.map((m) => (
            <option key={m.id} value={m.id}>
              {m.label}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        onClick={go}
        disabled={busy || loading}
        className="w-full rounded-lg bg-tc-green px-4 py-2.5 text-sm font-bold text-black hover:opacity-90 disabled:opacity-50"
      >
        {busy ? "Opening checkout..." : cta}
      </button>
      {error && <p className="text-sm text-red-400">{error}</p>}
      <p className="text-xs text-tc-text-dim">Checkout through CoinPay: crypto or PayPal. No card form on this site.</p>
    </div>
  );
}
