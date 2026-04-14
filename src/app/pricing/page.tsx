"use client";

import { useState, useCallback } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders, getAccessToken } from "@/lib/auth-client";

type CryptoCurrency =
  | "usdc_sol"
  | "usdc_eth"
  | "usdc_pol"
  | "usdt"
  | "btc"
  | "eth"
  | "sol"
  | "pol";

interface CurrencyOption {
  value: CryptoCurrency;
  label: string;
  symbol: string;
  chain: string;
}

const CURRENCY_OPTIONS: CurrencyOption[] = [
  { value: "usdc_sol", label: "USDC", symbol: "USDC", chain: "Solana" },
  { value: "usdc_eth", label: "USDC", symbol: "USDC", chain: "Ethereum" },
  { value: "usdc_pol", label: "USDC", symbol: "USDC", chain: "Polygon" },
  { value: "usdt", label: "USDT", symbol: "USDT", chain: "Multi-chain" },
  { value: "btc", label: "BTC", symbol: "BTC", chain: "Bitcoin" },
  { value: "eth", label: "ETH", symbol: "ETH", chain: "Ethereum" },
  { value: "sol", label: "SOL", symbol: "SOL", chain: "Solana" },
  { value: "pol", label: "POL", symbol: "POL", chain: "Polygon" },
];

const FEATURES = [
  "Real-time threat intelligence feed",
  "Vulnerability tracking & alerts",
  "Attack surface monitoring",
  "Threat actor intelligence",
  "Custom alerts & notifications",
  "API access",
  "Unlimited workspaces",
  "Team collaboration",
  "Priority support",
  "Lifetime updates",
];

const CHECK_ICON = (
  <svg
    className="w-5 h-5 text-tc-green flex-shrink-0"
    fill="none"
    viewBox="0 0 24 24"
    stroke="currentColor"
    strokeWidth={2.5}
  >
    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
  </svg>
);

export default function PricingPage() {
  const { signedIn, loading: authLoading } = useAuth();
  const [currency, setCurrency] = useState<CryptoCurrency>("usdc_sol");
  const [payLoading, setPayLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const handlePurchase = useCallback(async () => {
    setPayLoading(true);
    setError("");

    const token = getAccessToken();
    if (!token) {
      setError("You must be signed in to purchase.");
      setPayLoading(false);
      return;
    }

    try {
      const res = await fetch("/api/auth/purchase", {
        method: "POST",
        headers: {
          ...authHeaders({ "Content-Type": "application/json" }),
        },
        body: JSON.stringify({ currency }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Purchase failed");
      }

      // Redirect to checkout URL if available
      if (data.checkout_url) {
        window.location.href = data.checkout_url;
        return;
      }

      // Fallback: show payment address if provided
      if (data.payment_address) {
        setError(
          `Send payment to: ${data.payment_address} (${data.amount_usd} USD)`,
        );
        setPayLoading(false);
        return;
      }

      setError("Something went wrong. Please try again.");
      setPayLoading(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setPayLoading(false);
    }
  }, [currency]);

  const copyReferralLink = useCallback(() => {
    const url = `${typeof window !== "undefined" ? window.location.origin : ""}/pricing?ref=YOUR_CODE`;
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, []);

  const signupUrl = `/auth/signup?next=/pricing`;

  return (
    <div className="min-h-screen bg-tc-darker">
      {/* Hero */}
      <section className="pt-20 pb-12 px-4 text-center">
        <div className="max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-5xl font-bold font-mono text-white mb-4">
            Simple, Transparent{" "}
            <span className="text-tc-green glow-green">Pricing</span>
          </h1>
          <p className="text-lg text-tc-text-dim max-w-xl mx-auto">
            One price. Lifetime access. No subscriptions. No surprises.
          </p>
        </div>
      </section>

      {/* Pricing Card */}
      <section className="pb-16 px-4">
        <div className="max-w-lg mx-auto">
          <div className="relative bg-tc-card border border-tc-border rounded-2xl overflow-hidden">
            {/* Glow accent */}
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-tc-green to-transparent opacity-40" />

            <div className="p-8">
              {/* Price */}
              <div className="text-center mb-8">
                <div className="inline-flex items-center gap-2 bg-tc-green/10 text-tc-green text-sm font-medium px-3 py-1 rounded-full mb-4">
                  <span>Lifetime Access</span>
                </div>
                <div className="flex items-baseline justify-center gap-1">
                  <span className="text-5xl md:text-6xl font-bold text-white font-mono">
                    $499
                  </span>
                </div>
                <p className="text-tc-text-dim text-sm mt-2">
                  One-time payment. Yours forever.
                </p>
              </div>

              {/* Referral banner */}
              <div className="mb-8 p-4 border border-tc-green/20 rounded-xl bg-tc-green/5">
                <p className="text-sm text-tc-green font-medium mb-1">
                  Save $100 with a referral code
                </p>
                <p className="text-xs text-tc-text-dim">
                  <span className="line-through opacity-50">$499</span>{" "}
                  <span className="text-tc-green font-bold text-tc-green">$399</span>{" "}
                  — both you and the referrer get the discount.
                </p>
                <div className="flex gap-2 mt-3">
                  <input
                    readOnly
                    onClick={(e) => (e.target as HTMLInputElement).select()}
                    value={`${typeof window !== "undefined" ? window.location.origin : ""}/pricing?ref=YOUR_CODE`}
                    className="flex-1 bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-xs font-mono text-tc-text truncate"
                  />
                  <button
                    onClick={copyReferralLink}
                    className="px-3 py-2 rounded-lg bg-tc-green/10 text-tc-green text-xs font-medium hover:bg-tc-green/20 transition-colors whitespace-nowrap"
                  >
                    {copied ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>

              {/* Features list */}
              <div className="mb-8">
                <h3 className="text-sm font-medium text-tc-text-dim mb-3 uppercase tracking-wider">
                  What&apos;s included
                </h3>
                <ul className="space-y-2.5">
                  {FEATURES.map((feature) => (
                    <li key={feature} className="flex items-center gap-3">
                      {CHECK_ICON}
                      <span className="text-sm text-tc-text">{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Error message */}
              {error && (
                <div className="mb-4 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">
                  {error}
                </div>
              )}

              {/* Auth-gated purchase area */}
              {authLoading ? (
                <div className="w-full h-12 bg-tc-darker border border-tc-border rounded-lg flex items-center justify-center">
                  <div className="w-5 h-5 border-2 border-tc-green/30 border-t-tc-green rounded-full animate-spin" />
                </div>
              ) : signedIn ? (
                <div>
                  {/* Currency selector */}
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-tc-text-dim mb-2">
                      Pay with
                    </label>
                    <div className="grid grid-cols-2 gap-2">
                      {CURRENCY_OPTIONS.map((opt) => (
                        <button
                          key={opt.value}
                          onClick={() => setCurrency(opt.value)}
                          className={`rounded-lg border p-2.5 text-left transition-all ${
                            currency === opt.value
                              ? "border-tc-green bg-tc-green/5"
                              : "border-tc-border bg-tc-darker hover:border-tc-green/30"
                          }`}
                        >
                          <div
                            className={`text-sm font-medium ${
                              currency === opt.value
                                ? "text-tc-green"
                                : "text-tc-text"
                            }`}
                          >
                            {opt.symbol}
                          </div>
                          <div className="text-xs text-tc-text-dim">
                            {opt.chain}
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={handlePurchase}
                    disabled={payLoading}
                    className="w-full rounded-lg bg-tc-green px-6 py-3 font-bold text-black text-lg transition-all hover:bg-tc-green-dim disabled:opacity-40 disabled:cursor-not-allowed pulse-glow"
                  >
                    {payLoading ? (
                      <span className="flex items-center justify-center gap-2">
                        <div className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                        Processing...
                      </span>
                    ) : (
                      `Pay $499`
                    )}
                  </button>
                  <p className="text-center text-xs text-tc-text-dim mt-3">
                    Secure crypto checkout via CoinPayPortal
                  </p>
                </div>
              ) : (
                <div>
                  <Link
                    href={signupUrl}
                    className="block w-full text-center rounded-lg bg-tc-green px-6 py-3 font-bold text-black text-lg transition-all hover:bg-tc-green-dim pulse-glow"
                  >
                    Sign Up to Purchase
                  </Link>
                  <div className="mt-3 text-center">
                    <Link
                      href="/auth/login?next=/pricing"
                      className="text-sm text-tc-text-dim hover:text-tc-green transition-colors"
                    >
                      Already have an account? Log in
                    </Link>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* FAQ / Comparison section */}
      <section className="pb-20 px-4">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-2xl font-bold text-white font-mono mb-8 text-center">
            Why <span className="text-tc-green">ThreatCrush</span>?
          </h2>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-tc-card border border-tc-border rounded-xl p-6">
              <div className="text-3xl mb-3">🔒</div>
              <h3 className="text-lg font-bold text-white mb-2">
                Lifetime Access
              </h3>
              <p className="text-sm text-tc-text-dim">
                Pay once, use forever. No subscriptions, no recurring fees, no
                hidden costs. Ever.
              </p>
            </div>
            <div className="bg-tc-card border border-tc-border rounded-xl p-6">
              <div className="text-3xl mb-3">⚡</div>
              <h3 className="text-lg font-bold text-white mb-2">
                Real-Time Intel
              </h3>
              <p className="text-sm text-tc-text-dim">
                Live threat feeds, CVE tracking, and actor intelligence updated
                continuously from dozens of sources.
              </p>
            </div>
            <div className="bg-tc-card border border-tc-border rounded-xl p-6">
              <div className="text-3xl mb-3">🎁</div>
              <h3 className="text-lg font-bold text-white mb-2">
                Referral Rewards
              </h3>
              <p className="text-sm text-tc-text-dim">
                Share your code, save $100 each. Build your network, earn
                lifetime access for less.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
