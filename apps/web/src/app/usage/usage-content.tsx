"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";
import ScrollReveal from "@/components/ScrollReveal";

interface UsageData {
  balance_usd: number;
  today_usd: number;
  today_requests: number;
  week_usd: number;
  week_requests: number;
  month_usd: number;
  month_requests: number;
  burn_rate_daily: number;
  estimated_days_remaining: number;
  projected_monthly_usd: number;
  daily_spend: Array<{ date: string; amount: number; requests: number }>;
  module_breakdown: Array<{
    module: string;
    action: string;
    requests: number;
    cost: number;
    percentage: number;
  }>;
  history: Array<{
    id: string;
    timestamp: string;
    module: string;
    action: string;
    cost_usd: number;
    status: string;
  }>;
  payment_history: Array<{
    id: string;
    coinpay_payment_id: string | null;
    amount_usd: number;
    status: string;
    created_at: string;
  }>;
}

function costTierColor(cost: number): string {
  if (cost >= 0.01) return "text-red-400";
  if (cost >= 0.005) return "text-yellow-400";
  return "text-tc-green";
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export default function UsageContent() {
  const { signedIn, loading: authLoading, profile } = useAuth();
  const [data, setData] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [topupAmount, setTopupAmount] = useState<number>(10);
  const [topupCurrency, setTopupCurrency] = useState("usdc_sol");
  const [showTopup, setShowTopup] = useState(false);
  const [payLoading, setPayLoading] = useState(false);
  const [paymentError, setPaymentError] = useState("");
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [paymentStatus, setPaymentStatus] = useState<{
    paymentId: string;
    checkoutUrl: string | null;
    paymentAddress: string | null;
    amountUsd: number;
    amountCrypto: number | null;
    currency: string;
    status: "pending" | "confirming" | "confirmed" | "forwarded" | "expired" | "failed";
  } | null>(null);

  useEffect(() => {
    if (!authLoading && !signedIn) {
      window.location.href = "/auth/login?next=/usage";
      return;
    }
    if (!authLoading && signedIn) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000); // 15s timeout

      fetch(`/api/usage`, { headers: authHeaders(), signal: controller.signal })
        .then(async (r) => {
          const d = await r.json();
          if (!r.ok || d.error) {
            throw new Error(d.error || `HTTP ${r.status}`);
          }
          return d;
        })
        .then((d) => {
          clearTimeout(timeout);
          setData(d);
          setLoading(false);
        })
        .catch((err) => {
          clearTimeout(timeout);
          console.error("Usage API error:", err);
          setError(err.name === "AbortError" ? "Request timed out. Check your connection or try again later." : err.message || "Failed to fetch usage data");
          setLoading(false);
        });

      return () => clearTimeout(timeout);
    }
  }, [signedIn, authLoading]);

  const handleTopup = async () => {
    if (!topupAmount || topupAmount < 1) return;
    setPayLoading(true);
    setPaymentError("");
    setCopiedField(null);
    try {
      const res = await fetch("/api/usage/topup", {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ amount_usd: topupAmount, currency: topupCurrency }),
      });
      const result = await res.json();
      if (!res.ok) {
        setPaymentError(result.error || "Failed to create top-up");
        return;
      }
      // Open payment tracking modal
      setPaymentStatus({
        paymentId: result.payment_id,
        checkoutUrl: result.checkout_url,
        paymentAddress: result.payment_address,
        amountUsd: topupAmount,
        amountCrypto: result.amount_crypto ?? null,
        currency: topupCurrency,
        status: "pending",
      });
      setShowTopup(false);
      // Poll for payment status
      pollPaymentStatus(result.payment_id);
    } catch {
      setPaymentError("Failed to create top-up. Try again.");
    } finally {
      setPayLoading(false);
    }
  };

  const pollPaymentStatus = async (paymentId: string) => {
    let attempts = 0;
    const maxAttempts = 60; // 5 minutes at 5s intervals
    const interval = setInterval(async () => {
      if (attempts >= maxAttempts) {
        clearInterval(interval);
        setPaymentStatus((prev) => prev ? { ...prev, status: "expired" } : null);
        return;
      }
      try {
        const res = await fetch(`/api/usage/payment-status/${paymentId}`);
        if (res.ok) {
          const data = await res.json();
          setPaymentStatus((prev) => prev ? { ...prev, status: data.status } : null);
          if (data.status === "confirmed" || data.status === "forwarded") {
            clearInterval(interval);
            // Refresh usage data
            fetch(`/api/usage`, { headers: authHeaders() })
              .then((r) => r.json())
              .then((d) => { if (!d.error) setData(d); setLoading(false); });
          }
        }
      } catch {
        // retry
      }
      attempts++;
    }, 5000);

    return () => clearInterval(interval);
  };

  const maxDailySpend = data?.daily_spend
    ? Math.max(...data.daily_spend.map((d) => d.amount), 0.01)
    : 1;

  return (
    <>
      {/* ─── Top Bar ─── */}
      <div className="fixed top-16 right-4 z-40">
        <button
          onClick={() => setShowTopup(true)}
          className="rounded-lg bg-tc-green px-4 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim shadow-lg"
        >
          Top Up
        </button>
      </div>

      <main className="pt-24 pb-16 min-h-screen">
      <div className="mx-auto max-w-6xl px-6">
        {/* Header */}
        <ScrollReveal>
          <div className="mb-8">
            <p className="font-mono text-sm text-tc-green mb-2 tracking-wider">// USAGE &amp; BILLING</p>
            <h1 className="text-3xl sm:text-4xl font-bold text-white">
              AI Usage <span className="text-tc-green glow-green">Dashboard</span>
            </h1>
            <p className="text-tc-text-dim mt-2">
              Track your AI module spending and manage credits.
            </p>
          </div>
        </ScrollReveal>

          {loading ? (
            <div className="flex items-center justify-center py-32">
              <div className="text-tc-green font-mono animate-pulse">Loading usage data...</div>
            </div>
          ) : data ? (
            <>
              {/* ─── Balance Card ─── */}
              <ScrollReveal delay={100}>
                <div className="rounded-2xl border border-tc-green/30 bg-tc-card p-8 mb-8 glow-box">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
                    <div>
                      <p className="text-sm text-tc-text-dim font-mono mb-1">Available Balance</p>
                      <p className="text-5xl sm:text-6xl font-black text-tc-green glow-green-strong font-mono">
                        ${data.balance_usd.toFixed(2)}
                      </p>
                      <p className="text-sm text-tc-text-dim mt-2">remaining</p>
                    </div>
                    <div className="flex flex-col items-start sm:items-end gap-2">
                      <p className="text-sm text-tc-text-dim">
                        <span className="text-tc-green font-mono">~${data.burn_rate_daily.toFixed(2)}</span>/day at current usage
                      </p>
                      <p className="text-sm text-tc-text-dim">
                        <span className="text-tc-green font-mono">~{data.estimated_days_remaining}</span> days remaining
                      </p>
                      <button
                        onClick={() => setShowTopup(true)}
                        className="mt-2 rounded-lg bg-tc-green px-6 py-2.5 text-sm font-bold text-black transition-all hover:bg-tc-green-dim"
                      >
                        + Top Up Credits
                      </button>
                    </div>
                  </div>
                </div>
              </ScrollReveal>

              {/* ─── Stats Row ─── */}
              <ScrollReveal delay={200}>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                  {[
                    { label: "Today", value: `$${data.today_usd.toFixed(2)}`, sub: `${data.today_requests} requests`, color: "text-tc-green" },
                    { label: "This Week", value: `$${data.week_usd.toFixed(2)}`, sub: `${data.week_requests} requests`, color: "text-tc-green" },
                    { label: "This Month", value: `$${data.month_usd.toFixed(2)}`, sub: `${data.month_requests} requests`, color: "text-tc-green" },
                    { label: "Projected", value: `~$${data.projected_monthly_usd.toFixed(2)}`, sub: "per month", color: "text-yellow-400" },
                  ].map((stat) => (
                    <div
                      key={stat.label}
                      className="rounded-xl border border-tc-border bg-tc-card p-5 hover:border-tc-green/30 transition-all"
                    >
                      <p className="text-xs text-tc-text-dim font-mono mb-2">{stat.label}</p>
                      <p className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</p>
                      <p className="text-xs text-tc-text-dim mt-1">{stat.sub}</p>
                    </div>
                  ))}
                </div>
              </ScrollReveal>

              {/* ─── Usage by Module ─── */}
              {data.module_breakdown.length > 0 && (
                <ScrollReveal delay={300}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-6 mb-8">
                    <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <span className="text-tc-green">📊</span> Usage by Module
                    </h2>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-tc-border text-tc-text-dim font-mono text-xs">
                            <th className="text-left py-3 pr-4">Module</th>
                            <th className="text-left py-3 pr-4">Action</th>
                            <th className="text-right py-3 pr-4">Requests</th>
                            <th className="text-right py-3 pr-4">Cost</th>
                            <th className="text-right py-3">% of Total</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.module_breakdown.map((mod) => (
                            <tr key={`${mod.module}-${mod.action}`} className="border-b border-tc-border/50 hover:bg-tc-green/5 transition-colors">
                              <td className="py-3 pr-4">
                                <span className="font-mono text-tc-green">{mod.module}</span>
                              </td>
                              <td className="py-3 pr-4 text-tc-text-dim font-mono text-xs">{mod.action}</td>
                              <td className="py-3 pr-4 text-right text-tc-text font-mono">{mod.requests.toLocaleString()}</td>
                              <td className="py-3 pr-4 text-right font-mono text-tc-green">${mod.cost.toFixed(2)}</td>
                              <td className="py-3 text-right">
                                <div className="flex items-center justify-end gap-2">
                                  <div className="w-16 h-1.5 rounded-full bg-tc-border overflow-hidden">
                                    <div
                                      className="h-full rounded-full bg-tc-green"
                                      style={{ width: `${mod.percentage}%` }}
                                    />
                                  </div>
                                  <span className="text-tc-text-dim font-mono text-xs w-8 text-right">{mod.percentage}%</span>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </ScrollReveal>
              )}

              {/* ─── Daily Spend Chart ─── */}
              {data.daily_spend.length > 0 && (
                <ScrollReveal delay={400}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-6 mb-8">
                    <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <span className="text-tc-green">📈</span> Daily Spend — Last 30 Days
                    </h2>
                    <div className="flex items-end gap-1 h-40">
                      {data.daily_spend.map((day) => {
                        const heightPct = maxDailySpend > 0 ? (day.amount / maxDailySpend) * 100 : 0;
                        return (
                          <div
                            key={day.date}
                            className="flex-1 group relative flex flex-col items-center justify-end"
                            title={`${formatDate(day.date)}: $${day.amount.toFixed(2)} (${day.requests} req)`}
                          >
                            <div
                              className="w-full rounded-t bg-tc-green/70 hover:bg-tc-green transition-colors min-h-[2px]"
                              style={{ height: `${Math.max(heightPct, 1)}%` }}
                            />
                            {/* Tooltip */}
                            <div className="absolute bottom-full mb-2 hidden group-hover:block z-10">
                              <div className="rounded-lg bg-tc-darker border border-tc-border px-3 py-2 text-xs whitespace-nowrap shadow-lg">
                                <p className="text-tc-text font-mono">{formatDate(day.date)}</p>
                                <p className="text-tc-green font-bold">${day.amount.toFixed(2)}</p>
                                <p className="text-tc-text-dim">{day.requests} requests</p>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div className="flex justify-between mt-2 text-[10px] text-tc-text-dim font-mono">
                      <span>{data.daily_spend.length > 0 ? formatDate(data.daily_spend[0].date) : ""}</span>
                      <span>{data.daily_spend.length > 0 ? formatDate(data.daily_spend[data.daily_spend.length - 1].date) : ""}</span>
                    </div>
                  </div>
                </ScrollReveal>
              )}

              {/* ─── Recent Activity ─── */}
              {data.history.length > 0 && (
                <ScrollReveal delay={500}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-6">
                    <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <span className="text-tc-green">🔄</span> Recent Activity
                    </h2>
                    <div className="space-y-1">
                      {data.history.map((evt) => (
                        <div
                          key={evt.id}
                          className="flex items-center gap-4 rounded-lg px-3 py-2 hover:bg-tc-green/5 transition-colors font-mono text-xs"
                        >
                          <span className="text-tc-text-dim w-32 flex-shrink-0">
                            {formatDate(evt.timestamp)} {formatTime(evt.timestamp)}
                          </span>
                          <span className="text-tc-green w-28 flex-shrink-0 truncate">{evt.module}</span>
                          <span className="text-tc-text-dim flex-1 truncate">{evt.action}</span>
                          <span className={`font-bold flex-shrink-0 ${costTierColor(evt.cost_usd)}`}>
                            ${evt.cost_usd.toFixed(4)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </ScrollReveal>
              )}

              {/* ─── Payment History ─── */}
              {data.payment_history && data.payment_history.length > 0 && (
                <ScrollReveal delay={600}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-6">
                    <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <span className="text-tc-green">💳</span> Payment History
                    </h2>
                    <div className="space-y-1">
                      {data.payment_history.map((payment) => (
                        <div
                          key={payment.id}
                          className="flex items-center justify-between px-4 py-3 rounded-lg border border-transparent hover:border-tc-border/50 hover:bg-tc-green/5 transition-all"
                        >
                          <div className="flex items-center gap-4">
                            <span className={`inline-block w-2 h-2 rounded-full ${
                              payment.status === "confirmed" || payment.status === "forwarded" ? "bg-tc-green" :
                              payment.status === "expired" ? "bg-red-400" :
                              payment.status === "failed" ? "bg-red-500" :
                              "bg-yellow-400 animate-pulse"
                            }`} />
                            <div>
                              <p className="text-tc-text font-mono text-sm">
                                ${payment.amount_usd.toFixed(2)}
                              </p>
                              <p className="text-[10px] text-tc-text-dim font-mono">
                                {new Date(payment.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" })}
                              </p>
                            </div>
                          </div>
                          <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold ${
                            payment.status === "confirmed" || payment.status === "forwarded" ? "bg-tc-green/10 text-tc-green border border-tc-green/30" :
                            payment.status === "pending" ? "bg-yellow-400/10 text-yellow-400 border border-yellow-400/30" :
                            "bg-red-400/10 text-red-400 border border-red-400/30"
                          }`}>
                            {payment.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </ScrollReveal>
              )}
            </>
          ) : error ? (
            <div className="text-center py-32">
              <p className="text-red-400 font-mono mb-4">Error: {error}</p>
              <button
                onClick={() => {
                  setError(null);
                  setLoading(true);
                  fetch(`/api/usage`, { headers: authHeaders() })
                    .then(async (r) => {
                      const d = await r.json();
                      if (!r.ok || d.error) {
                        throw new Error(d.error || `HTTP ${r.status}`);
                      }
                      return d;
                    })
                    .then((d) => {
                      setData(d);
                      setLoading(false);
                    })
                    .catch((err) => {
                      console.error("Usage API error:", err);
                      setError(err.message || "Failed to fetch usage data");
                      setLoading(false);
                    });
                }}
                className="rounded-lg bg-tc-green px-6 py-2.5 text-sm font-bold text-black transition-all hover:bg-tc-green-dim"
              >
                Retry
              </button>
            </div>
          ) : (
            <div className="text-center py-32">
              <p className="text-tc-text-dim">Failed to load usage data.</p>
            </div>
          )}
        </div>
      </main>

      {/* ─── Top Up Modal ─── */}
      {showTopup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setShowTopup(false)}>
          <div className="relative rounded-2xl border border-tc-green/30 bg-tc-darker p-8 max-w-md w-full mx-4 glow-box" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => setShowTopup(false)} className="absolute top-4 right-4 text-tc-text-dim hover:text-tc-text">✕</button>
            <h2 className="text-xl font-bold text-white mb-2">Top Up Credits</h2>
            <p className="text-sm text-tc-text-dim mb-6">Add AI usage credits via crypto.</p>

            {paymentError && <p className="text-red-400 text-sm mb-4">{paymentError}</p>}

            <div className="mb-4">
              <label className="text-xs text-tc-text-dim font-mono block mb-1">Payment currency</label>
              <select
                value={topupCurrency}
                onChange={(e) => setTopupCurrency(e.target.value)}
                className="w-full rounded-lg border border-tc-border bg-black/60 px-3 py-2 font-mono text-tc-green focus:border-tc-green/50 focus:outline-none"
              >
                <option value="usdc_sol">USDC (Solana) — Fast, cheap</option>
                <option value="usdc_eth">USDC (Ethereum)</option>
                <option value="usdc_pol">USDC (Polygon)</option>
                <option value="usdt">USDT</option>
                <option value="btc">Bitcoin</option>
                <option value="eth">Ethereum</option>
                <option value="sol">Solana</option>
                <option value="pol">Polygon</option>
              </select>
            </div>

            <div className="grid grid-cols-5 gap-2 mb-4">
              {[1, 5, 10, 25, 50].map((amt) => (
                <button
                  key={amt}
                  onClick={() => setTopupAmount(amt)}
                  className={`rounded-lg border px-3 py-2.5 font-mono text-sm font-bold transition-all ${
                    topupAmount === amt
                      ? "border-tc-green bg-tc-green/10 text-tc-green"
                      : "border-tc-border text-tc-text-dim hover:border-tc-green/30"
                  }`}
                >
                  ${amt}
                </button>
              ))}
            </div>

            <div className="mb-6">
              <label className="text-xs text-tc-text-dim font-mono block mb-1">Custom amount</label>
              <div className="flex items-center gap-2">
                <span className="text-tc-text-dim font-mono">$</span>
                <input
                  type="number"
                  min={1}
                  max={10000}
                  value={topupAmount}
                  onChange={(e) => setTopupAmount(Number(e.target.value))}
                  className="flex-1 rounded-lg border border-tc-border bg-black/60 px-3 py-2 font-mono text-tc-green focus:border-tc-green/50 focus:outline-none"
                />
              </div>
              <p className="text-[10px] text-tc-text-dim mt-1">Min $1 · Max $10,000</p>
            </div>

            <div className="flex gap-3">
              <button onClick={() => setShowTopup(false)} className="flex-1 rounded-lg border border-tc-border px-4 py-3 text-sm text-tc-text-dim hover:border-tc-green/30 transition-all">Cancel</button>
              <button
                onClick={handleTopup}
                disabled={payLoading || topupAmount < 1}
                className="flex-1 rounded-lg bg-tc-green px-4 py-3 text-sm font-bold text-black hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {payLoading ? "Creating payment..." : `Pay $${topupAmount}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Payment Tracking Modal ─── */}
      {paymentStatus && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setPaymentStatus(null)}>
          <div className="relative rounded-2xl border border-tc-green/30 bg-tc-darker p-8 max-w-lg w-full mx-4 glow-box" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => setPaymentStatus(null)} className="absolute top-4 right-4 text-tc-text-dim hover:text-tc-text">✕</button>

            <div className="text-center mb-6">
              <div className={`text-4xl mb-3 ${paymentStatus.status === "confirmed" || paymentStatus.status === "forwarded" ? "text-tc-green" : paymentStatus.status === "expired" ? "text-red-400" : "text-yellow-400 animate-pulse"}`}>
                {paymentStatus.status === "confirmed" || paymentStatus.status === "forwarded" ? "✅" : paymentStatus.status === "expired" ? "❌" : "⏳"}
              </div>
              <h2 className="text-xl font-bold text-white mb-1">
                {paymentStatus.status === "confirmed" || paymentStatus.status === "forwarded"
                  ? "Payment Confirmed!"
                  : paymentStatus.status === "expired"
                  ? "Payment Expired"
                  : "Awaiting Payment"}
              </h2>
              <p className="text-sm text-tc-text-dim">
                {paymentStatus.status === "pending" && "Send the exact amount below to complete your top-up."}
                {paymentStatus.status === "confirming" && "Payment detected — waiting for blockchain confirmations..."}
                {paymentStatus.status === "confirmed" && "Your credits have been added!"}
                {paymentStatus.status === "forwarded" && "Payment settled — credits updated!"}
                {paymentStatus.status === "expired" && "The payment window closed. Try again."}
              </p>
            </div>

            {/* Status indicator */}
            <div className="flex items-center justify-center gap-2 mb-6">
              <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-mono font-bold ${
                paymentStatus.status === "pending" ? "bg-yellow-400/10 text-yellow-400 border border-yellow-400/30" :
                paymentStatus.status === "confirming" ? "bg-blue-400/10 text-blue-400 border border-blue-400/30" :
                paymentStatus.status === "confirmed" || paymentStatus.status === "forwarded" ? "bg-tc-green/10 text-tc-green border border-tc-green/30" :
                "bg-red-400/10 text-red-400 border border-red-400/30"
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${
                  paymentStatus.status === "pending" ? "bg-yellow-400 animate-pulse" :
                  paymentStatus.status === "confirming" ? "bg-blue-400 animate-pulse" :
                  paymentStatus.status === "confirmed" || paymentStatus.status === "forwarded" ? "bg-tc-green" :
                  "bg-red-400"
                }`} />
                {paymentStatus.status.toUpperCase()}
              </span>
            </div>

            {/* Payment details */}
            <div className="space-y-3 mb-6">
              <div className="flex justify-between text-sm">
                <span className="text-tc-text-dim">Amount</span>
                <span className="text-white font-mono font-bold">${paymentStatus.amountUsd.toFixed(2)}</span>
              </div>
              {paymentStatus.amountCrypto && (
                <div className="flex justify-between text-sm items-center">
                  <span className="text-tc-text-dim">Send exactly</span>
                  <div className="flex items-center gap-2">
                    <span className="text-tc-green font-mono font-bold">{paymentStatus.amountCrypto} {paymentStatus.currency.split("_")[0].toUpperCase()}</span>
                    <span className="text-tc-text-dim font-mono text-xs">(${paymentStatus.amountUsd.toFixed(2)})</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(`${paymentStatus.amountCrypto}`);
                        setCopiedField("crypto");
                        setTimeout(() => setCopiedField(null), 1500);
                      }}
                      className={`text-xs transition-colors ${copiedField === "crypto" ? "text-tc-green font-bold" : "text-tc-text-dim hover:text-tc-green"}`}
                      title="Click to copy"
                    >
                      {copiedField === "crypto" ? "✓ Copied!" : "📋"}
                    </button>
                  </div>
                </div>
              )}
              <div className="flex justify-between text-sm">
                <span className="text-tc-text-dim">Currency</span>
                <span className="text-white font-mono">{paymentStatus.currency}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-tc-text-dim">Payment ID</span>
                <span className="text-white font-mono text-xs truncate ml-4 max-w-[200px]">{paymentStatus.paymentId}</span>
              </div>
            </div>

            {/* Payment address */}
            {(paymentStatus.status === "pending" || paymentStatus.status === "confirming") && paymentStatus.paymentAddress && (
              <div className="mb-6 p-4 border border-tc-border rounded-xl bg-tc-darker">
                <p className="text-xs text-tc-text-dim mb-2">Send payment to:</p>
                <code className="block bg-black/40 border border-tc-border rounded-lg p-3 text-xs text-tc-green font-mono break-all select-all cursor-pointer"
                  onClick={() => {
                    navigator.clipboard.writeText(paymentStatus.paymentAddress || "");
                    setCopiedField("address");
                    setTimeout(() => setCopiedField(null), 1500);
                  }}
                  title="Click to copy"
                >
                  {paymentStatus.paymentAddress}
                </code>
                <p className="text-[10px] text-tc-text-dim mt-1.5">
                  {copiedField === "address" ? "✓ Copied to clipboard!" : "Click address to copy"}
                </p>
              </div>
            )}

            {/* Stripe checkout link */}
            {paymentStatus.checkoutUrl && paymentStatus.status === "pending" && (
              <a
                href={paymentStatus.checkoutUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="block w-full text-center bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all mb-3"
              >
                Open Checkout →
              </a>
            )}

            <div className="flex gap-3">
              {paymentStatus.status === "expired" && (
                <button
                  onClick={() => { setPaymentStatus(null); setShowTopup(true); }}
                  className="flex-1 rounded-lg bg-tc-green px-4 py-3 text-sm font-bold text-black hover:bg-tc-green-dim transition-all"
                >
                  Try Again
                </button>
              )}
              {(paymentStatus.status === "confirmed" || paymentStatus.status === "forwarded") && (
                <button
                  onClick={() => setPaymentStatus(null)}
                  className="flex-1 rounded-lg bg-tc-green px-4 py-3 text-sm font-bold text-black hover:bg-tc-green-dim transition-all"
                >
                  Done
                </button>
              )}
              {paymentStatus.status === "pending" && (
                <div className="flex-1 text-center">
                  <span className="text-sm text-tc-text-dim font-mono animate-pulse">Monitoring payment...</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
