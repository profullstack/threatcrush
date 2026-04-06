"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
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
  demo: boolean;
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
  const [data, setData] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [topupAmount, setTopupAmount] = useState<number>(10);
  const [showTopup, setShowTopup] = useState(false);

  useEffect(() => {
    fetch("/api/usage")
      .then((r) => r.json())
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const handleTopup = async () => {
    if (!topupAmount || topupAmount < 5) return;
    try {
      const res = await fetch("/api/usage/topup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "user@example.com", amount_usd: topupAmount }),
      });
      const result = await res.json();
      if (result.payment_url) {
        window.location.href = result.payment_url;
      } else if (result.demo) {
        alert("Demo mode: Top-up simulated! In production, this would redirect to CoinPayPortal.");
        setShowTopup(false);
      }
    } catch {
      alert("Failed to create top-up. Try again.");
    }
  };

  const maxDailySpend = data?.daily_spend
    ? Math.max(...data.daily_spend.map((d) => d.amount), 0.01)
    : 1;

  return (
    <>
      {/* ─── NAV ─── */}
      <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-xl font-bold text-tc-green glow-green font-mono">
              ⚡ ThreatCrush
            </span>
          </Link>
          <div className="hidden sm:flex items-center gap-6 text-sm text-tc-text-dim">
            <Link href="/#features" className="hover:text-tc-green transition-colors">Features</Link>
            <Link href="/store" className="hover:text-tc-green transition-colors">Module Store</Link>
            <Link href="/usage" className="text-tc-green transition-colors">Usage</Link>
            <Link href="/#pricing" className="hover:text-tc-green transition-colors">Pricing</Link>
          </div>
          <button
            onClick={() => setShowTopup(true)}
            className="rounded-lg bg-tc-green px-4 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim"
          >
            Top Up
          </button>
        </div>
      </nav>

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
                {data?.demo && (
                  <span className="ml-2 inline-block rounded-full bg-yellow-400/10 border border-yellow-400/30 px-2 py-0.5 text-xs text-yellow-400 font-mono">
                    DEMO DATA
                  </span>
                )}
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
            </>
          ) : (
            <div className="text-center py-32">
              <p className="text-tc-text-dim">Failed to load usage data.</p>
            </div>
          )}
        </div>
      </main>

      {/* ─── Top Up Modal ─── */}
      {showTopup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="rounded-2xl border border-tc-green/30 bg-tc-darker p-8 max-w-md w-full mx-4 glow-box">
            <h2 className="text-xl font-bold text-white mb-2">Top Up Credits</h2>
            <p className="text-sm text-tc-text-dim mb-6">Add AI usage credits via CoinPayPortal (crypto or card).</p>

            <div className="grid grid-cols-4 gap-2 mb-4">
              {[5, 10, 25, 50].map((amt) => (
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
                  min={5}
                  max={1000}
                  value={topupAmount}
                  onChange={(e) => setTopupAmount(Number(e.target.value))}
                  className="flex-1 rounded-lg border border-tc-border bg-black/60 px-3 py-2 font-mono text-tc-green focus:border-tc-green/50 focus:outline-none"
                />
              </div>
              <p className="text-[10px] text-tc-text-dim mt-1">Min $5 · Max $1,000</p>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setShowTopup(false)}
                className="flex-1 rounded-lg border border-tc-border px-4 py-3 text-sm text-tc-text-dim hover:border-tc-green/30 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleTopup}
                className="flex-1 rounded-lg bg-tc-green px-4 py-3 text-sm font-bold text-black hover:bg-tc-green-dim transition-all"
              >
                Pay ${topupAmount}
              </button>
            </div>

            <div className="flex items-center justify-center gap-3 mt-4 text-[10px] text-tc-text-dim">
              <span>💳 Stripe</span>
              <span>·</span>
              <span>₿ Crypto</span>
              <span>·</span>
              <span>🔒 Secure</span>
            </div>
          </div>
        </div>
      )}

      {/* ─── Footer ─── */}
      <footer className="border-t border-tc-border py-12">
        <div className="mx-auto max-w-6xl px-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
            <Link href="/" className="font-mono text-tc-green font-bold">⚡ ThreatCrush</Link>
            <div className="flex items-center gap-6 text-sm text-tc-text-dim">
              <Link href="/#features" className="hover:text-tc-green transition-colors">Features</Link>
              <Link href="/store" className="hover:text-tc-green transition-colors">Module Store</Link>
              <Link href="/usage" className="hover:text-tc-green transition-colors">Usage</Link>
              <Link href="/#pricing" className="hover:text-tc-green transition-colors">Pricing</Link>
            </div>
            <p className="text-xs text-tc-text-dim">
              © {new Date().getFullYear()} <a href="https://profullstack.com" className="hover:text-tc-green transition-colors">Profullstack, Inc.</a>
            </p>
          </div>
        </div>
      </footer>
    </>
  );
}
