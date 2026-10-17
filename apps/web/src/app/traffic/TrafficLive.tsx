"use client";

import { useEffect, useRef, useState } from "react";
import type { CommunitySummary } from "@/lib/community-threats";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-sky-400",
  info: "text-tc-text-dim",
};

const SEVERITY_BG: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-sky-500",
  info: "bg-tc-border",
};

const REFRESH_MS = 15_000;

function num(n: number): string {
  return n.toLocaleString("en-US");
}

function ago(iso: string | null): string {
  if (!iso) return "—";
  const secs = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="rounded-xl border border-tc-border bg-tc-card p-5">
      <div className={`font-mono text-3xl font-bold ${accent ? "text-tc-green glow-green" : "text-tc-text"}`}>{value}</div>
      <div className="mt-1 text-sm text-tc-text-dim">{label}</div>
    </div>
  );
}

export default function TrafficLive({ initial }: { initial: CommunitySummary }) {
  const [data, setData] = useState<CommunitySummary>(initial);
  const [live, setLive] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    let alive = true;
    const pull = async () => {
      try {
        const res = await fetch("/api/traffic/summary.json", { cache: "no-store" });
        if (!res.ok) return;
        const next = (await res.json()) as CommunitySummary;
        if (alive) {
          setData(next);
          setLive(true);
        }
      } catch {
        /* keep the last good snapshot */
      }
    };
    timer.current = setInterval(pull, REFRESH_MS);
    return () => {
      alive = false;
      if (timer.current) clearInterval(timer.current);
    };
  }, []);

  const severities = ["critical", "high", "medium", "low", "info"] as const;
  const sevTotal = severities.reduce((s, k) => s + (data.by_severity[k] ?? 0), 0) || 1;

  return (
    <div className="space-y-10">
      <div className="flex items-center gap-2 text-sm text-tc-text-dim">
        <span className={`inline-block h-2 w-2 rounded-full ${live ? "bg-tc-green animate-pulse" : "bg-tc-border"}`} />
        {live ? "live" : "snapshot"} · updated {ago(data.generated_at)} · last {data.window_hours}h
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        <Stat label="Reports" value={num(data.totals.reports)} accent />
        <Stat label="Unique sources" value={num(data.totals.sources)} />
        <Stat label="Reporters" value={num(data.totals.reporters)} />
        <Stat label="On the blocklist" value={num(data.totals.published)} accent />
        <Stat label="Active bans" value={num(data.totals.active_bans)} />
      </div>

      {/* Severity distribution */}
      <section>
        <h2 className="mb-3 text-lg font-semibold text-tc-text">By severity</h2>
        <div className="flex h-3 overflow-hidden rounded-full border border-tc-border">
          {severities.map((k) => {
            const pct = ((data.by_severity[k] ?? 0) / sevTotal) * 100;
            return pct > 0 ? <div key={k} className={SEVERITY_BG[k]} style={{ width: `${pct}%` }} title={`${k}: ${num(data.by_severity[k] ?? 0)}`} /> : null;
          })}
        </div>
        <div className="mt-2 flex flex-wrap gap-4 text-sm">
          {severities.map((k) => (
            <span key={k} className={SEVERITY_CLASS[k]}>
              {k} · {num(data.by_severity[k] ?? 0)}
            </span>
          ))}
        </div>
      </section>

      <div className="grid gap-8 lg:grid-cols-2">
        {/* Top sources (masked) */}
        <section>
          <h2 className="mb-3 text-lg font-semibold text-tc-text">Most-reported sources</h2>
          <div className="overflow-hidden rounded-xl border border-tc-border">
            <table className="w-full text-sm">
              <thead className="bg-tc-card text-left text-tc-text-dim">
                <tr>
                  <th className="px-4 py-2 font-medium">Network</th>
                  <th className="px-4 py-2 font-medium">Reports</th>
                  <th className="px-4 py-2 font-medium">Reporters</th>
                  <th className="px-4 py-2 font-medium">Severity</th>
                  <th className="px-4 py-2 font-medium">Last</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-tc-border">
                {data.top_sources.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-tc-text-dim">No activity in the window.</td>
                  </tr>
                ) : (
                  data.top_sources.map((s) => (
                    <tr key={s.ip} className="bg-tc-darker/40">
                      <td className="px-4 py-2 font-mono text-tc-text">{s.ip}</td>
                      <td className="px-4 py-2">{num(s.reports)}</td>
                      <td className="px-4 py-2">{num(s.reporters)}</td>
                      <td className={`px-4 py-2 ${SEVERITY_CLASS[s.severity] ?? ""}`}>{s.severity}</td>
                      <td className="px-4 py-2 text-tc-text-dim">{ago(s.last_seen)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-xs text-tc-text-dim">Host octet hidden. Full addresses are in the key-gated blocklist feed.</p>
        </section>

        {/* Top rules */}
        <section>
          <h2 className="mb-3 text-lg font-semibold text-tc-text">Top detections</h2>
          <div className="overflow-hidden rounded-xl border border-tc-border">
            <table className="w-full text-sm">
              <thead className="bg-tc-card text-left text-tc-text-dim">
                <tr>
                  <th className="px-4 py-2 font-medium">Rule</th>
                  <th className="px-4 py-2 font-medium">Count</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-tc-border">
                {data.top_rules.length === 0 ? (
                  <tr>
                    <td colSpan={2} className="px-4 py-6 text-center text-tc-text-dim">No detections in the window.</td>
                  </tr>
                ) : (
                  data.top_rules.map((r) => (
                    <tr key={r.rule_id} className="bg-tc-darker/40">
                      <td className="px-4 py-2 text-tc-text">
                        {r.title}
                        <span className="ml-2 font-mono text-xs text-tc-text-dim">{r.rule_id}</span>
                      </td>
                      <td className="px-4 py-2">{num(r.count)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
