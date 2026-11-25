"use client";

import { useState } from "react";

type PortState = "open" | "closed" | "stealth";
interface PortResult { port: number; name: string; state: PortState }
interface ScanResult {
  target: string;
  test: string;
  total: number;
  open: number;
  closed: number;
  stealth: number;
  grade: "stealth" | "good" | "warning" | "danger";
  verdict: string;
  ports: PortResult[];
  error?: string;
}

const TESTS = [
  { id: "common", label: "Common Ports", hint: "34 most-targeted service ports" },
  { id: "file-sharing", label: "File Sharing", hint: "NetBIOS / SMB (135–139, 445)" },
  { id: "all", label: "All Service Ports", hint: "TCP 0–1055 (1056 ports)" },
] as const;

const GRADE_COLOR: Record<ScanResult["grade"], string> = {
  stealth: "text-tc-green",
  good: "text-tc-green",
  warning: "text-yellow-400",
  danger: "text-red-500",
};

const STATE_COLOR: Record<PortState, string> = {
  open: "bg-red-500",
  closed: "bg-yellow-400",
  stealth: "bg-tc-border",
};

export default function ShieldsPage() {
  const [test, setTest] = useState<string>("common");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/shields", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ test }),
      });
      const data = (await res.json()) as ScanResult;
      if (!res.ok) {
        setError(data.error ?? "Scan failed");
      } else {
        setResult(data);
      }
    } catch {
      setError("Could not reach the Shields service. Try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="pt-24 pb-20 min-h-screen bg-tc-darker">
      <section className="mx-auto max-w-3xl px-6">
        <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">{"// FIREWALL SELF-TEST"}</p>
        <h1 className="text-4xl sm:text-5xl font-black text-white mb-4">
          Shields <span className="text-tc-green">port exposure test</span>
        </h1>
        <p className="text-tc-text-dim mb-2">
          We connect to the ports of <strong className="text-white">your own connection</strong> from the
          outside and report whether each one is open, closed, or fully stealthed — the way a classic firewall
          self-test works.
        </p>
        <p className="text-xs text-tc-text-dim mb-8">
          Shields only ever tests the public IP you are connecting from. It cannot scan anyone else. Inspired by
          GRC&apos;s ShieldsUP!; this is an independent service, not affiliated with or endorsed by GRC.
        </p>

        <div className="rounded-2xl border border-tc-border bg-tc-card p-6">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-5">
            {TESTS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTest(t.id)}
                disabled={loading}
                className={`rounded-xl border p-4 text-left transition-all ${
                  test === t.id
                    ? "border-tc-green bg-tc-green/10"
                    : "border-tc-border hover:border-tc-green/50"
                }`}
              >
                <div className="font-bold text-white text-sm">{t.label}</div>
                <div className="text-xs text-tc-text-dim mt-1">{t.hint}</div>
              </button>
            ))}
          </div>
          <button
            onClick={run}
            disabled={loading}
            className="w-full rounded-xl bg-tc-green px-6 py-4 text-lg font-bold text-black transition-all hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Probing your ports…" : "Test my firewall"}
          </button>
        </div>

        {error && (
          <div className="mt-6 rounded-xl border border-red-500/40 bg-red-500/5 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {result && (
          <div className="mt-6 rounded-2xl border border-tc-border bg-tc-card p-6">
            <div className="flex items-center justify-between flex-wrap gap-2 mb-4">
              <div>
                <div className="text-xs text-tc-text-dim">Your IP</div>
                <div className="font-mono text-white">{result.target}</div>
              </div>
              <div className={`text-2xl font-black ${GRADE_COLOR[result.grade]}`}>
                {result.grade.toUpperCase()}
              </div>
            </div>
            <p className="text-sm text-tc-text-dim mb-5">{result.verdict}</p>

            <div className="flex gap-4 text-sm mb-5">
              <span className="text-red-400">● {result.open} open</span>
              <span className="text-yellow-400">○ {result.closed} closed</span>
              <span className="text-tc-text-dim">· {result.stealth} stealth</span>
              <span className="text-tc-text-dim ml-auto">{result.total} tested</span>
            </div>

            <div className="flex flex-wrap gap-1.5">
              {result.ports.map((p) => (
                <span
                  key={p.port}
                  title={`${p.port}${p.name ? ` ${p.name}` : ""} — ${p.state}`}
                  className={`inline-block h-3 w-3 rounded-sm ${STATE_COLOR[p.state]}`}
                />
              ))}
            </div>

            {result.open > 0 && (
              <ul className="mt-5 space-y-1 text-sm">
                {result.ports.filter((p) => p.state === "open").map((p) => (
                  <li key={p.port} className="text-red-300">
                    <span className="font-mono">TCP {p.port}</span>
                    {p.name ? ` (${p.name})` : ""} is OPEN — reachable from the Internet
                  </li>
                ))}
              </ul>
            )}

            <p className="mt-5 text-xs text-tc-text-dim">
              Want this on a schedule across your whole fleet, or from the terminal? Run{" "}
              <code className="text-tc-green">threatcrush shields</code> — it ships free in the ThreatCrush CLI.
            </p>
          </div>
        )}
      </section>
    </main>
  );
}
