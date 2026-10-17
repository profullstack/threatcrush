import type { Metadata } from "next";
import Link from "next/link";
import { loadCommunitySummary, type CommunitySummary } from "@/lib/community-threats";
import TrafficLive from "./TrafficLive";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Live threat traffic — the ThreatCrush community blocklist",
  description:
    "A crowdsourced reputation feed: attack sources reported by every ThreatCrush daemon on the fleet, aggregated and corroborated. Free blocklist feed for fail2ban, nftables and ipset.",
};

const EMPTY: CommunitySummary = {
  generated_at: new Date(0).toISOString(),
  window_hours: 168,
  totals: { reports: 0, sources: 0, reporters: 0, active_bans: 0, published: 0 },
  by_severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
  top_rules: [],
  top_sources: [],
};

export default async function TrafficPage() {
  let initial: CommunitySummary;
  try {
    initial = await loadCommunitySummary();
  } catch {
    initial = EMPTY;
  }

  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <section className="border-b border-tc-border bg-gradient-to-b from-tc-dark to-tc-darker">
        <div className="mx-auto max-w-5xl px-4 py-14 sm:py-20">
          <p className="font-mono text-sm text-tc-green">// community threat feed</p>
          <h1 className="mt-3 text-3xl font-bold text-tc-text sm:text-4xl">Live threat traffic across the fleet</h1>
          <p className="mt-4 max-w-2xl text-tc-text-dim">
            Every ThreatCrush daemon reports the attacks it blocks. This is the pooled, corroborated result — our own
            reputation feed. An address only appears once independent reporters agree, so one noisy box can&apos;t get
            anyone listed.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-4 py-12">
        <TrafficLive initial={initial} />
      </section>

      {/* Contribute + consume */}
      <section className="border-t border-tc-border bg-tc-dark">
        <div className="mx-auto grid max-w-5xl gap-8 px-4 py-14 md:grid-cols-2">
          <div>
            <h2 className="text-xl font-semibold text-tc-text">Contribute</h2>
            <p className="mt-2 text-tc-text-dim">
              Install ThreatCrush and link the box. Submission is automatic and on by default — the detections it blocks
              feed the community feed. Nothing you host is exposed; only corroborated attacker addresses are published,
              with the host octet hidden on this page.
            </p>
            <pre className="mt-4 overflow-x-auto rounded-lg border border-tc-border bg-tc-darker p-4 font-mono text-sm text-tc-green">
{`curl -fsSL https://threatcrush.com/install.sh | sh
threatcrush login
threatcrush servers link`}
            </pre>
          </div>

          <div>
            <h2 className="text-xl font-semibold text-tc-text">Consume the blocklist</h2>
            <p className="mt-2 text-tc-text-dim">
              The full-IP feed is free with a ThreatCrush API key — drop it straight into fail2ban, nftables or ipset.
            </p>
            <pre className="mt-4 overflow-x-auto rounded-lg border border-tc-border bg-tc-darker p-4 font-mono text-sm text-tc-green">
{`curl -H "Authorization: Bearer tc_agent_…" \\
  https://threatcrush.com/api/traffic/blocklist.txt`}
            </pre>
            <p className="mt-3 text-sm text-tc-text-dim">
              Masked summary (no key):{" "}
              <Link href="/api/traffic/summary.json" className="text-tc-green hover:underline">
                /api/traffic/summary.json
              </Link>
            </p>
            <Link
              href="/register"
              className="mt-4 inline-block rounded-lg bg-tc-green px-5 py-3 font-bold text-black hover:bg-tc-green-dim"
            >
              Get an API key
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}
