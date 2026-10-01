import type { Metadata } from "next";
import { headers } from "next/headers";
import Link from "next/link";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Intrusion detected. Stand by for countermeasures. — ThreatCrush",
  description:
    "This server is protected by ThreatCrush. Attacks are blocked on first detection and every return doubles the ban.",
  robots: { index: false, follow: true },
};

/**
 * What an attacker (or the human behind an attacking agent) sees when they
 * follow a ThreatCrush block back to its source. Honest copy only: the request
 * was logged and the address blocked. "Countermeasures" means defending, never
 * retaliating.
 */

// `?reason=` is passed by the blocking side. Only known values are shown, so
// the page can never be made to display arbitrary text.
const REASONS: Record<string, string> = {
  path_traversal: "Path traversal",
  rce: "Remote code execution probe",
  sqli: "SQL injection",
  xss: "Cross-site scripting",
  scanner: "Vulnerability scanner",
  exploit: "Exploit probe",
  ssh: "SSH brute force",
  port_scan: "Port scan",
  scraper: "Paywall scraping",
};

function clientIp(h: Headers): string | null {
  const real = h.get("x-real-ip")?.trim();
  if (real) return real;
  const first = h.get("x-forwarded-for")?.split(",")[0]?.trim();
  return first || null;
}

function isIp(value: string | null): value is string {
  return Boolean(value) && /^[0-9a-fA-F:.]{3,45}$/.test(value!);
}

const LADDER = ["5m", "10m", "20m", "40m", "1h 20m", "2h 40m", "5h 20m", "10h 40m", "21h 20m", "…", "7 days"];

export default async function CaughtPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const h = await headers();
  const ip = clientIp(h);
  const params = await searchParams;
  const reasonKey = typeof params.reason === "string" ? params.reason : "";
  const reason = REASONS[reasonKey] ?? null;
  const when = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      {/* The warning */}
      <section className="border-b border-red-500/30 bg-gradient-to-b from-red-950/60 to-tc-darker">
        <div className="mx-auto max-w-4xl px-4 py-16 sm:py-24 text-center">
          <p className="inline-flex items-center gap-2 rounded-full border border-red-500/50 bg-red-500/10 px-4 py-1 text-xs font-bold uppercase tracking-[0.3em] text-red-400">
            <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" aria-hidden />
            Intrusion detected
          </p>
          <h1 className="mt-6 text-4xl font-black tracking-tight text-white sm:text-6xl font-mono">
            We are now tracking you.
          </h1>
          <p className="mt-4 text-2xl font-bold text-red-400 sm:text-3xl font-mono">
            Stand by for countermeasures<span className="animate-pulse">_</span>
          </p>

          <dl className="mx-auto mt-10 grid max-w-2xl gap-px overflow-hidden rounded-xl border border-red-500/30 bg-red-500/20 text-left font-mono text-sm sm:grid-cols-2">
            <div className="bg-tc-darker p-4">
              <dt className="text-xs uppercase tracking-wider text-tc-text-dim">Source</dt>
              <dd className="mt-1 text-white">{isIp(ip) ? ip : "recorded"}</dd>
            </div>
            <div className="bg-tc-darker p-4">
              <dt className="text-xs uppercase tracking-wider text-tc-text-dim">Logged at</dt>
              <dd className="mt-1 text-white">{when}</dd>
            </div>
            <div className="bg-tc-darker p-4">
              <dt className="text-xs uppercase tracking-wider text-tc-text-dim">Detected</dt>
              <dd className="mt-1 text-white">{reason ?? "Attack signature match"}</dd>
            </div>
            <div className="bg-tc-darker p-4">
              <dt className="text-xs uppercase tracking-wider text-tc-text-dim">Status</dt>
              <dd className="mt-1 text-red-400">Blocked. Every return doubles the ban.</dd>
            </div>
          </dl>

          <p className="mx-auto mt-8 max-w-2xl text-sm text-tc-text-dim">
            The first ban is 5 minutes. Come back and it is 10, then 20, then 40, all the way to 7 days.
            Offences are remembered for 30 days, so waiting it out does not reset anything.
          </p>
          <ol className="mx-auto mt-4 flex max-w-3xl flex-wrap justify-center gap-2 font-mono text-xs" aria-label="Ban length by offence">
            {LADDER.map((step, i) => (
              <li key={step + i} className="rounded border border-red-500/30 px-2 py-1 text-red-300" style={{ opacity: 0.45 + (i / LADDER.length) * 0.55 }}>
                {step}
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* The pitch */}
      <section className="mx-auto max-w-4xl px-4 py-16">
        <p className="text-sm font-bold uppercase tracking-widest text-tc-green">Impressed? Good.</p>
        <h2 className="mt-2 text-3xl font-bold text-white sm:text-4xl">
          This server is protected by ThreatCrush. Yours could be too.
        </h2>
        <p className="mt-4 max-w-2xl text-lg text-tc-text-dim">
          Whoever pointed that scanner here, you clearly run servers. ThreatCrush is the agent that just stopped you:
          it reads the logs, spots attacks as they happen, and bans the source on the first hit.
        </p>

        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {[
            ["First hit, banned", "Path traversal, RCE probes, scanners, SSH guessing and port scans are banned on first detection, not after a threshold."],
            ["Comes back? Doubled.", "Each repeat offence doubles the ban, up to 7 days. 222 bans across 132 addresses in 75 minutes on one of our servers."],
            ["Fix prompts for your AI", "Every open hardening finding as a prompt your AI agent can work through, or a private report it can read."],
          ].map(([title, body]) => (
            <div key={title} className="rounded-xl border border-tc-border bg-tc-card p-5">
              <h3 className="font-bold text-white">{title}</h3>
              <p className="mt-2 text-sm text-tc-text-dim">{body}</p>
            </div>
          ))}
        </div>

        <div className="mt-10 rounded-xl border border-tc-green/30 bg-tc-card p-6">
          <p className="text-sm text-tc-text-dim">Install it on a Linux server in one line:</p>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-tc-darker p-4 font-mono text-sm text-tc-green">
            curl -fsSL https://threatcrush.com/install.sh | sh
          </pre>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/auth/signup?next=/dashboard" className="rounded-lg bg-tc-green px-5 py-3 font-bold text-black hover:bg-tc-green-dim">
              Protect your servers
            </Link>
            <Link href="/blog/attack-us-we-double-your-ban" className="rounded-lg border border-tc-border px-5 py-3 font-bold text-tc-text hover:border-tc-green">
              How we caught you
            </Link>
            <Link href="/" className="rounded-lg px-5 py-3 font-bold text-tc-text-dim hover:text-tc-green">
              What is ThreatCrush?
            </Link>
          </div>
        </div>

        <p className="mt-10 text-xs text-tc-text-dim">
          If you are a legitimate user and think this is a mistake, the block expires on its own. Contact the site owner
          and include the source and time above.
        </p>
      </section>
    </main>
  );
}
