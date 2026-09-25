"use client";

import { useState } from "react";
import { serializeJsonForHtml } from "@/lib/safe-json";
import ScrollReveal from "@/components/ScrollReveal";
import WaitlistModal from "@/components/WaitlistModal";

/* ─── Feature data ─── */
const features = [
  {
    icon: "🔍",
    title: "Live Attack Detection",
    desc: "Reads your nginx, auth, syslog and journald logs and watches inbound connections to the ports you serve. Every nginx request is scored against the OWASP Core Rule Set (paranoia level 1, with libinjection for SQLi and XSS) — SQLi, XSS, path traversal, RFI, RCE — alongside SSH brute force, sudo abuse, port scan, SYN flood and DNS tunneling detection. Add your own JSON rules in /etc/threatcrush/rules.d.",
  },
  {
    icon: "🛡️",
    title: "Code Security Scanner",
    desc: "Scan a codebase for hardcoded secrets and risky code patterns, and with --deps check lockfile versions against OSV.dev advisories. Text, JSON or SARIF output, with --fail-on for CI.",
  },
  {
    icon: "💥",
    title: "Pentest Checks",
    desc: "Point it at a URL: security headers, CSP, CORS, cookie flags, server banners, directory listings and error leaks, then SQL-error, path-traversal and unsafe-HTTP-method probes. Every finding rated by severity.",
  },
  {
    icon: "🔀",
    title: "Network Monitor",
    desc: "Polls the kernel's connection table (conntrack / ss) every 5 seconds for inbound TCP connections to the ports you actually serve. Flags port scans and SYN floods — and ignores your own outbound traffic, so your upstreams never get banned.",
  },
  {
    icon: "🚫",
    title: "Automatic IP Bans",
    desc: "When a rule fires, the daemon bans the source IP through nftables, iptables or fail2ban. Repeat offenders get longer bans each time. Allowlisted ranges and verified Google and Bing crawlers are never auto-banned; block and unblock by hand with the CLI or the dashboard.",
  },
  {
    icon: "🧱",
    title: "Hardening Checks",
    desc: "threatcrush harden checks SSH password and root login, sshd weaknesses, automatic security updates, an active firewall, risky exposed ports and fail2ban, and tells you what to fix.",
  },
  {
    icon: "🔔",
    title: "Alerts",
    desc: "Email, Slack, Discord, PagerDuty and webhook notifications when a threat is detected. Web and mobile push for servers linked to the dashboard, where enabled.",
  },
  {
    icon: "📊",
    title: "Cloud Dashboard",
    desc: "Run threatcrush servers link and the daemon sends detections, hardening findings, bans and heartbeats to your organization's dashboard, where you can review them and ban or unban IPs.",
  },
  {
    icon: "⚙️",
    title: "systemd Daemon",
    desc: "Runs as a background service on your server. Starts on boot and monitors 24/7. Detection and banning run on the host and work without the cloud.",
  },
];

const faqs = [
  {
    q: "What does \"Lifetime Access\" mean?",
    a: "Pay once, access forever. No subscriptions, no renewals. You get the full ThreatCrush platform — CLI, daemon, scanner, pentest engine, API — and all future updates for life.",
  },
  {
    q: "Can I use it today?",
    a: "Yes. The CLI and daemon are open source (MIT) and install with one command. The cloud dashboard and desktop app are in beta, the browser extension is a dev preview, and the mobile app is in development. Join the waitlist to hear about each release.",
  },
  {
    q: "What servers does it support?",
    a: "Any Linux server. ThreatCrush reads your nginx, SSH (auth.log), syslog and journald logs, and watches inbound connections to the ports you serve — not just web traffic. `threatcrush init` detects SSH, nginx, Apache, PostgreSQL, MySQL, Redis and BIND and writes a config for them.",
  },
  {
    q: "What payment methods do you accept?",
    a: "Credit/debit cards (processed by Stripe through CoinPayPortal), and cryptocurrency (BTC, ETH, USDT, SOL, and more) via CoinPayPortal.",
  },
  {
    q: "Can I get a refund?",
    a: "Yes. If you're not satisfied within 30 days of getting access, we'll refund your payment in full. No questions asked.",
  },
  {
    q: "Do you work with government agencies?",
    a: "Talk to us at gov@threatcrush.com about your requirements. The agent runs entirely on your own servers, and detection and banning work without the cloud dashboard.",
  },
];

const included = [
  "Live attack detection & automatic IP bans",
  "Code vulnerability scanner",
  "Pentest checks for your URLs",
  "Network monitor — port scans & SYN floods",
  "Host hardening checks",
  "Email, Slack, Discord, PagerDuty + webhook alerts",
  "Cloud dashboard for linked servers",
  "systemd daemon — runs 24/7",
  "CLI, TUI & desktop app (mobile in development)",
  "All core modules + future updates",
];

const stripHtml = (s: string) => s.replace(/<[^>]*>/g, "");

const faqJsonLd = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: faqs.map((f) => ({
    "@type": "Question",
    name: f.q,
    acceptedAnswer: {
      "@type": "Answer",
      text: stripHtml(f.a),
    },
  })),
};

export default function Home() {
  const [modalOpen, setModalOpen] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const openModal = () => setModalOpen(true);

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(faqJsonLd) }}
      />
      <WaitlistModal open={modalOpen} onClose={() => setModalOpen(false)} />

      <main>
        {/* ─── HERO ─── */}
        <section className="relative min-h-screen flex items-center justify-center overflow-hidden matrix-bg grid-pattern scanlines">
          {/* Decorative gradient orbs */}
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-tc-green/5 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-tc-green/3 rounded-full blur-3xl" />

          <div className="relative z-10 mx-auto w-full min-w-0 max-w-4xl px-6 text-center pt-28 sm:pt-24">
            <ScrollReveal>
              <div className="inline-block rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-1.5 text-sm font-mono text-tc-green mb-8">
                <span className="mr-2">●</span> PRIVATE BETA — LIMITED SPOTS
              </div>
            </ScrollReveal>

            <ScrollReveal delay={100}>
              <h1 className="text-5xl sm:text-6xl md:text-7xl font-black tracking-tight mb-6">
                <span className="text-tc-green glow-green-strong">Crush Every Threat</span>
                <br />
                <span className="text-white">Before It Crushes You</span>
              </h1>
            </ScrollReveal>

            <ScrollReveal delay={200}>
              <p className="mx-auto max-w-3xl text-lg sm:text-xl text-tc-text-dim mb-6 leading-relaxed">
                One open-source agent for your Linux servers. It watches your logs and inbound connections for attacks, <span className="text-tc-green">bans attackers at the firewall</span>, checks host hardening, scans your code and spot-checks your URLs.
              </p>
              <p className="mx-auto max-w-2xl text-base sm:text-lg text-tc-text-dim mb-6 leading-relaxed">
                Link a server to the <span className="text-tc-green">cloud dashboard</span> to see its detections, findings and bans next to the rest of your organization, and get alerts where your team already is.
              </p>
              <a
                href="/read/ctem-guide"
                className="inline-flex items-center gap-2 text-sm font-mono text-tc-green hover:underline mb-10"
              >
                <span>📄</span> Free guide: Evolving from VM to CTEM →
              </a>
            </ScrollReveal>

            <ScrollReveal delay={300}>
              <div className="mx-auto max-w-2xl mb-10">
                {/* Main install command */}
                <div className="rounded-xl border border-tc-green/20 bg-tc-card/60 p-6 backdrop-blur-md">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-tc-green text-lg">⚡</span>
                    <span className="text-sm font-semibold text-tc-text">Get started in one line</span>
                  </div>
                  <div className="group relative rounded-lg bg-black/60 border border-tc-border px-5 py-4 font-mono text-base cursor-pointer transition-all hover:border-tc-green/40"
                    onClick={() => { navigator.clipboard?.writeText('curl -fsSL https://threatcrush.com/install.sh | sh'); }}
                  >
                    <span className="text-tc-text-dim">$ </span>
                    <span className="text-tc-green break-all">curl -fsSL https://threatcrush.com/install.sh | sh</span>
                    <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs opacity-0 group-hover:opacity-100 transition-opacity bg-black/90 border border-tc-border/60 rounded px-2 py-0.5 shadow">📋 click to copy</span>
                  </div>
                  <div className="mt-3 text-left">
                    <a href="/docs" className="text-xs font-semibold text-tc-green hover:underline">
                      Read the docs →
                    </a>
                  </div>

                  {/* Install notes */}
                  <div className="mt-4 pt-4 border-t border-tc-border/50 space-y-3 text-left">
                    <div>
                      <p className="text-xs font-semibold text-tc-text">Preferred install path</p>
                      <p className="text-xs text-tc-text-dim mt-1">
                        The installer detects whether this machine is a <span className="text-tc-green">server</span> or <span className="text-tc-green">desktop</span>, uses your existing package manager when available,
                        and can bootstrap Node.js with <span className="text-tc-green">mise</span> on bare machines.
                      </p>
                      <p className="text-xs text-tc-text-dim mt-2">
                        Linux servers get the CLI. On desktops (Linux, macOS, Windows) it installs the CLI and points you to the desktop app, a separate download that talks to a ThreatCrush daemon on the same machine; log monitoring and firewall bans need Linux.
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold text-tc-text">Preferred lifecycle commands</p>
                      <div className="space-y-2 mt-2">
                        <div
                          className="group relative rounded-lg bg-black/60 border border-tc-border px-4 py-3 font-mono text-sm cursor-pointer transition-all hover:border-tc-green/40"
                          onClick={() => { navigator.clipboard?.writeText('threatcrush update'); }}
                        >
                          <span className="text-tc-green">threatcrush update</span>
                          <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs opacity-0 group-hover:opacity-100 transition-opacity bg-black/90 border border-tc-border/60 rounded px-2 py-0.5 shadow">📋 click to copy</span>
                        </div>
                        <div
                          className="group relative rounded-lg bg-black/60 border border-tc-border px-4 py-3 font-mono text-sm cursor-pointer transition-all hover:border-tc-green/40"
                          onClick={() => { navigator.clipboard?.writeText('threatcrush remove'); }}
                        >
                          <span className="text-tc-green">threatcrush remove</span>
                          <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs opacity-0 group-hover:opacity-100 transition-opacity bg-black/90 border border-tc-border/60 rounded px-2 py-0.5 shadow">📋 click to copy</span>
                        </div>
                      </div>
                    </div>
                    <p className="text-xs text-tc-text-dim">
                      Manual npm / pnpm / yarn / bun installs still work, but <span className="text-tc-green">curl | sh</span> is the recommended default.
                    </p>
                  </div>
                </div>
              </div>
            </ScrollReveal>

            <ScrollReveal delay={400}>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <a
                  href="/store"
                  className="rounded-xl bg-tc-green px-8 py-4 text-lg font-bold text-black transition-all hover:bg-tc-green-dim pulse-glow"
                >
                  Explore Module Store
                </a>
                <a
                  href="/store/publish"
                  className="rounded-xl border border-tc-green/30 px-8 py-4 text-lg font-medium text-tc-green transition-all hover:bg-tc-green/10"
                >
                  Publish a Module
                </a>
                <button
                  onClick={openModal}
                  className="rounded-xl border border-tc-border px-8 py-4 text-lg font-medium text-tc-text-dim transition-all hover:border-tc-green/30 hover:text-tc-text"
                >
                  Join the Waitlist
                </button>
              </div>
            </ScrollReveal>

            <ScrollReveal delay={500}>
              <p className="mt-6 text-sm text-tc-text-dim">
                The CLI and daemon are open source (MIT). The cloud dashboard and desktop app are in beta; the browser extension is a dev preview.
              </p>
            </ScrollReveal>

            {/* CLI screenshot */}
            <ScrollReveal delay={500}>
              <div className="mt-16 mx-auto max-w-2xl">
                <img
                  src="/images/gallery-cli.png"
                  alt="ThreatCrush CLI"
                  className="w-full shadow-2xl shadow-tc-green/5"
                />
              </div>
            </ScrollReveal>
          </div>
        </section>

        {/* ─── INVESTORS CTA ─── */}
        <section className="py-12">
          <div className="mx-auto max-w-4xl px-6">
            <ScrollReveal>
              <a
                href="/investors"
                className="group flex flex-col sm:flex-row items-center justify-between gap-4 rounded-2xl border border-tc-green/30 bg-tc-card px-6 py-6 transition-all hover:border-tc-green hover:bg-tc-green/5 glow-box-hover"
              >
                <div>
                  <p className="font-mono text-xs text-tc-green tracking-wider">// INVEST</p>
                  <h3 className="mt-1 text-xl font-bold text-white">
                    Back ThreatCrush — <span className="text-tc-green glow-green">become a founding investor</span>
                  </h3>
                  <p className="mt-1 text-sm text-tc-text-dim">
                    Contribute via credit card or crypto. Live progress + recent backers at threatcrush.com/investors.
                  </p>
                </div>
                <span className="rounded-lg border border-tc-green/40 bg-tc-green/10 px-5 py-3 text-sm font-bold text-tc-green group-hover:bg-tc-green/20 whitespace-nowrap">
                  Invest now →
                </span>
              </a>
            </ScrollReveal>
          </div>
        </section>

        {/* ─── FEATURES ─── */}
        <section id="features" className="py-24 sm:py-32">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// CAPABILITIES</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  Everything You Need to <span className="text-tc-green glow-green">Stay Ahead</span>
                </h2>
              </div>
            </ScrollReveal>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {features.map((f, i) => (
                <ScrollReveal key={f.title} delay={i * 100}>
                  <div className="group rounded-xl border border-tc-border bg-tc-card p-6 transition-all hover:border-tc-green/30 glow-box-hover h-full">
                    <div className="text-3xl mb-4">{f.icon}</div>
                    <h3 className="text-lg font-bold text-white mb-2 group-hover:text-tc-green transition-colors">
                      {f.title}
                    </h3>
                    <p className="text-sm text-tc-text-dim leading-relaxed">
                      {f.desc}
                    </p>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ─── CTEM LOOP ─── */}
        <section id="ctem" className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// THE CTEM LOOP</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  Built for <span className="text-tc-green glow-green">Continuous Threat Exposure Management</span>
                </h2>
                <p className="mt-4 max-w-3xl mx-auto text-tc-text-dim leading-relaxed">
                  CTEM is a five-stage loop — scope, discover, prioritize, validate, mobilize — that replaces the periodic-scan-and-ticket cycle. Here is what ThreatCrush does at each stage today.
                </p>
              </div>
            </ScrollReveal>

            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-12">
              {[
                { n: "01", t: "Scope", d: "Add the servers, URLs, APIs, domains and repos you care about to an organization." },
                { n: "02", t: "Discover", d: "Log and inbound-connection monitoring, hardening checks, code scanning and pentest checks." },
                { n: "03", t: "Prioritize", d: "Every detection and finding carries a severity, from critical to info." },
                { n: "04", t: "Validate", d: "Re-run scans and pentest checks against a target after you fix it." },
                { n: "05", t: "Mobilize", d: "Alerts to email, Slack, Discord, PagerDuty and webhooks, automatic IP bans, and bans from the dashboard." },
              ].map((s, i) => (
                <ScrollReveal key={s.n} delay={i * 80}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-5 h-full">
                    <div className="font-mono text-xs text-tc-green mb-2">{s.n}</div>
                    <h3 className="text-lg font-bold text-white mb-2">{s.t}</h3>
                    <p className="text-sm text-tc-text-dim leading-relaxed">{s.d}</p>
                  </div>
                </ScrollReveal>
              ))}
            </div>

          </div>
        </section>

        {/* ─── DETECT & RESPOND LAYER ─── */}
        <section id="detect-respond" className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// DETECT AND RESPOND</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  CTEM finds the gaps. <span className="text-tc-green glow-green">The daemon</span> catches what slips through.
                </h2>
                <p className="mt-4 max-w-3xl mx-auto text-tc-text-dim leading-relaxed">
                  CTEM is preventive — it reduces exposures before incidents. Detection and response is reactive — it acts when attackers do. ThreatCrush does both from the same agent.
                </p>
              </div>
            </ScrollReveal>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
              {[
                {
                  tag: "DETECT",
                  title: "Watches logs and connections",
                  desc: "Tails nginx, auth, syslog and journald and watches inbound connections and DNS traffic. Built-in rules catch web attacks, SSH brute force and user enumeration, sudo abuse, port scans and SYN floods.",
                  capabilities: [
                    "Log + inbound-connection monitor",
                    "OWASP CRS web rules + libinjection",
                    "Custom JSON rules",
                  ],
                },
                {
                  tag: "RESPOND",
                  title: "Bans at the firewall",
                  desc: "The systemd daemon runs on each server. When a rule fires it bans the source IP with nftables, iptables or fail2ban, and bans repeat offenders for longer each time.",
                  capabilities: [
                    "On-host daemon agent",
                    "Automatic, escalating IP bans",
                    "Allowlist + crawler protection",
                  ],
                },
                {
                  tag: "ALERT",
                  title: "Alerts operators read",
                  desc: "Alerts to email, Slack, Discord, PagerDuty and webhooks from the daemon. Linked servers also show up in the cloud dashboard, with org-wide alert destinations.",
                  capabilities: [
                    "Multi-channel alerting",
                    "Cloud dashboard for linked servers",
                    "Generic webhooks for your own tooling",
                  ],
                },
              ].map((c, i) => (
                <ScrollReveal key={c.tag} delay={i * 120}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-6 h-full transition-all hover:border-tc-green/30 glow-box-hover">
                    <div className="inline-block rounded-md border border-tc-green/30 bg-tc-green/10 px-2.5 py-0.5 text-xs font-mono text-tc-green tracking-wider mb-3">
                      {c.tag}
                    </div>
                    <h3 className="text-xl font-bold text-white mb-2">{c.title}</h3>
                    <p className="text-sm text-tc-text-dim leading-relaxed mb-4">{c.desc}</p>
                    <ul className="space-y-1.5">
                      {c.capabilities.map((cap) => (
                        <li key={cap} className="flex items-start gap-2 text-xs text-tc-text">
                          <span className="text-tc-green flex-shrink-0">▸</span>
                          <span>{cap}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </ScrollReveal>
              ))}
            </div>

            <ScrollReveal delay={400}>
              <div className="rounded-xl border border-tc-border bg-tc-card/40 p-5 text-center">
                <p className="text-sm text-tc-text-dim">
                  <span className="text-tc-green font-semibold">Works alongside what you already have.</span>{" "}
                  Integration points today are webhooks for alerts, SARIF from <code className="rounded bg-tc-darker px-1.5 py-0.5 text-tc-green">threatcrush scan</code> for code-scanning tools, and JSON output from the CLI.
                </p>
              </div>
            </ScrollReveal>
          </div>
        </section>

        {/* ─── FREE GUIDE ─── */}
        <section id="guide" className="py-16 sm:py-20 border-t border-tc-border">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal delay={500}>
              <div className="rounded-2xl border border-tc-green/30 bg-tc-card/60 backdrop-blur-md px-6 py-6 sm:px-8 sm:py-8">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                  <div>
                    <p className="font-mono text-xs text-tc-green tracking-wider mb-1">// FREE GUIDE</p>
                    <h3 className="text-xl sm:text-2xl font-bold text-white">
                      Get the operator&apos;s playbook — CTEM, SIEM/EDR/SOC, and the standards that tie them together
                    </h3>
                    <p className="text-sm text-tc-text-dim mt-1">
                      The 5 CTEM stages · how it maps to ATT&amp;CK, D3FEND, Sigma, OCSF · a 90-day implementation plan · a 27-control readiness checklist that scores your program. Read it here, no signup.
                    </p>
                  </div>
                  <a
                    href="/read/ctem-guide"
                    className="rounded-xl bg-tc-green px-6 py-3 font-bold text-black transition-all hover:bg-tc-green-dim pulse-glow whitespace-nowrap"
                  >
                    Read the guide →
                  </a>
                </div>
              </div>
            </ScrollReveal>
          </div>
        </section>

        {/* ─── MODULE STORE FIRST ─── */}
        <section className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// MODULES</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  The <span className="text-tc-green glow-green">Module Store</span>
                </h2>
                <p className="mt-4 max-w-3xl mx-auto text-tc-text-dim">
                  Discover community modules and publish your own. Publishing a module is free; new listings go live after review.
                </p>
              </div>
            </ScrollReveal>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {[
                {
                  title: "Browse modules",
                  desc: "See what exists today in the marketplace and where the ecosystem is heading.",
                  cta: "Open Store →",
                  href: "/store",
                },
                {
                  title: "Publish your module",
                  desc: "Submit a repo or website URL and we fetch its metadata. Listings go live after review.",
                  cta: "Publish Module →",
                  href: "/store/publish",
                },
                {
                  title: "Read module docs",
                  desc: "Understand contributor expectations, listing quality, required metadata, and what’s still planned.",
                  cta: "Module Docs →",
                  href: "/docs/modules",
                },
              ].map((item, i) => (
                <ScrollReveal key={item.title} delay={i * 100}>
                  <a href={item.href} className="block rounded-xl border border-tc-border bg-tc-card p-6 transition-all hover:border-tc-green/30 glow-box-hover h-full">
                    <h3 className="text-xl font-bold text-white mb-3">{item.title}</h3>
                    <p className="text-sm text-tc-text-dim leading-relaxed mb-5">{item.desc}</p>
                    <span className="text-sm font-semibold text-tc-green">{item.cta}</span>
                  </a>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ─── HOW IT WORKS ─── */}
        <section className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-4xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// SETUP</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  Three Commands to <span className="text-tc-green glow-green">Get Running</span>
                </h2>
              </div>
            </ScrollReveal>

            <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
              {[
                {
                  step: "01",
                  title: "Install",
                  desc: "curl -fsSL https://threatcrush.com/install.sh | sh",
                  subdesc: "Detects server vs desktop, can bootstrap with mise, then installs the right bundle cleanly",
                  icon: "📦",
                },
                {
                  step: "02",
                  title: "Configure",
                  desc: "threatcrush init",
                  subdesc: "Offers to sign you in, detects SSH, nginx, Apache, databases and BIND, and writes a config",
                  icon: "⚙️",
                },
                {
                  step: "03",
                  title: "Run",
                  desc: "sudo threatcrush install-service",
                  subdesc: "Installs the daemon as a systemd service that starts on boot. `threatcrush monitor` runs it in the foreground instead",
                  icon: "🚀",
                },
              ].map((s, i) => (
                <ScrollReveal key={s.step} delay={i * 150}>
                  <div className="flex h-full flex-col items-center rounded-xl border border-tc-border bg-tc-card p-6 text-center">
                    <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full border border-tc-green/30 bg-tc-green/5 text-2xl">
                      {s.icon}
                    </div>
                    <div className="mb-2 font-mono text-sm text-tc-green">{s.step}</div>
                    <h3 className="mb-3 text-xl font-bold text-white">{s.title}</h3>
                    <code className="break-words text-sm font-mono text-tc-green">{s.desc}</code>
                    <p className="mt-3 text-xs leading-relaxed text-tc-text-dim">{s.subdesc}</p>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ─── SCREENSHOTS ─── */}
        <section className="py-24 sm:py-32 border-t border-tc-border overflow-hidden">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// PREVIEW</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  See It in <span className="text-tc-green glow-green">Action</span>
                </h2>
                <p className="mt-4 text-tc-text-dim max-w-xl mx-auto">Real-time security monitoring across every platform.</p>
              </div>
            </ScrollReveal>

            {/* CLI / TUI screenshots */}
            <ScrollReveal delay={0}>
              <div className="mb-16 grid grid-cols-1 md:grid-cols-2 gap-8">
                <div>
                  <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">⚡ CLI</h3>
                  <img
                    src="/images/gallery-cli.png"
                    alt="ThreatCrush CLI"
                    className="w-full shadow-2xl shadow-tc-green/5"
                  />
                </div>
                <div>
                  <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">▣ TUI Dashboard</h3>
                  <img
                    src="/images/gallery-tui.png"
                    alt="ThreatCrush TUI Dashboard"
                    className="w-full shadow-2xl shadow-tc-green/5"
                  />
                </div>
              </div>
            </ScrollReveal>

            {/* Desktop + Mobile side by side */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-8 items-start">
              {/* Desktop screenshot */}
              <ScrollReveal delay={100} className="lg:col-span-3">
                <div>
                  <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">🖥️ Desktop App</h3>
                  <img
                    src="/images/gallery-desktop.png"
                    alt="ThreatCrush Desktop App"
                    className="w-full shadow-2xl shadow-tc-green/5"
                  />
                </div>
              </ScrollReveal>

              {/* Mobile screenshot */}
              <ScrollReveal delay={200} className="lg:col-span-2">
                <div className="flex justify-center">
                  <div className="w-full max-w-[320px]">
                    <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">📱 Mobile App</h3>
                    <img
                      src="/images/gallery-mobile.png"
                      alt="ThreatCrush Mobile App"
                      className="w-full shadow-2xl shadow-tc-green/5"
                    />
                  </div>
                </div>
              </ScrollReveal>
            </div>
          </div>
        </section>

        {/* ─── GET THREATCRUSH ─── */}
        <section className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-5xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// DOWNLOAD</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  Available <span className="text-tc-green glow-green">Everywhere</span>
                </h2>
                <p className="mt-4 text-tc-text-dim max-w-xl mx-auto">Monitor your servers from anywhere — terminal, desktop, or on the go.</p>
              </div>
            </ScrollReveal>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {/* CLI */}
              <ScrollReveal delay={0}>
                <div className="rounded-xl border border-tc-border bg-tc-card/60 p-6 backdrop-blur-sm hover:border-tc-green/30 transition-all h-full">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 rounded-lg bg-tc-green/10 border border-tc-green/20 flex items-center justify-center text-2xl">⚡</div>
                    <div>
                      <h3 className="text-lg font-bold text-white">CLI</h3>
                      <p className="text-xs text-tc-text-dim">Linux servers · desktop clients</p>
                    </div>
                  </div>
                  <p className="text-sm text-tc-text-dim mb-4">The core agent. On Linux servers it runs the monitoring daemon; on any machine it runs code scans and pentest checks and manages your organization.</p>
                  <div className="rounded-lg bg-black/60 border border-tc-border px-3 py-2 font-mono text-xs">
                    <span className="text-tc-text-dim">$ </span>
                    <span className="text-tc-green break-all">curl -fsSL https://threatcrush.com/install.sh | sh</span>
                  </div>
                  <div className="mt-3 flex gap-2">
                    <a href="https://www.npmjs.com/package/@profullstack/threatcrush" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 rounded-lg border border-tc-green/30 bg-tc-green/5 px-3 py-1.5 text-xs font-medium text-tc-green hover:bg-tc-green/10 transition-all">
                      <span>📦</span> npm
                    </a>
                    <a href="https://github.com/profullstack/threatcrush" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs font-medium text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green transition-all">
                      <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
                      Source
                    </a>
                  </div>
                </div>
              </ScrollReveal>

              {/* Desktop */}
              <ScrollReveal delay={100}>
                <div className="rounded-xl border border-tc-border bg-tc-card/60 p-6 backdrop-blur-sm hover:border-tc-green/30 transition-all h-full">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 rounded-lg bg-tc-green/10 border border-tc-green/20 flex items-center justify-center text-2xl">🖥️</div>
                    <div>
                      <h3 className="text-lg font-bold text-white">Desktop</h3>
                      <p className="text-xs text-tc-text-dim">macOS · Windows · Linux</p>
                    </div>
                  </div>
                  <p className="text-sm text-tc-text-dim mb-4">A window onto the daemon running on the same machine: live event stream, loaded security modules and daemon settings, over a local socket.</p>
                  <div className="flex gap-2 flex-wrap">
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🍎 macOS
                    </span>
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🪟 Windows
                    </span>
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🐧 Linux
                    </span>
                  </div>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-yellow-500/30 bg-yellow-500/5 px-2.5 py-0.5 text-[10px] font-medium text-yellow-400 uppercase tracking-wider">
                      Public beta
                    </span>
                    <a
                      href="https://github.com/profullstack/threatcrush/releases/latest"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-tc-text-dim hover:text-tc-green font-mono"
                    >
                      Download →
                    </a>
                  </div>
                  <p className="mt-2 text-[11px] text-tc-text-dim">
                    .dmg (Apple silicon + Intel), Windows x64 installer, AppImage and .deb. macOS and Windows builds are not code-signed yet, so Gatekeeper and SmartScreen block or warn on first launch.
                  </p>
                </div>
              </ScrollReveal>

              {/* Mobile */}
              <ScrollReveal delay={200}>
                <div className="rounded-xl border border-tc-border bg-tc-card/60 p-6 backdrop-blur-sm hover:border-tc-green/30 transition-all h-full">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 rounded-lg bg-tc-green/10 border border-tc-green/20 flex items-center justify-center text-2xl">📱</div>
                    <div>
                      <h3 className="text-lg font-bold text-white">Mobile</h3>
                      <p className="text-xs text-tc-text-dim">iOS · Android</p>
                    </div>
                  </div>
                  <p className="text-sm text-tc-text-dim mb-4">Your organizations, servers, detections and scan results on your phone, with push alerts where enabled.</p>
                  <div className="flex gap-2 flex-wrap">
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🍎 App Store
                    </span>
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🤖 Google Play
                    </span>
                  </div>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-tc-border bg-tc-card/40 px-2.5 py-0.5 text-[10px] font-medium text-tc-text-dim uppercase tracking-wider">
                      In development
                    </span>
                    <a
                      href="#waitlist"
                      className="text-xs text-tc-text-dim hover:text-tc-green font-mono"
                    >
                      Join mobile beta →
                    </a>
                  </div>
                </div>
              </ScrollReveal>

              {/* Browser Extension */}
              <ScrollReveal delay={300}>
                <div className="rounded-xl border border-tc-border bg-tc-card/60 p-6 backdrop-blur-sm hover:border-tc-green/30 transition-all h-full">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 rounded-lg bg-tc-green/10 border border-tc-green/20 flex items-center justify-center text-2xl">🌐</div>
                    <div>
                      <h3 className="text-lg font-bold text-white">Browser Extension</h3>
                      <p className="text-xs text-tc-text-dim">Chrome · Firefox · Edge</p>
                    </div>
                  </div>
                  <p className="text-sm text-tc-text-dim mb-4">Checks the page in the current tab — HTTPS, security headers, CSP, clickjacking, mixed content, forms and cookie flags — entirely in your browser. Signed in, the toolbar badge counts new detections for your organization.</p>
                  <div className="flex gap-2 flex-wrap">
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🔵 Chrome
                    </span>
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🦊 Firefox
                    </span>
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🧭 Safari <span className="text-[10px] text-tc-text-dim">(soon)</span>
                    </span>
                  </div>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-yellow-500/30 bg-yellow-500/5 px-2.5 py-0.5 text-[10px] font-medium text-yellow-400 uppercase tracking-wider">
                      Dev preview
                    </span>
                    <a
                      href="https://github.com/profullstack/threatcrush/tree/master/apps/extension"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-tc-text-dim hover:text-tc-green font-mono"
                    >
                      Sideload from source →
                    </a>
                  </div>
                </div>
              </ScrollReveal>
            </div>

            {/* Transport notice */}
            <ScrollReveal delay={300}>
              <div className="mt-10 text-center">
                <p className="inline-flex items-center gap-2 rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-2 text-sm text-tc-text-dim">
                  <span className="text-tc-green">🔒</span>
                  The desktop app talks to the daemon on the same machine over a local socket. Anything sent to threatcrush.com — such as detections from a linked server — goes over HTTPS.
                </p>
              </div>
            </ScrollReveal>
          </div>
        </section>

        {/* ─── PRICING ─── */}
        <section id="pricing" className="py-24 sm:py-32 border-t border-tc-border matrix-bg">
          <div className="mx-auto max-w-2xl px-6">
            <ScrollReveal>
              <div className="text-center mb-12">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// PRICING</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  One Price. <span className="text-tc-green glow-green">Forever.</span>
                </h2>
              </div>
            </ScrollReveal>

            <ScrollReveal delay={100}>
              <div className="rounded-2xl border border-tc-green/30 bg-tc-card p-8 sm:p-10 glow-box">
                <div className="text-center mb-8">
                  <div className="inline-block rounded-full bg-tc-green/10 px-3 py-1 text-xs font-mono text-tc-green mb-4">
                    CONTACT FOR PRICING
                  </div>
                  <h3 className="text-3xl sm:text-4xl font-black text-white">Talk to Sales</h3>
                  <p className="text-tc-text-dim mt-3">Full platform: CLI, daemon, scanner, pentest engine, API. Tell us about your environment and we&apos;ll send you a quote.</p>
                </div>

                <ul className="space-y-3 mb-8">
                  {included.map((item) => (
                    <li key={item} className="flex items-center gap-3 text-sm text-tc-text">
                      <span className="text-tc-green">✓</span>
                      {item}
                    </li>
                  ))}
                </ul>

                <a
                  href="/hire"
                  className="block w-full text-center rounded-xl bg-tc-green py-4 text-lg font-bold text-black transition-all hover:bg-tc-green-dim pulse-glow"
                >
                  Get a Quote
                </a>

                <p className="text-center text-xs text-tc-text-dim mt-4">
                  Quotes typically returned within 1 business day.
                </p>
              </div>
            </ScrollReveal>

            {/* Enterprise + Government */}
            <ScrollReveal delay={200}>
              <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-2xl mx-auto">
                <div className="rounded-xl border border-tc-border bg-tc-card/40 p-6 text-center">
                  <div className="text-2xl mb-2">🏢</div>
                  <h3 className="text-lg font-bold text-white mb-1">Enterprise</h3>
                  <p className="text-sm text-tc-text-dim mb-3">Custom modules, SLA, dedicated support, volume licensing.</p>
                  <a href="https://calendly.com/chovy" target="_blank" rel="noopener noreferrer" className="inline-block rounded-lg border border-tc-green/30 bg-tc-green/5 px-5 py-2 text-sm font-medium text-tc-green hover:bg-tc-green/10 transition-all">
                    📅 Schedule a Call
                  </a>
                </div>
                <div className="rounded-xl border border-tc-border bg-tc-card/40 p-6 text-center">
                  <div className="text-2xl mb-2">🏳️</div>
                  <h3 className="text-lg font-bold text-white mb-1">Government &amp; Defense</h3>
                  <p className="text-sm text-tc-text-dim mb-3">The agent runs on your own servers, and detection and banning work without the cloud dashboard. Tell us your requirements.</p>
                  <a href="https://calendly.com/chovy" target="_blank" rel="noopener noreferrer" className="inline-block rounded-lg border border-tc-green/30 bg-tc-green/5 px-5 py-2 text-sm font-medium text-tc-green hover:bg-tc-green/10 transition-all">
                    📅 Schedule a Call
                  </a>
                </div>
              </div>
            </ScrollReveal>
          </div>
        </section>

        {/* ─── FAQ ─── */}
        <section id="faq" className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-2xl px-6">
            <ScrollReveal>
              <div className="text-center mb-12">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// FAQ</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  Questions? <span className="text-tc-green glow-green">Answers.</span>
                </h2>
              </div>
            </ScrollReveal>

            <div className="space-y-3">
              {faqs.map((faq, i) => (
                <ScrollReveal key={i} delay={i * 80}>
                  <div className="rounded-xl border border-tc-border bg-tc-card overflow-hidden">
                    <button
                      onClick={() => setOpenFaq(openFaq === i ? null : i)}
                      className="w-full px-6 py-4 text-left flex items-center justify-between hover:bg-tc-green/5 transition-colors"
                    >
                      <span className="font-medium text-white text-sm sm:text-base">{faq.q}</span>
                      <span className="text-tc-green ml-4 flex-shrink-0">
                        {openFaq === i ? "−" : "+"}
                      </span>
                    </button>
                    {openFaq === i && (
                      <div className="px-6 pb-4 text-sm text-tc-text-dim leading-relaxed">
                        {faq.a}
                      </div>
                    )}
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ─── CTA BANNER ─── */}
        <section className="py-20 border-t border-tc-border matrix-bg">
          <div className="mx-auto max-w-3xl px-6 text-center">
            <ScrollReveal>
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
                Ready to <span className="text-tc-green glow-green">Crush Threats</span>?
              </h2>
              <p className="text-tc-text-dim mb-8 max-w-xl mx-auto">
                Join the waitlist now. Your server deserves real-time protection.
                Early waitlist locks our lowest launch pricing.
              </p>
              <button
                onClick={openModal}
                className="rounded-xl bg-tc-green px-8 py-4 text-lg font-bold text-black transition-all hover:bg-tc-green-dim pulse-glow"
              >
                Join the Waitlist
              </button>
            </ScrollReveal>
          </div>
        </section>
      </main>

    </>
  );
}
