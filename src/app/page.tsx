"use client";

import { useState } from "react";
import ScrollReveal from "@/components/ScrollReveal";
import WaitlistModal from "@/components/WaitlistModal";

/* ─── Feature data ─── */
const features = [
  {
    icon: "🔍",
    title: "Live Attack Detection",
    desc: "Monitors all inbound connections — every port, every protocol. Detects SQLi, XSS, brute force, SSH attacks, port scans, DNS tunneling, and more in real-time.",
  },
  {
    icon: "🛡️",
    title: "Code Security Scanner",
    desc: "Scan your codebase for vulnerabilities, hardcoded secrets, and misconfigurations. Find problems before attackers do.",
  },
  {
    icon: "💥",
    title: "Pentest Engine",
    desc: "Automated penetration testing on your URLs and APIs. Discovers attack vectors and rates their severity.",
  },
  {
    icon: "🔀",
    title: "Network Monitor",
    desc: "Watches all TCP/UDP traffic across every port — HTTP, SSH, DNS, FTP, database connections. See exactly what's hitting your server and flag anomalies.",
  },
  {
    icon: "🔔",
    title: "Real-time Alerts",
    desc: "Email, SMS, Slack, Discord, and webhook notifications the instant a threat is detected. Push alerts to your phone. Never miss an attack.",
  },
  {
    icon: "💢",
    title: "Active Defense — Strike Back",
    desc: "Don't just detect — retaliate. Tar pits waste attacker resources, honeypots trap and fingerprint them, deception feeds them fake credentials, and auto-reports get their servers shut down. They attack you, you make them regret it.",
  },
  {
    icon: "⚙️",
    title: "systemd Daemon",
    desc: "Runs as a background service on your server. Auto-starts on boot, monitors 24/7, zero maintenance.",
  },
];

const faqs = [
  {
    q: "What does \"Lifetime Access\" mean?",
    a: "Pay once, access forever. No subscriptions, no renewals. You get the full ThreatCrush platform — CLI, daemon, scanner, pentest engine, API — and all future updates for life.",
  },
  {
    q: "When will ThreatCrush launch?",
    a: "We're in private beta. Waitlist members get early access before public launch. Expected Q3 2026.",
  },
  {
    q: "What servers does it support?",
    a: "Any Linux server. ThreatCrush monitors all network connections (not just web traffic), plus application logs from nginx, Apache, SSH, and more. Auto-detects your setup during `threatcrush init`.",
  },
  {
    q: "What payment methods do you accept?",
    a: "Credit/debit cards via Stripe, and cryptocurrency (BTC, ETH, USDT, SOL, and more) via <a href='https://coinpayportal.com' target='_blank' rel='noopener noreferrer' class='text-tc-green hover:underline'>CoinPayPortal</a>.",
  },
  {
    q: "Can I get a refund?",
    a: "Yes. If you're not satisfied within 30 days of getting access, we'll refund your payment in full. No questions asked.",
  },
  {
    q: "Is the API included in Lifetime Access?",
    a: "Yes. Full API access with generous rate limits is included. Enterprise rate limits available on request.",
  },
  {
    q: "What about AI-enhanced modules?",
    a: "Some modules use AI for advanced threat classification, anomaly detection, and smart alerting. These are usage-based — you only pay for what you use. Your lifetime license covers the core platform; AI usage is metered separately so you're never overpaying.",
  },
  {
    q: "Do you work with government agencies?",
    a: "Yes. ThreatCrush supports air-gapped deployment, on-prem hardware appliances, and is designed for FedRAMP, FIPS 140-2, and ITAR compliance. Contact gov@threatcrush.com for GSA Schedule pricing and custom deployment.",
  },
  {
    q: "How does the referral program work?",
    a: "After signing up, you get a unique referral link. Your friend pays $399 ($100 off), and you earn $100 per referral, paid out in crypto via <a href='https://coinpayportal.com' target='_blank' rel='noopener noreferrer' class='text-tc-green hover:underline'>CoinPayPortal</a> (BTC, ETH, USDT, SOL). No limits — refer 5 friends and you've paid for your own license. Must be a paying member to earn.",
  },
];

const included = [
  "Live attack detection & blocking",
  "Code vulnerability scanner",
  "Automated pentest engine",
  "Network monitor — all ports, all protocols",
  "Real-time email + SMS alerts",
  "Webhook support for custom integrations",
  "Active defense — tar pits, honeypots, deception",
  "systemd daemon — runs 24/7",
  "Full CLI, desktop & mobile apps",
  "All core modules + future updates",
  "Priority support",
];

export default function Home() {
  const [modalOpen, setModalOpen] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const openModal = () => setModalOpen(true);

  return (
    <>
      <WaitlistModal open={modalOpen} onClose={() => setModalOpen(false)} />

      {/* ─── NAV ─── */}
      <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6">
          <a href="/" className="flex items-center gap-2">
            <img src="/logo.svg" alt="ThreatCrush" width={90} height={40} className="w-[90px] h-10 object-contain" />
            <span className="text-xl font-bold text-tc-green glow-green font-mono">
              ThreatCrush
            </span>
          </a>
          <div className="hidden lg:flex items-center gap-6 text-sm text-tc-text-dim">
            <a href="/store" className="text-tc-green transition-colors">Module Store</a>
            <a href="/docs" className="hover:text-tc-green transition-colors">Docs</a>
            <a href="#features" className="hover:text-tc-green transition-colors">Features</a>
            <a href="/usage" className="hover:text-tc-green transition-colors">Usage</a>
            <a href="#pricing" className="hover:text-tc-green transition-colors">Pricing</a>
            <a href="#faq" className="hover:text-tc-green transition-colors">FAQ</a>
            <a href="https://github.com/profullstack/threatcrush" target="_blank" rel="noopener noreferrer" className="hover:text-tc-green transition-colors flex items-center gap-1">
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
              GitHub
            </a>
          </div>
          <div className="flex items-center gap-2 sm:gap-3">
            <a
              href="/auth/signup"
              className="rounded-lg bg-tc-green px-3 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim sm:px-4"
            >
              Sign Up
            </a>
            <button
              type="button"
              onClick={() => setMobileNavOpen((open) => !open)}
              className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-tc-border text-tc-text-dim transition-all hover:border-tc-green/30 hover:text-tc-green lg:hidden"
              aria-label="Toggle navigation menu"
              aria-expanded={mobileNavOpen}
            >
              <span className="text-lg">{mobileNavOpen ? "✕" : "☰"}</span>
            </button>
            <div className="hidden lg:flex items-center gap-3">
              <a
                href="/auth/login"
                className="text-sm text-tc-text-dim hover:text-tc-green transition-colors"
              >
                Log In
              </a>
              <button
                onClick={openModal}
                className="rounded-lg border border-tc-green/30 px-4 py-2 text-sm font-bold text-tc-green transition-all hover:bg-tc-green/10"
              >
                Join Waitlist
              </button>
            </div>
          </div>
        </div>
        {mobileNavOpen && (
          <div className="border-t border-tc-border/50 bg-tc-darker/95 px-4 py-4 lg:hidden">
            <div className="flex flex-col gap-3 text-sm text-tc-text-dim">
              <a href="/store" className="text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Module Store</a>
              <a href="/docs" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Docs</a>
              <a href="#features" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Features</a>
              <a href="/usage" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Usage</a>
              <a href="#pricing" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Pricing</a>
              <a href="#faq" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>FAQ</a>
              <a href="/auth/login" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Log In</a>
              <button
                onClick={() => {
                  setMobileNavOpen(false);
                  openModal();
                }}
                className="rounded-lg border border-tc-green/30 px-4 py-2 text-left font-bold text-tc-green transition-all hover:bg-tc-green/10"
              >
                Join Waitlist
              </button>
              <a
                href="https://github.com/profullstack/threatcrush"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-tc-green transition-colors"
                onClick={() => setMobileNavOpen(false)}
              >
                GitHub
              </a>
            </div>
          </div>
        )}
      </nav>

      <main>
        {/* ─── HERO ─── */}
        <section className="relative min-h-screen flex items-center justify-center overflow-hidden matrix-bg grid-pattern scanlines">
          {/* Decorative gradient orbs */}
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-tc-green/5 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-tc-green/3 rounded-full blur-3xl" />

          <div className="relative z-10 mx-auto max-w-4xl px-6 text-center pt-20">
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
                ThreatCrush starts with a module marketplace: discover, publish, and grow security modules first — while the broader platform, daemon, and operator workflows continue to mature.
              </p>
              <p className="mx-auto max-w-2xl text-base sm:text-lg text-tc-text-dim mb-10 leading-relaxed">
                The long-term product is an all-in-one security agent for Linux servers, with desktop clients for operators. Right now, the module store is the clearest place to start.
              </p>
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
                    <span className="text-tc-green">curl -fsSL https://threatcrush.com/install.sh | sh</span>
                    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs opacity-0 group-hover:opacity-100 transition-opacity">📋 click to copy</span>
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
                        Linux servers get the CLI. Linux desktops get CLI + desktop app. Windows is desktop-client only and connects to a ThreatCrush server elsewhere.
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
                          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs opacity-0 group-hover:opacity-100 transition-opacity">📋 click to copy</span>
                        </div>
                        <div
                          className="group relative rounded-lg bg-black/60 border border-tc-border px-4 py-3 font-mono text-sm cursor-pointer transition-all hover:border-tc-green/40"
                          onClick={() => { navigator.clipboard?.writeText('threatcrush remove'); }}
                        >
                          <span className="text-tc-green">threatcrush remove</span>
                          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs opacity-0 group-hover:opacity-100 transition-opacity">📋 click to copy</span>
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
                Start with the marketplace now. Broader platform rollout continues after the basic install/docs/housekeeping work.
              </p>
            </ScrollReveal>

            {/* Terminal decoration */}
            <ScrollReveal delay={500}>
              <div className="mt-16 mx-auto max-w-2xl rounded-xl border border-tc-border bg-tc-card/80 p-4 text-left font-mono text-sm backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-3 pb-2 border-b border-tc-border">
                  <span className="w-3 h-3 rounded-full bg-red-500/80" />
                  <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
                  <span className="w-3 h-3 rounded-full bg-green-500/80" />
                  <span className="text-tc-text-dim text-xs ml-2">threatcrush — zsh</span>
                </div>
                <div className="space-y-1">
                  <p><span className="text-tc-text-dim">$</span> <span className="text-tc-green/80">threatcrush monitor</span></p>
                  <p><span className="text-tc-text-dim">[12:03:41]</span> <span className="text-tc-green">✓</span> <span className="text-tc-text-dim">Monitoring all ports · nginx · sshd · postgres</span></p>
                  <p><span className="text-tc-text-dim">[12:03:42]</span> <span className="text-tc-green">✓</span> <span className="text-tc-text-dim">Loaded 1,247 attack signatures</span></p>
                  <p><span className="text-tc-text-dim">[12:03:45]</span> <span className="text-yellow-400">⚠</span> <span className="text-yellow-400">SQLi attempt</span> <span className="text-tc-text-dim">— :443 185.43.21.8 → /api/users?id=1 OR 1=1</span></p>
                  <p><span className="text-tc-text-dim">[12:03:47]</span> <span className="text-red-400">✗</span> <span className="text-red-400">SSH brute force</span> <span className="text-tc-text-dim">— :22 91.232.105.3 → 47 failed attempts</span></p>
                  <p><span className="text-tc-text-dim">[12:03:50]</span> <span className="text-yellow-400">⚠</span> <span className="text-yellow-400">Port scan</span> <span className="text-tc-text-dim">— 45.33.32.156 scanning :21-:8080 (SYN flood)</span></p>
                  <p><span className="text-tc-text-dim">[12:03:52]</span> <span className="text-yellow-400">⚠</span> <span className="text-yellow-400">DNS tunneling</span> <span className="text-tc-text-dim">— :53 suspicious TXT queries from 103.44.8.2</span></p>
                  <p><span className="text-tc-text-dim">[12:03:55]</span> <span className="text-tc-green">✓</span> <span className="text-tc-text-dim">Honeypot triggered — logging attacker recon on :2222</span></p>
                  <p><span className="text-tc-text-dim">[12:04:01]</span> <span className="text-tc-green">✓</span> <span className="text-tc-text-dim">3,891 connections · 4 threats · 1 blocked · 2 tar-pitted</span></p>
                </div>
              </div>
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

        {/* ─── MODULE STORE FIRST ─── */}
        <section className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="text-center mb-16">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// START HERE</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  The <span className="text-tc-green glow-green">Module Store</span> Comes First
                </h2>
                <p className="mt-4 max-w-3xl mx-auto text-tc-text-dim">
                  After the basic housekeeping work, the first real wedge for ThreatCrush is the marketplace.
                  Discover modules, publish your own, and shape the ecosystem before the rest of the platform fills in.
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
                  desc: "Submit a repo or website URL, fetch metadata automatically, review it, then list it.",
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
                  Three Commands to <span className="text-tc-green glow-green">Full Protection</span>
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
                  subdesc: "Auto-detects all services — web, SSH, DNS, databases",
                  icon: "⚙️",
                },
                {
                  step: "03",
                  title: "Monitor",
                  desc: "threatcrush monitor",
                  subdesc: "Real-time protection, runs as a daemon",
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
                    className="w-full rounded-xl border border-tc-border shadow-2xl shadow-tc-green/5"
                  />
                </div>
                <div>
                  <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">▣ TUI Dashboard</h3>
                  <img
                    src="/images/gallery-tui.png"
                    alt="ThreatCrush TUI Dashboard"
                    className="w-full rounded-xl border border-tc-border shadow-2xl shadow-tc-green/5"
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
                    className="w-full rounded-xl border border-tc-border shadow-2xl shadow-tc-green/5"
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
                      className="w-full rounded-xl border border-tc-border shadow-2xl shadow-tc-green/5"
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
                  <p className="text-sm text-tc-text-dim mb-4">The core agent. Linux servers run the real monitoring/daemon stack. Desktop installs are for operating and interfacing with a ThreatCrush server.</p>
                  <div className="rounded-lg bg-black/60 border border-tc-border px-3 py-2 font-mono text-xs">
                    <span className="text-tc-text-dim">$ </span>
                    <span className="text-tc-green">curl -fsSL https://threatcrush.com/install.sh | sh</span>
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
                  <p className="text-sm text-tc-text-dim mb-4">Full dashboard with real-time event stream, module management, and threat analytics. E2E encrypted connection to your daemon.</p>
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
                  <p className="mt-3 text-xs text-tc-green font-mono">Coming soon</p>
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
                  <p className="text-sm text-tc-text-dim mb-4">Get instant push alerts when threats are detected. Monitor dashboards, manage modules, and check server status from anywhere.</p>
                  <div className="flex gap-2 flex-wrap">
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🍎 App Store
                    </span>
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim">
                      🤖 Google Play
                    </span>
                  </div>
                  <p className="mt-3 text-xs text-tc-green font-mono">Coming soon</p>
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
                  <p className="text-sm text-tc-text-dim mb-4">Scan any website from your browser. Get real-time alerts, check security headers, and monitor your servers without leaving the tab.</p>
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
                  <p className="mt-3 text-xs text-tc-green font-mono">Coming soon</p>
                </div>
              </ScrollReveal>
            </div>

            {/* E2E notice */}
            <ScrollReveal delay={300}>
              <div className="mt-10 text-center">
                <p className="inline-flex items-center gap-2 rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-2 text-sm text-tc-text-dim">
                  <span className="text-tc-green">🔒</span>
                  All apps connect via <span className="text-tc-green font-medium">end-to-end encryption</span> — your vulnerability data never touches our servers unencrypted.
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
                    LIFETIME ACCESS
                  </div>
                  <div className="flex items-baseline justify-center gap-1">
                    <span className="text-5xl sm:text-6xl font-black text-white">$499</span>
                    <span className="text-tc-text-dim text-lg">/once</span>
                  </div>
                  <p className="text-tc-text-dim mt-2">Full platform: CLI, daemon, scanner, pentest engine, API. Pay once.</p>
                  <p className="text-tc-text-dim text-xs mt-1">AI-enhanced modules billed on usage — <span className="text-tc-green">pay only for what you use</span></p>
                  <p className="text-tc-green text-sm mt-1 font-medium">🎁 Refer a friend → they save $100, you earn $100</p>
                </div>

                <ul className="space-y-3 mb-8">
                  {included.map((item) => (
                    <li key={item} className="flex items-center gap-3 text-sm text-tc-text">
                      <span className="text-tc-green">✓</span>
                      {item}
                    </li>
                  ))}
                </ul>

                <button
                  onClick={openModal}
                  className="w-full rounded-xl bg-tc-green py-4 text-lg font-bold text-black transition-all hover:bg-tc-green-dim pulse-glow"
                >
                  Join the Waitlist
                </button>

                <div className="flex items-center justify-center gap-4 mt-4 text-xs text-tc-text-dim">
                  <span>💳 Stripe</span>
                  <span>·</span>
                  <a href="https://coinpayportal.com" target="_blank" rel="noopener noreferrer" className="hover:text-tc-green transition-colors">₿ CoinPayPortal</a>
                  <span>·</span>
                  <span>🔒 30-day refund</span>
                </div>
              </div>
            </ScrollReveal>

            {/* Enterprise + Government */}
            <ScrollReveal delay={200}>
              <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-2xl mx-auto">
                <div className="rounded-xl border border-tc-border bg-tc-card/40 p-6 text-center">
                  <div className="text-2xl mb-2">🏢</div>
                  <h3 className="text-lg font-bold text-white mb-1">Enterprise</h3>
                  <p className="text-sm text-tc-text-dim mb-3">Custom modules, SLA, dedicated support, on-prem hardware appliances, volume licensing.</p>
                  <a href="https://calendly.com/chovy" target="_blank" rel="noopener noreferrer" className="inline-block rounded-lg border border-tc-green/30 bg-tc-green/5 px-5 py-2 text-sm font-medium text-tc-green hover:bg-tc-green/10 transition-all">
                    📅 Schedule a Call
                  </a>
                </div>
                <div className="rounded-xl border border-tc-border bg-tc-card/40 p-6 text-center">
                  <div className="text-2xl mb-2">🏳️</div>
                  <h3 className="text-lg font-bold text-white mb-1">Government &amp; Defense</h3>
                  <p className="text-sm text-tc-text-dim mb-3">FedRAMP-ready, air-gapped deployment, FIPS 140-2, ITAR compliant, GSA Schedule compatible.</p>
                  <a href="https://calendly.com/chovy" target="_blank" rel="noopener noreferrer" className="inline-block rounded-lg border border-tc-green/30 bg-tc-green/5 px-5 py-2 text-sm font-medium text-tc-green hover:bg-tc-green/10 transition-all">
                    📅 Schedule a Call
                  </a>
                </div>
              </div>
            </ScrollReveal>
          </div>
        </section>

        {/* ─── Referral Program ─── */}
        <section className="py-24 sm:py-32 border-t border-tc-border">
          <div className="mx-auto max-w-3xl px-6">
            <ScrollReveal>
              <div className="text-center mb-12">
                <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// REFER &amp; SAVE</p>
                <h2 className="text-3xl sm:text-4xl font-bold text-white">
                  Bring a Friend. <span className="text-tc-green glow-green">Both Save $250.</span>
                </h2>
                <p className="text-tc-text-dim mt-4 max-w-xl mx-auto">
                  Share your referral link after signing up. When your friend joins, your friend gets lifetime access for <strong className="text-tc-green">$399</strong> and you earn <strong className="text-tc-green">$100 in crypto</strong> per referral via CoinPayPortal. Refer 5 friends = free license.
                </p>
              </div>
            </ScrollReveal>

            <ScrollReveal delay={100}>
              <div className="grid sm:grid-cols-3 gap-6">
                <div className="rounded-xl border border-tc-border bg-tc-card p-6 text-center">
                  <div className="text-3xl mb-3">🔗</div>
                  <h3 className="font-bold text-white mb-2">1. Sign Up</h3>
                  <p className="text-sm text-tc-text-dim">Join the waitlist and get your unique referral link.</p>
                </div>
                <div className="rounded-xl border border-tc-border bg-tc-card p-6 text-center">
                  <div className="text-3xl mb-3">📤</div>
                  <h3 className="font-bold text-white mb-2">2. Share</h3>
                  <p className="text-sm text-tc-text-dim">Send your link to a friend who needs server security.</p>
                </div>
                <div className="rounded-xl border border-tc-border bg-tc-card p-6 text-center">
                  <div className="text-3xl mb-3">💰</div>
                  <h3 className="font-bold text-white mb-2">3. Both Save</h3>
                  <p className="text-sm text-tc-text-dim">They pay $399, you earn $100 in crypto (BTC/ETH/USDT/SOL). No limits.</p>
                </div>
              </div>
            </ScrollReveal>

            <ScrollReveal delay={200}>
              <div className="text-center mt-10">
                <button
                  onClick={openModal}
                  className="inline-block rounded-xl border border-tc-green/30 bg-tc-green/5 px-8 py-4 font-bold text-tc-green transition-all hover:bg-tc-green/10 hover:border-tc-green/50"
                >
                  Get Your Referral Link →
                </button>
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
                Limited lifetime spots at $499 — price increases after launch.
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

      {/* ─── FOOTER ─── */}
      <footer className="border-t border-tc-border py-12">
        <div className="mx-auto max-w-6xl px-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
            <div className="font-mono text-tc-green font-bold">⚡ ThreatCrush</div>
            <div className="flex items-center gap-6 text-sm text-tc-text-dim">
              <a href="#features" className="hover:text-tc-green transition-colors">Features</a>
              <a href="/store" className="hover:text-tc-green transition-colors">Module Store</a>
              <a href="/docs" className="hover:text-tc-green transition-colors">Docs</a>
              <a href="/usage" className="hover:text-tc-green transition-colors">Usage</a>
              <a href="#pricing" className="hover:text-tc-green transition-colors">Pricing</a>
              <a href="#faq" className="hover:text-tc-green transition-colors">FAQ</a>
              <a href="/affiliates" className="hover:text-tc-green transition-colors">Affiliates</a>
              <a href="https://github.com/profullstack/threatcrush" target="_blank" rel="noopener noreferrer" className="hover:text-tc-green transition-colors">GitHub</a>
              <a href="https://www.npmjs.com/package/@profullstack/threatcrush" target="_blank" rel="noopener noreferrer" className="hover:text-tc-green transition-colors">npm</a>
            </div>
            <p className="text-xs text-tc-text-dim">
              © {new Date().getFullYear()} ThreatCrush. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </>
  );
}
