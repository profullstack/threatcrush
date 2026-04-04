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
    title: "Active Defense",
    desc: "Fight back. Tar pits slow attackers down, honeypots trap them, deception serves fake data, and auto-reports file abuse complaints to their ISP.",
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

  const openModal = () => setModalOpen(true);

  return (
    <>
      <WaitlistModal open={modalOpen} onClose={() => setModalOpen(false)} />

      {/* ─── NAV ─── */}
      <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-tc-green glow-green font-mono">
              ⚡ ThreatCrush
            </span>
          </div>
          <div className="hidden sm:flex items-center gap-6 text-sm text-tc-text-dim">
            <a href="#features" className="hover:text-tc-green transition-colors">Features</a>
            <a href="/store" className="hover:text-tc-green transition-colors">Module Store</a>
            <a href="/usage" className="hover:text-tc-green transition-colors">Usage</a>
            <a href="#pricing" className="hover:text-tc-green transition-colors">Pricing</a>
            <a href="#faq" className="hover:text-tc-green transition-colors">FAQ</a>
            <a href="https://github.com/profullstack/threatcrush" target="_blank" rel="noopener noreferrer" className="hover:text-tc-green transition-colors flex items-center gap-1">
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
              GitHub
            </a>
          </div>
          <div className="flex items-center gap-3">
            <a
              href="/auth/login"
              className="text-sm text-tc-text-dim hover:text-tc-green transition-colors"
            >
              Log In
            </a>
            <a
              href="/auth/signup"
              className="rounded-lg bg-tc-green px-4 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim"
            >
              Sign Up
            </a>
            <button
              onClick={openModal}
              className="rounded-lg border border-tc-green/30 px-4 py-2 text-sm font-bold text-tc-green transition-all hover:bg-tc-green/10"
            >
              Join Waitlist
            </button>
          </div>
        </div>
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
              <p className="mx-auto max-w-2xl text-lg sm:text-xl text-tc-text-dim mb-10 leading-relaxed">
                An all-in-one security agent that lives on your server.
                Monitors every connection on every port — not just HTTP. Detects live attacks,
                scans your code, pentests your APIs, and alerts you in real-time.
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
                    <span className="text-tc-green">curl -fsSL threatcrush.com/install.sh | sh</span>
                    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs opacity-0 group-hover:opacity-100 transition-opacity">📋 click to copy</span>
                  </div>

                  {/* Package manager tabs */}
                  <div className="mt-4 pt-4 border-t border-tc-border/50">
                    <p className="text-xs text-tc-text-dim mb-3">Or install with your package manager:</p>
                    <div className="flex flex-wrap gap-2">
                      {[
                        { label: 'npm', cmd: 'npm i -g @profullstack/threatcrush' },
                        { label: 'pnpm', cmd: 'pnpm add -g @profullstack/threatcrush' },
                        { label: 'yarn', cmd: 'yarn global add @profullstack/threatcrush' },
                        { label: 'bun', cmd: 'bun add -g @profullstack/threatcrush' },
                      ].map((pm) => (
                        <button
                          key={pm.label}
                          onClick={() => { navigator.clipboard?.writeText(pm.cmd); }}
                          className="group/pm flex items-center gap-2 rounded-lg border border-tc-border bg-black/40 px-3 py-2 font-mono text-xs transition-all hover:border-tc-green/40 hover:bg-black/60"
                        >
                          <span className="text-tc-green font-semibold">{pm.label}</span>
                          <span className="text-tc-text-dim hidden sm:inline">{pm.cmd}</span>
                          <span className="text-tc-text-dim sm:hidden">{pm.cmd.split(' ').slice(0, 3).join(' ')}...</span>
                          <span className="text-[10px] text-tc-text-dim opacity-0 group-hover/pm:opacity-100 transition-opacity">📋</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </ScrollReveal>

            <ScrollReveal delay={400}>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <button
                  onClick={openModal}
                  className="rounded-xl bg-tc-green px-8 py-4 text-lg font-bold text-black transition-all hover:bg-tc-green-dim pulse-glow"
                >
                  Join the Waitlist
                </button>
                <a
                  href="#features"
                  className="rounded-xl border border-tc-border px-8 py-4 text-lg font-medium text-tc-text-dim transition-all hover:border-tc-green/30 hover:text-tc-text"
                >
                  See Features ↓
                </a>
              </div>
            </ScrollReveal>

            <ScrollReveal delay={500}>
              <p className="mt-6 text-sm text-tc-text-dim">
                💰 $499 one-time · No subscription · Access forever
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

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {[
                {
                  step: "01",
                  title: "Install",
                  desc: "npm i -g threatcrush",
                  subdesc: "or curl -sL threatcrush.com/install | sh",
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
                  <div className="text-center">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full border border-tc-green/30 bg-tc-green/5 text-2xl mb-4">
                      {s.icon}
                    </div>
                    <div className="font-mono text-tc-green text-sm mb-2">{s.step}</div>
                    <h3 className="text-xl font-bold text-white mb-2">{s.title}</h3>
                    <code className="text-tc-green text-sm font-mono">{s.desc}</code>
                    <p className="text-tc-text-dim text-xs mt-2">{s.subdesc}</p>
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

            {/* CLI / TUI Mock */}
            <ScrollReveal delay={0}>
              <div className="mb-16">
                <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">⚡ CLI &amp; TUI Dashboard</h3>
                <div className="mx-auto max-w-4xl rounded-xl border border-tc-border bg-[#0a0a0a] p-1 shadow-2xl shadow-tc-green/5">
                  {/* Terminal chrome */}
                  <div className="flex items-center gap-2 px-4 py-2.5 border-b border-tc-border">
                    <span className="w-3 h-3 rounded-full bg-red-500/80" />
                    <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <span className="w-3 h-3 rounded-full bg-green-500/80" />
                    <span className="text-tc-text-dim text-xs ml-2 font-mono">threatcrush — tui</span>
                  </div>
                  {/* TUI content */}
                  <div className="p-4 font-mono text-xs leading-relaxed">
                    <div className="grid grid-cols-12 gap-3">
                      {/* Left sidebar - modules */}
                      <div className="col-span-3 border-r border-tc-border pr-3">
                        <p className="text-tc-green font-bold mb-2">┌ MODULES</p>
                        {[
                          { name: 'network-mon', on: true },
                          { name: 'ssh-guard', on: true },
                          { name: 'log-watcher', on: true },
                          { name: 'dns-monitor', on: true },
                          { name: 'code-scanner', on: false },
                          { name: 'pentest-eng', on: false },
                          { name: 'firewall', on: true },
                          { name: 'alert-sys', on: true },
                        ].map((m) => (
                          <div key={m.name} className="flex items-center gap-1.5 py-0.5">
                            <span className={m.on ? 'text-tc-green' : 'text-red-400'}>{m.on ? '●' : '○'}</span>
                            <span className="text-tc-text-dim">{m.name}</span>
                          </div>
                        ))}
                        <p className="text-tc-text-dim mt-3 text-[10px]">6/8 active</p>
                      </div>
                      {/* Center - event stream */}
                      <div className="col-span-6">
                        <p className="text-tc-green font-bold mb-2">┌ LIVE EVENTS</p>
                        {[
                          { time: '14:23:01', type: 'info', icon: '✓', msg: 'Monitoring 847 connections', color: 'text-tc-green' },
                          { time: '14:23:05', type: 'warn', icon: '⚠', msg: 'SQLi — :443 185.43.21.8 → /api/users', color: 'text-yellow-400' },
                          { time: '14:23:07', type: 'crit', icon: '✗', msg: 'SSH brute — :22 91.232.105.3 (47 fails)', color: 'text-red-400' },
                          { time: '14:23:09', type: 'warn', icon: '⚠', msg: 'Port scan — 45.33.32.156 :21-:8080', color: 'text-yellow-400' },
                          { time: '14:23:12', type: 'warn', icon: '⚠', msg: 'DNS tunnel — :53 TXT from 103.44.8.2', color: 'text-yellow-400' },
                          { time: '14:23:15', type: 'info', icon: '✓', msg: 'Tar pit engaged — 91.232.105.3 (slowing)', color: 'text-tc-green' },
                          { time: '14:23:18', type: 'crit', icon: '✗', msg: 'XSS attempt — :443 /search?q=<script>', color: 'text-red-400' },
                          { time: '14:23:22', type: 'info', icon: '✓', msg: 'Rate limited 45.33.32.156 (50 req/s)', color: 'text-tc-green' },
                        ].map((e, i) => (
                          <div key={i} className="flex gap-2 py-0.5">
                            <span className="text-tc-text-dim">[{e.time}]</span>
                            <span className={e.color}>{e.icon}</span>
                            <span className={e.color === 'text-tc-green' ? 'text-tc-text-dim' : e.color}>{e.msg}</span>
                          </div>
                        ))}
                      </div>
                      {/* Right panel - threat IPs */}
                      <div className="col-span-3 border-l border-tc-border pl-3">
                        <p className="text-tc-green font-bold mb-2">┌ TOP THREATS</p>
                        {[
                          { ip: '91.232.105.3', hits: 47, flag: '🇷🇺' },
                          { ip: '45.33.32.156', hits: 23, flag: '🇨🇳' },
                          { ip: '185.43.21.8', hits: 12, flag: '🇺🇦' },
                          { ip: '103.44.8.2', hits: 8, flag: '🇻🇳' },
                          { ip: '77.88.55.60', hits: 5, flag: '🇷🇺' },
                        ].map((t) => (
                          <div key={t.ip} className="flex items-center justify-between py-0.5">
                            <span className="text-tc-text-dim">{t.flag} {t.ip}</span>
                            <span className="text-red-400">{t.hits}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    {/* Stats bar */}
                    <div className="mt-3 pt-2 border-t border-tc-border flex justify-between text-[10px]">
                      <span className="text-tc-green">▲ 3,891 events</span>
                      <span className="text-yellow-400">⚠ 12 warnings</span>
                      <span className="text-red-400">✗ 4 threats</span>
                      <span className="text-tc-green">✓ 1 blocked</span>
                      <span className="text-tc-text-dim">● 847 conn/s</span>
                      <span className="text-tc-text-dim">uptime 14d 6h</span>
                    </div>
                  </div>
                </div>
              </div>
            </ScrollReveal>

            {/* Desktop + Mobile side by side */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-8 items-start">
              {/* Desktop Mock */}
              <ScrollReveal delay={100} className="lg:col-span-3">
                <div>
                  <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">🖥️ Desktop App</h3>
                  <div className="rounded-xl border border-tc-border bg-[#0a0a0a] p-1 shadow-2xl shadow-tc-green/5">
                    {/* Window chrome */}
                    <div className="flex items-center gap-2 px-4 py-2 border-b border-tc-border">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                      <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
                      <span className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
                      <span className="text-tc-text-dim text-xs ml-auto font-mono">ThreatCrush</span>
                    </div>
                    <div className="p-4">
                      <div className="flex gap-4">
                        {/* Sidebar nav */}
                        <div className="w-36 space-y-1">
                          {['Dashboard', 'Monitor', 'Modules', 'Settings'].map((item, i) => (
                            <div key={item} className={`rounded-lg px-3 py-2 text-xs font-mono ${
                              i === 0 ? 'bg-tc-green/10 border border-tc-green/30 text-tc-green' : 'text-tc-text-dim hover:text-tc-text'
                            }`}>
                              {item}
                            </div>
                          ))}
                        </div>
                        {/* Dashboard content */}
                        <div className="flex-1 space-y-3">
                          {/* Stats row */}
                          <div className="grid grid-cols-4 gap-2">
                            {[
                              { label: 'Events', value: '3,891', color: 'text-tc-green' },
                              { label: 'Threats', value: '4', color: 'text-red-400' },
                              { label: 'Blocked', value: '1', color: 'text-yellow-400' },
                              { label: 'Uptime', value: '14d 6h', color: 'text-tc-text-dim' },
                            ].map((s) => (
                              <div key={s.label} className="rounded-lg border border-tc-border bg-tc-card/60 p-2 text-center">
                                <p className={`text-lg font-bold font-mono ${s.color}`}>{s.value}</p>
                                <p className="text-[10px] text-tc-text-dim">{s.label}</p>
                              </div>
                            ))}
                          </div>
                          {/* Mini event stream */}
                          <div className="rounded-lg border border-tc-border bg-tc-card/40 p-2 font-mono text-[10px] space-y-1">
                            <div className="flex gap-2"><span className="text-tc-text-dim">[14:23:05]</span><span className="text-yellow-400">⚠ SQLi attempt blocked</span></div>
                            <div className="flex gap-2"><span className="text-tc-text-dim">[14:23:07]</span><span className="text-red-400">✗ SSH brute force detected</span></div>
                            <div className="flex gap-2"><span className="text-tc-text-dim">[14:23:15]</span><span className="text-tc-green">✓ IP blocked via iptables</span></div>
                            <div className="flex gap-2"><span className="text-tc-text-dim">[14:23:18]</span><span className="text-red-400">✗ XSS attempt on /search</span></div>
                          </div>
                          {/* Module grid */}
                          <div className="grid grid-cols-3 gap-1.5">
                            {['network-mon', 'ssh-guard', 'firewall', 'log-watcher', 'dns-monitor', 'alert-sys'].map((m) => (
                              <div key={m} className="rounded border border-tc-border bg-tc-card/40 px-2 py-1.5 text-[10px] font-mono flex items-center gap-1">
                                <span className="text-tc-green">●</span>
                                <span className="text-tc-text-dim">{m}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </ScrollReveal>

              {/* Mobile Mock */}
              <ScrollReveal delay={200} className="lg:col-span-2">
                <div className="flex justify-center">
                  <div>
                    <h3 className="text-center text-sm font-mono text-tc-green mb-6 tracking-wider">📱 Mobile App</h3>
                    <div className="w-[260px] rounded-[2rem] border-2 border-tc-border bg-[#0a0a0a] p-2 shadow-2xl shadow-tc-green/5">
                      {/* Phone notch */}
                      <div className="mx-auto w-24 h-5 bg-black rounded-b-xl mb-2" />
                      {/* Screen content */}
                      <div className="rounded-2xl bg-[#0a0a0a] px-3 py-2 space-y-3">
                        {/* Status bar */}
                        <div className="flex justify-between text-[9px] text-tc-text-dim font-mono">
                          <span>14:23</span>
                          <span className="text-tc-green font-bold">ThreatCrush</span>
                          <span>●●●●</span>
                        </div>
                        {/* Alert banner */}
                        <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-2">
                          <p className="text-red-400 text-[10px] font-bold">🚨 4 Active Threats</p>
                          <p className="text-red-400/60 text-[9px]">SSH brute force on :22</p>
                        </div>
                        {/* Stats */}
                        <div className="grid grid-cols-2 gap-2">
                          <div className="rounded-lg border border-tc-border bg-tc-card/40 p-2 text-center">
                            <p className="text-tc-green font-bold font-mono text-sm">3,891</p>
                            <p className="text-[9px] text-tc-text-dim">Events</p>
                          </div>
                          <div className="rounded-lg border border-tc-border bg-tc-card/40 p-2 text-center">
                            <p className="text-yellow-400 font-bold font-mono text-sm">847</p>
                            <p className="text-[9px] text-tc-text-dim">Conn/s</p>
                          </div>
                        </div>
                        {/* Recent events */}
                        <div className="space-y-1.5">
                          <p className="text-[10px] text-tc-green font-mono font-bold">Recent</p>
                          {[
                            { icon: '⚠', msg: 'SQLi on :443', time: '2m', color: 'text-yellow-400' },
                            { icon: '✗', msg: 'SSH brute force', time: '4m', color: 'text-red-400' },
                            { icon: '✓', msg: 'IP blocked', time: '4m', color: 'text-tc-green' },
                            { icon: '⚠', msg: 'Port scan :21-:8080', time: '7m', color: 'text-yellow-400' },
                          ].map((e, i) => (
                            <div key={i} className="flex items-center gap-2 rounded-lg border border-tc-border bg-tc-card/40 px-2 py-1.5">
                              <span className={`text-xs ${e.color}`}>{e.icon}</span>
                              <span className="text-[10px] text-tc-text-dim flex-1">{e.msg}</span>
                              <span className="text-[9px] text-tc-text-dim">{e.time}</span>
                            </div>
                          ))}
                        </div>
                        {/* Bottom nav */}
                        <div className="flex justify-around pt-2 border-t border-tc-border">
                          {['📊', '🔍', '🪢', '⚙️'].map((icon, i) => (
                            <span key={i} className={`text-sm ${i === 0 ? 'text-tc-green' : 'text-tc-text-dim'}`}>{icon}</span>
                          ))}
                        </div>
                      </div>
                      {/* Home indicator */}
                      <div className="mx-auto w-24 h-1 bg-tc-text-dim/30 rounded-full mt-2" />
                    </div>
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
                      <p className="text-xs text-tc-text-dim">Linux · macOS · Windows</p>
                    </div>
                  </div>
                  <p className="text-sm text-tc-text-dim mb-4">The core agent. Runs as a systemd daemon, monitors all ports, TUI dashboard via SSH. The engine behind everything.</p>
                  <div className="rounded-lg bg-black/60 border border-tc-border px-3 py-2 font-mono text-xs">
                    <span className="text-tc-text-dim">$ </span>
                    <span className="text-tc-green">npm i -g @profullstack/threatcrush</span>
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
