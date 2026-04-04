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
    desc: "Slack, email, and webhook notifications the instant a threat is detected. Never miss an attack.",
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
    a: "Credit/debit cards via Stripe, and cryptocurrency (BTC, ETH, USDT, and more) via CoinPayPortal.",
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
    q: "How does the referral program work?",
    a: "After signing up, you get a unique referral link. Share it with a friend — when they join, you both pay $249 instead of $499. There's no limit on referrals. Each friend you refer saves you both $250.",
  },
];

const included = [
  "Live attack detection & blocking",
  "Code vulnerability scanner",
  "Automated pentest engine",
  "Request interceptor / reverse proxy",
  "Real-time alerts (Slack, email, webhooks)",
  "systemd daemon — runs 24/7",
  "Full CLI & API access",
  "All future updates",
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
            <a href="#pricing" className="hover:text-tc-green transition-colors">Pricing</a>
            <a href="#faq" className="hover:text-tc-green transition-colors">FAQ</a>
          </div>
          <button
            onClick={openModal}
            className="rounded-lg bg-tc-green px-4 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim"
          >
            Join Waitlist
          </button>
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

            <ScrollReveal delay={400}>
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
                  <p><span className="text-tc-text-dim">[12:04:01]</span> <span className="text-tc-green">✓</span> <span className="text-tc-text-dim">3,891 connections analyzed · 4 threats · 1 blocked</span></p>
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
                  <p className="text-tc-green text-sm mt-1 font-medium">🎁 Refer a friend → both get it for $249</p>
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
                  <span>₿ Crypto</span>
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
                  Share your referral link after signing up. When your friend joins, you both get lifetime access for <strong className="text-tc-green">$249</strong> instead of $499.
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
                  <p className="text-sm text-tc-text-dim">You both pay $249 instead of $499. No limits on referrals.</p>
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
              <a href="#pricing" className="hover:text-tc-green transition-colors">Pricing</a>
              <a href="#faq" className="hover:text-tc-green transition-colors">FAQ</a>
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
