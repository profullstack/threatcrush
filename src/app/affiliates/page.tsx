"use client";

import { useState } from "react";
import ScrollReveal from "@/components/ScrollReveal";
import WaitlistModal from "@/components/WaitlistModal";

export default function AffiliatesPage() {
  const [modalOpen, setModalOpen] = useState(false);

  return (
    <>
      <WaitlistModal open={modalOpen} onClose={() => setModalOpen(false)} />

      <nav className="fixed top-0 left-0 right-0 z-40 border-b border-[#222]/50 bg-[#0a0a0a]/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <a href="/" className="flex items-center gap-2">
            <span className="text-xl font-bold text-[#00ff41] font-mono">⚡ ThreatCrush</span>
          </a>
          <div className="hidden sm:flex items-center gap-6 text-sm text-[#999]">
            <a href="/#features" className="hover:text-[#00ff41] transition-colors">Features</a>
            <a href="/store" className="hover:text-[#00ff41] transition-colors">Module Store</a>
            <a href="/#pricing" className="hover:text-[#00ff41] transition-colors">Pricing</a>
            <a href="/affiliates" className="text-[#00ff41]">Affiliates</a>
          </div>
        </div>
      </nav>

      <main className="pt-24 pb-16 min-h-screen bg-[#0a0a0a]">
        {/* Hero */}
        <section className="py-16 sm:py-24">
          <div className="mx-auto max-w-4xl px-6 text-center">
            <ScrollReveal>
              <p className="font-mono text-sm text-[#00ff41] mb-3 tracking-wider">// AFFILIATE PROGRAM</p>
              <h1 className="text-4xl sm:text-5xl font-black text-white mb-6">
                Earn <span className="text-[#00ff41]">$100</span> Per Referral
              </h1>
              <p className="text-lg text-[#999] max-w-2xl mx-auto mb-8">
                Share ThreatCrush with your network. Your friend saves $100, you earn $100 in crypto.
                No limits. Paid via CoinPayPortal.
              </p>
              <button
                onClick={() => setModalOpen(true)}
                className="rounded-xl bg-[#00ff41] px-8 py-4 text-lg font-bold text-black transition-all hover:opacity-90"
              >
                Get Your Referral Link
              </button>
            </ScrollReveal>
          </div>
        </section>

        {/* How it works */}
        <section className="py-16 border-t border-[#222]">
          <div className="mx-auto max-w-4xl px-6">
            <ScrollReveal>
              <h2 className="text-2xl sm:text-3xl font-bold text-white text-center mb-12">
                How It Works
              </h2>
            </ScrollReveal>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              {[
                {
                  step: "01",
                  icon: "📝",
                  title: "Sign Up",
                  desc: "Create a free account or join the waitlist. You get a unique referral link instantly.",
                },
                {
                  step: "02",
                  icon: "📤",
                  title: "Share",
                  desc: "Share your link with friends, your team, on social media, or your blog.",
                },
                {
                  step: "03",
                  icon: "💰",
                  title: "They Save",
                  desc: "Your friend pays $399 instead of $499 — $100 off their lifetime license.",
                },
                {
                  step: "04",
                  icon: "🪙",
                  title: "You Earn",
                  desc: "You receive $100 in crypto (BTC, ETH, USDT, or SOL) via CoinPayPortal.",
                },
              ].map((s, i) => (
                <ScrollReveal key={s.step} delay={i * 100}>
                  <div className="text-center">
                    <div className="inline-flex items-center justify-center w-14 h-14 rounded-full border border-[#00ff41]/30 bg-[#00ff41]/5 text-2xl mb-4">
                      {s.icon}
                    </div>
                    <div className="font-mono text-[#00ff41] text-sm mb-2">{s.step}</div>
                    <h3 className="text-lg font-bold text-white mb-2">{s.title}</h3>
                    <p className="text-sm text-[#999]">{s.desc}</p>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* The Math */}
        <section className="py-16 border-t border-[#222]">
          <div className="mx-auto max-w-3xl px-6">
            <ScrollReveal>
              <h2 className="text-2xl sm:text-3xl font-bold text-white text-center mb-10">
                The Math
              </h2>
            </ScrollReveal>

            <div className="space-y-4">
              {[
                { refs: 1, earned: 100, note: "Cover 20% of your license" },
                { refs: 3, earned: 300, note: "Cover 60% of your license" },
                { refs: 5, earned: 500, note: "Your license is FREE + $1 profit 🎉" },
                { refs: 10, earned: 1000, note: "Pure profit — $501 earned" },
                { refs: 25, earned: 2500, note: "Serious side income — $2,001" },
                { refs: 50, earned: 5000, note: "You're a ThreatCrush ambassador — $4,501" },
              ].map((row, i) => (
                <ScrollReveal key={row.refs} delay={i * 50}>
                  <div className="flex items-center justify-between rounded-lg border border-[#222] bg-[#111] px-5 py-3">
                    <div className="flex items-center gap-4">
                      <span className="text-[#00ff41] font-mono font-bold text-lg w-12">{row.refs}</span>
                      <span className="text-[#999] text-sm">referral{row.refs > 1 ? "s" : ""}</span>
                    </div>
                    <div className="text-right">
                      <span className="text-white font-bold font-mono">${row.earned.toLocaleString()}</span>
                      <span className="text-[#999] text-xs ml-3">{row.note}</span>
                    </div>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* Details */}
        <section className="py-16 border-t border-[#222]">
          <div className="mx-auto max-w-4xl px-6">
            <ScrollReveal>
              <h2 className="text-2xl sm:text-3xl font-bold text-white text-center mb-10">
                Program Details
              </h2>
            </ScrollReveal>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[
                {
                  title: "Who can join?",
                  desc: "Anyone. Sign up for a free account and you get a referral link immediately. You must be a paying member ($499 or $399) to earn payouts.",
                },
                {
                  title: "How are payouts made?",
                  desc: "Via CoinPayPortal in your choice of cryptocurrency: BTC, ETH, USDT, or SOL. Set your wallet address in your account settings.",
                },
                {
                  title: "When do I get paid?",
                  desc: "Payouts are processed automatically when your referred friend's payment confirms. Crypto payouts typically arrive within minutes.",
                },
                {
                  title: "Is there a limit?",
                  desc: "No limits. Refer 5 friends or 500 — every paid referral earns you $100. The more you share, the more you earn.",
                },
                {
                  title: "What does my friend get?",
                  desc: "$100 off — they pay $399 instead of $499 for lifetime access. Same full platform, all core modules, all updates forever.",
                },
                {
                  title: "Can I promote it publicly?",
                  desc: "Absolutely. Blog posts, YouTube reviews, tweets, newsletters, podcasts — share your link however you want. We encourage it.",
                },
              ].map((item, i) => (
                <ScrollReveal key={item.title} delay={i * 50}>
                  <div className="rounded-xl border border-[#222] bg-[#111]/60 p-5">
                    <h3 className="text-white font-bold mb-2">{item.title}</h3>
                    <p className="text-sm text-[#999]">{item.desc}</p>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-16 border-t border-[#222]">
          <div className="mx-auto max-w-2xl px-6 text-center">
            <ScrollReveal>
              <h2 className="text-2xl sm:text-3xl font-bold text-white mb-4">
                Ready to Start Earning?
              </h2>
              <p className="text-[#999] mb-8">
                Sign up, grab your link, and start sharing. Every referral = $100 in crypto.
              </p>
              <button
                onClick={() => setModalOpen(true)}
                className="rounded-xl bg-[#00ff41] px-8 py-4 text-lg font-bold text-black transition-all hover:opacity-90"
              >
                Get Your Referral Link
              </button>
              <p className="mt-4 text-xs text-[#666]">
                Payouts via <a href="https://coinpayportal.com" target="_blank" rel="noopener noreferrer" className="text-[#00ff41] hover:underline">CoinPayPortal</a> · BTC · ETH · USDT · SOL
              </p>
            </ScrollReveal>
          </div>
        </section>
      </main>

      <footer className="border-t border-[#222] py-12 bg-[#0a0a0a]">
        <div className="mx-auto max-w-6xl px-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
            <div className="font-mono text-[#00ff41] font-bold">⚡ ThreatCrush</div>
            <div className="flex items-center gap-6 text-sm text-[#999]">
              <a href="/#features" className="hover:text-[#00ff41] transition-colors">Features</a>
              <a href="/store" className="hover:text-[#00ff41] transition-colors">Module Store</a>
              <a href="/#pricing" className="hover:text-[#00ff41] transition-colors">Pricing</a>
              <a href="/affiliates" className="hover:text-[#00ff41] transition-colors">Affiliates</a>
              <a href="https://github.com/profullstack/threatcrush" target="_blank" rel="noopener noreferrer" className="hover:text-[#00ff41] transition-colors">GitHub</a>
            </div>
            <p className="text-xs text-[#666]">
              © {new Date().getFullYear()} <a href="https://profullstack.com" className="hover:text-tc-green transition-colors">Profullstack, Inc.</a>
            </p>
          </div>
        </div>
      </footer>
    </>
  );
}
