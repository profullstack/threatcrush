import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Free security tools — password strength, key generator, TLS fingerprint",
  description:
    "Free ThreatCrush security tools: a password brute-force calculator, a cryptographically strong key generator, a TLS certificate fingerprint checker, and a DNS resolver benchmark.",
  alternates: { canonical: "/tools" },
};

const TOOLS = [
  { href: "/tools/haystack", icon: "🔑", name: "Password Haystacks", desc: "How long would an exhaustive brute-force take? Runs entirely in your browser." },
  { href: "/tools/password", icon: "🎲", name: "Perfect Passwords", desc: "Cryptographically strong random strings for keys, passwords and salts. Generated locally." },
  { href: "/tools/fingerprint", icon: "🔒", name: "TLS Fingerprint", desc: "Read a site's certificate fingerprint and compare it to your browser's to detect interception." },
  { href: "/shields", icon: "🛡️", name: "Shields", desc: "Firewall port-exposure self-test: is your own connection stealthed?" },
];

export default function ToolsPage() {
  return (
    <main className="pt-24 pb-20 min-h-screen bg-tc-darker">
      <section className="mx-auto max-w-3xl px-6">
        <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">{"// FREE TOOLS"}</p>
        <h1 className="text-4xl sm:text-5xl font-black text-white mb-4">Free security tools</h1>
        <p className="text-tc-text-dim mb-8">
          No account, no payment. Independent re-implementations of some classic free security
          self-tests (not affiliated with their originators). The password and key tools run entirely in
          your browser and send nothing.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {TOOLS.map((t) => (
            <a key={t.href} href={t.href} className="rounded-2xl border border-tc-border bg-tc-card p-5 hover:border-tc-green/50 transition-all">
              <div className="text-2xl mb-2">{t.icon}</div>
              <div className="font-bold text-white">{t.name}</div>
              <div className="text-sm text-tc-text-dim mt-1">{t.desc}</div>
            </a>
          ))}
        </div>
        <p className="text-xs text-tc-text-dim mt-8">
          Prefer the terminal? These ship in the free ThreatCrush CLI:{" "}
          <code className="text-tc-green">threatcrush haystack</code>,{" "}
          <code className="text-tc-green">genpass</code>,{" "}
          <code className="text-tc-green">fingerprint</code>,{" "}
          <code className="text-tc-green">dns-bench</code>, and{" "}
          <code className="text-tc-green">shields</code>. The DNS resolver benchmark is CLI-only — it has
          to run from your machine to measure your network.
        </p>
      </section>
    </main>
  );
}
