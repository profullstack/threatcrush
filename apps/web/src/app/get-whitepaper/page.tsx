"use client";

import { useEffect, useState, type FormEvent } from "react";
import ScrollReveal from "@/components/ScrollReveal";

const SLUG = "ctem-guide";
const PDF_PATH = "/whitepaper/threatcrush-ctem-guide.pdf";

type UtmFields = Partial<
  Record<"utm_source" | "utm_medium" | "utm_campaign" | "utm_content" | "utm_term", string>
>;

export default function GetWhitepaperPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [role, setRole] = useState("");
  const [teamSize, setTeamSize] = useState("");
  const [consentMarketing, setConsentMarketing] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [utm, setUtm] = useState<UtmFields>({});

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const u: UtmFields = {};
    (["utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term"] as const).forEach((k) => {
      const v = params.get(k);
      if (v) u[k] = v;
    });
    if (Object.keys(u).length) setUtm(u);
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!name || !email) return;
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/whitepaper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          email,
          company: company || undefined,
          role: role || undefined,
          team_size: teamSize || undefined,
          consent_marketing: consentMarketing,
          slug: SLUG,
          utm,
          source: "get-whitepaper",
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Something went wrong");
      setSubmitted(true);
      // Auto-trigger the download too
      if (typeof window !== "undefined") {
        const a = document.createElement("a");
        a.href = PDF_PATH;
        a.download = "threatcrush-ctem-guide.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main>
      <section className="relative pt-32 pb-24 overflow-hidden matrix-bg grid-pattern">
        <div className="absolute top-1/3 left-1/4 w-96 h-96 bg-tc-green/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-tc-green/5 rounded-full blur-3xl" />

        <div className="relative z-10 mx-auto max-w-6xl px-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
            {/* ── Left: pitch ── */}
            <div className="lg:col-span-7">
              <ScrollReveal>
                <div className="inline-block rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-1.5 text-sm font-mono text-tc-green mb-6">
                  // FREE GUIDE — CTEM FOR OPERATORS
                </div>
              </ScrollReveal>

              <ScrollReveal delay={100}>
                <h1 className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight mb-6 leading-[1.05]">
                  <span className="text-white">Evolving from </span>
                  <span className="text-tc-green glow-green">VM to CTEM</span>
                  <br />
                  <span className="text-white">— a practical guide</span>
                </h1>
              </ScrollReveal>

              <ScrollReveal delay={200}>
                <p className="text-lg text-tc-text-dim mb-6 leading-relaxed">
                  Vulnerability management is broken. Scanners spit out tens of thousands of findings, the exploit window is now measured in <span className="text-tc-green">days, not quarters</span>, and your team is closing tickets faster than they reduce risk.
                </p>
                <p className="text-lg text-tc-text-dim mb-8 leading-relaxed">
                  This guide is the operator playbook for the next stage:{" "}
                  <span className="text-white font-semibold">Continuous Threat Exposure Management</span>, how it relates to your existing <span className="text-white font-semibold">SIEM, EDR, and SOC</span>, and the open-standards stack — <span className="text-tc-green">MITRE ATT&amp;CK, D3FEND, Sigma, OCSF</span> — that ties them together. No vendor handwaving. Just a 90-day plan you can run with the team you already have.
                </p>
              </ScrollReveal>

              <ScrollReveal delay={300}>
                <div className="rounded-2xl border border-tc-border bg-tc-card/60 backdrop-blur-md p-6 mb-8">
                  <p className="font-mono text-xs text-tc-green mb-4 tracking-wider">// WHAT&apos;S INSIDE</p>
                  <ul className="space-y-3">
                    {[
                      "The 5 stages of CTEM (scope · discover · prioritize · validate · mobilize) in operator language",
                      "Why CVSS-weighted backlogs hide your real exposure window",
                      "How CTEM relates to SIEM, EDR, and SOC — and why you need both layers",
                      "The open-standards stack: MITRE ATT&CK, D3FEND, Sigma, YARA, osquery, OCSF, NIST CSF, CIS",
                      "A 90-day implementation playbook — calendar weeks, not sprints",
                      "Six metrics that actually reflect risk reduction",
                      "Common failure modes and how to avoid them",
                    ].map((item) => (
                      <li key={item} className="flex items-start gap-3 text-sm text-tc-text leading-relaxed">
                        <span className="text-tc-green flex-shrink-0 mt-0.5">✓</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </ScrollReveal>

              <ScrollReveal delay={400}>
                <div className="hidden lg:flex items-center gap-4 text-xs text-tc-text-dim">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="text-tc-green">📄</span> 14-page PDF
                  </span>
                  <span>·</span>
                  <span className="inline-flex items-center gap-1.5">
                    <span className="text-tc-green">⏱</span> 17 min read
                  </span>
                  <span>·</span>
                  <span className="inline-flex items-center gap-1.5">
                    <span className="text-tc-green">🔓</span> No paywall
                  </span>
                </div>
              </ScrollReveal>
            </div>

            {/* ── Right: form ── */}
            <div className="lg:col-span-5">
              <ScrollReveal delay={150}>
                <div className="lg:sticky lg:top-28">
                  {/* Cover preview */}
                  <div className="hidden lg:block mb-6 mx-auto max-w-[280px]">
                    <img
                      src="/whitepaper/cover.svg"
                      alt="The CTEM Operator's Guide cover"
                      className="w-full rounded-lg shadow-2xl shadow-tc-green/10 border border-tc-green/20"
                    />
                  </div>

                  <div className="rounded-2xl border border-tc-green/30 bg-tc-card p-6 sm:p-8 glow-box">
                    {submitted ? (
                      <div className="text-center py-4">
                        <div className="text-5xl mb-4">📥</div>
                        <h3 className="text-2xl font-bold text-tc-green glow-green mb-2">
                          Your guide is on the way.
                        </h3>
                        <p className="text-tc-text-dim text-sm mb-6">
                          The download should have started automatically. We&apos;ve also emailed a copy to{" "}
                          <span className="text-tc-green font-mono">{email}</span> so you can find it later.
                        </p>
                        <a
                          href={PDF_PATH}
                          className="inline-block rounded-lg bg-tc-green px-6 py-3 font-bold text-black transition-all hover:bg-tc-green-dim"
                        >
                          Download again →
                        </a>
                        <div className="mt-6 pt-6 border-t border-tc-border text-left">
                          <p className="text-xs font-mono text-tc-green tracking-wider mb-2">// NEXT STEP</p>
                          <p className="text-sm text-tc-text-dim mb-3">
                            Want to try the platform? Install in one line:
                          </p>
                          <pre className="rounded-lg bg-black/60 border border-tc-border px-3 py-2 font-mono text-xs text-tc-green overflow-x-auto">
                            curl -fsSL https://threatcrush.com/install.sh | sh
                          </pre>
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="mb-6">
                          <h3 className="text-2xl font-bold text-white mb-1">Get the guide</h3>
                          <p className="text-sm text-tc-text-dim">
                            We&apos;ll email you the PDF and start the download right away.
                          </p>
                        </div>
                        <form onSubmit={handleSubmit} className="space-y-4">
                          <div>
                            <label className="block text-xs font-mono text-tc-text-dim mb-1.5 tracking-wider">
                              NAME *
                            </label>
                            <input
                              type="text"
                              value={name}
                              onChange={(e) => setName(e.target.value)}
                              required
                              autoComplete="name"
                              placeholder="Jane Doe"
                              className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text placeholder:text-tc-text-dim/40 focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all text-sm"
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-mono text-tc-text-dim mb-1.5 tracking-wider">
                              WORK EMAIL *
                            </label>
                            <input
                              type="email"
                              value={email}
                              onChange={(e) => setEmail(e.target.value)}
                              required
                              autoComplete="email"
                              placeholder="jane@company.com"
                              className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text placeholder:text-tc-text-dim/40 focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all font-mono text-sm"
                            />
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                              <label className="block text-xs font-mono text-tc-text-dim mb-1.5 tracking-wider">
                                COMPANY
                              </label>
                              <input
                                type="text"
                                value={company}
                                onChange={(e) => setCompany(e.target.value)}
                                autoComplete="organization"
                                placeholder="Optional"
                                className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text placeholder:text-tc-text-dim/40 focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all text-sm"
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-mono text-tc-text-dim mb-1.5 tracking-wider">
                                ROLE
                              </label>
                              <select
                                value={role}
                                onChange={(e) => setRole(e.target.value)}
                                className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all text-sm"
                              >
                                <option value="">Optional</option>
                                <option value="ciso">CISO / Security Leader</option>
                                <option value="security_engineer">Security Engineer</option>
                                <option value="soc">SOC / Detection</option>
                                <option value="vuln_mgmt">VM / Exposure Mgmt</option>
                                <option value="devops">DevOps / SRE / Platform</option>
                                <option value="engineer">Software Engineer</option>
                                <option value="founder">Founder / Exec</option>
                                <option value="other">Other</option>
                              </select>
                            </div>
                          </div>
                          <div>
                            <label className="block text-xs font-mono text-tc-text-dim mb-1.5 tracking-wider">
                              TEAM SIZE
                            </label>
                            <select
                              value={teamSize}
                              onChange={(e) => setTeamSize(e.target.value)}
                              className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all text-sm"
                            >
                              <option value="">Optional</option>
                              <option value="solo">Just me</option>
                              <option value="2-10">2 – 10</option>
                              <option value="11-50">11 – 50</option>
                              <option value="51-200">51 – 200</option>
                              <option value="201-1000">201 – 1,000</option>
                              <option value="1000+">1,000+</option>
                            </select>
                          </div>

                          <label className="flex items-start gap-2.5 text-xs text-tc-text-dim cursor-pointer">
                            <input
                              type="checkbox"
                              checked={consentMarketing}
                              onChange={(e) => setConsentMarketing(e.target.checked)}
                              className="mt-0.5 accent-tc-green"
                            />
                            <span>
                              Send me occasional ThreatCrush updates. We don&apos;t spam — opt out from any email.
                            </span>
                          </label>

                          {error && <p className="text-red-400 text-sm">{error}</p>}

                          <button
                            type="submit"
                            disabled={!name || !email || loading}
                            className="w-full rounded-xl bg-tc-green px-6 py-3.5 font-bold text-black transition-all hover:bg-tc-green-dim disabled:opacity-40 disabled:cursor-not-allowed pulse-glow"
                          >
                            {loading ? "Sending..." : "Download the guide →"}
                          </button>

                          <p className="text-center text-[11px] text-tc-text-dim">
                            🔒 No payment. No sales call. Direct PDF link in your inbox.
                          </p>
                        </form>
                      </>
                    )}
                  </div>
                </div>
              </ScrollReveal>
            </div>
          </div>
        </div>
      </section>

      {/* ── CTEM stages teaser ── */}
      <section className="py-20 border-t border-tc-border">
        <div className="mx-auto max-w-6xl px-6">
          <ScrollReveal>
            <div className="text-center mb-12">
              <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// THE CTEM LOOP</p>
              <h2 className="text-3xl sm:text-4xl font-bold text-white">
                Five stages. <span className="text-tc-green glow-green">One continuous loop.</span>
              </h2>
              <p className="mt-4 max-w-2xl mx-auto text-tc-text-dim">
                The guide breaks down each stage with operator-language playbooks and the metrics that matter.
              </p>
            </div>
          </ScrollReveal>

          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {[
              { n: "01", t: "Scope", d: "Protect business outcomes, not tool inventories." },
              { n: "02", t: "Discover", d: "Continuous enumeration — assets, services, identities, weaknesses." },
              { n: "03", t: "Prioritize", d: "Exploitability × reachability × blast radius — not raw CVSS." },
              { n: "04", t: "Validate", d: "Re-run the exploit. Re-test the control. Don’t trust dashboards." },
              { n: "05", t: "Mobilize", d: "Fix shipped, validated, and re-tested. Loop closed." },
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
    </main>
  );
}
