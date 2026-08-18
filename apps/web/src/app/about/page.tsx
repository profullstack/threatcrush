import type { Metadata } from "next";
import Link from "next/link";
import { serializeJsonForHtml } from "@/lib/safe-json";
import { SITE_URL } from "@/lib/blog";

export const metadata: Metadata = {
  title: "About — ThreatCrush",
  description:
    "ThreatCrush is built by Profullstack, Inc. — a small, senior team replacing the nine-tool security stack with one open-source agent and a module marketplace.",
  alternates: { canonical: "/about" },
  openGraph: {
    title: "About ThreatCrush",
    description:
      "Built by Profullstack, Inc. — one agent, one marketplace, two layers (CTEM + SIEM/EDR/SOC).",
    url: `${SITE_URL}/about`,
    type: "website",
  },
};

const aboutJsonLd = {
  "@context": "https://schema.org",
  "@type": "AboutPage",
  url: `${SITE_URL}/about`,
  name: "About ThreatCrush",
  about: { "@type": "Organization", name: "ThreatCrush", url: SITE_URL },
};

const breadcrumbJsonLd = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "About", item: `${SITE_URL}/about` },
  ],
};

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-tc-darker pt-24 pb-20">
      <main className="mx-auto max-w-3xl px-6">
        <p className="font-mono text-sm text-tc-green tracking-wider mb-3">// ABOUT</p>
        <h1 className="text-4xl sm:text-5xl font-bold text-white">
          One agent. <span className="text-tc-green glow-green">Two layers.</span> Open by default.
        </h1>

        <p className="mt-6 text-lg text-tc-text-dim leading-relaxed">
          ThreatCrush is a Continuous Threat Exposure Management (CTEM) platform with
          SIEM, EDR, and SOC capabilities folded into the same agent. We&apos;re building
          it because the average security team runs nine separate tools to do work that
          should live in one place, on one taxonomy, with one alert path.
        </p>

        <section className="mt-12">
          <h2 className="text-2xl font-bold text-white mb-3">What we do</h2>
          <p className="text-tc-text-dim leading-relaxed">
            One open-source agent runs on every server you operate. It speaks the
            standards your SOC already uses — MITRE ATT&amp;CK, D3FEND, Sigma, OCSF, NIST
            CSF — and emits events that drop straight into existing SIEM/EDR/SOC stacks.
            A module marketplace lets the community extend detections, scanners, and
            active-defense playbooks without forking the core.
          </p>
        </section>

        <section className="mt-10">
          <h2 className="text-2xl font-bold text-white mb-3">Who we are</h2>
          <p className="text-tc-text-dim leading-relaxed">
            ThreatCrush is a product of{" "}
            <a
              href="https://profullstack.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-tc-green hover:underline"
            >
              Profullstack, Inc.
            </a>{" "}
            — a senior engineering shop that has shipped infrastructure, payments,
            and developer tooling under the <span className="font-mono text-tc-green">@profullstack</span>{" "}
            scope on npm and GitHub for years. The same operators run ThreatCrush.
          </p>
          <p className="mt-3 text-tc-text-dim leading-relaxed">
            We&apos;re small and senior on purpose. We do not raise to hire — we hire when
            the loop demands it. If you&apos;re curious about the team, our{" "}
            <a
              href="https://github.com/profullstack"
              target="_blank"
              rel="noopener noreferrer"
              className="text-tc-green hover:underline"
            >
              GitHub
            </a>{" "}
            is the most honest signal.
          </p>
        </section>

        <section className="mt-10">
          <h2 className="text-2xl font-bold text-white mb-3">How we&apos;re different</h2>
          <ul className="space-y-2 text-tc-text-dim leading-relaxed list-disc pl-6">
            <li>
              <span className="text-tc-green">Open source by default.</span> MIT-licensed
              core. No vendor lock-in.
            </li>
            <li>
              <span className="text-tc-green">Open standards by default.</span> Every
              detection carries a public technique ID — not a vendor SKU.
            </li>
            <li>
              <span className="text-tc-green">One agent.</span> CTEM + SIEM + EDR + SOC
              capabilities from the same daemon, not four agents fighting for the same
              syscall.
            </li>
            <li>
              <span className="text-tc-green">A marketplace, not a roadmap.</span>{" "}
              Community modules close the long tail faster than any single team can.
            </li>
          </ul>
        </section>

        <section className="mt-12 rounded-2xl border border-tc-green/30 bg-tc-card p-6">
          <h2 className="text-xl font-bold text-white mb-3">Get in touch</h2>
          <ul className="text-sm text-tc-text-dim space-y-1.5">
            <li>
              <span className="font-mono text-tc-green">General:</span>{" "}
              <a href="mailto:hello@threatcrush.com" className="hover:text-tc-green">
                hello@threatcrush.com
              </a>
            </li>
            <li>
              <span className="font-mono text-tc-green">Security:</span>{" "}
              <a href="mailto:security@threatcrush.com" className="hover:text-tc-green">
                security@threatcrush.com
              </a>
            </li>
            <li>
              <span className="font-mono text-tc-green">Investors:</span>{" "}
              <Link href="/investors" className="hover:text-tc-green">
                threatcrush.com/investors
              </Link>{" "}
              ·{" "}
              <a href="mailto:invest@threatcrush.com" className="hover:text-tc-green">
                invest@threatcrush.com
              </a>
            </li>
            <li>
              <span className="font-mono text-tc-green">Gov &amp; defense:</span>{" "}
              <a href="mailto:gov@threatcrush.com" className="hover:text-tc-green">
                gov@threatcrush.com
              </a>
            </li>
            <li>
              <span className="font-mono text-tc-green">Schedule:</span>{" "}
              <a
                href="https://calendly.com/chovy"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-tc-green"
              >
                calendly.com/chovy
              </a>
            </li>
          </ul>
        </section>

        <div className="mt-10 flex flex-wrap gap-4">
          <Link
            href="/pricing"
            className="rounded-xl bg-tc-green px-6 py-3 font-bold text-black hover:bg-tc-green-dim"
          >
            Talk to sales
          </Link>
          <Link
            href="/docs"
            className="rounded-xl border border-tc-green/30 px-6 py-3 font-medium text-tc-green hover:bg-tc-green/10"
          >
            Read the docs
          </Link>
        </div>
      </main>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(aboutJsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(breadcrumbJsonLd) }}
      />
    </div>
  );
}
