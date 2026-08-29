import type { Metadata } from "next";
import { SITE_URL } from "@/lib/blog";
import { serializeJsonForHtml } from "@/lib/safe-json";
import GuideReader from "@/components/GuideReader";
import {
  CHECKLIST_TOTAL,
  GUIDE_READ_MINUTES,
  GUIDE_SECTIONS,
  GUIDE_WORD_COUNT,
} from "@/content/ctem-guide.generated";

const PATH = "/read/ctem-guide";
const TITLE = "From Vulnerability Management to CTEM — the operator's guide";
const DESCRIPTION =
  "Read the full CTEM operator's guide in your browser — no form, no paywall. The five stages in operator language, a 90-day implementation playbook, the metrics that matter, and a 27-control readiness checklist that scores your program.";

export const metadata: Metadata = {
  title: TITLE,
  description: DESCRIPTION,
  alternates: { canonical: PATH },
  openGraph: {
    title: "The CTEM Operator's Guide · ThreatCrush",
    description: DESCRIPTION,
    url: `${SITE_URL}${PATH}`,
    type: "article",
  },
  twitter: {
    card: "summary_large_image",
    title: "The CTEM Operator's Guide · ThreatCrush",
    description: DESCRIPTION,
  },
};

/**
 * The whole guide is server-rendered as static HTML, which is the point: the
 * gated version at /get-whitepaper is invisible to search engines and to anyone
 * unwilling to trade an email for a PDF they have not read yet.
 */
const articleJsonLd = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "From Vulnerability Management to Continuous Threat Exposure Management",
  description: DESCRIPTION,
  url: `${SITE_URL}${PATH}`,
  wordCount: GUIDE_WORD_COUNT,
  articleSection: GUIDE_SECTIONS.map((s) => s.title),
  isAccessibleForFree: true,
  inLanguage: "en",
  author: { "@type": "Organization", name: "ThreatCrush", url: SITE_URL },
  publisher: {
    "@type": "Organization",
    name: "ThreatCrush",
    url: SITE_URL,
    logo: { "@type": "ImageObject", url: `${SITE_URL}/logo.svg` },
  },
  mainEntityOfPage: { "@type": "WebPage", "@id": `${SITE_URL}${PATH}` },
};

const breadcrumbJsonLd = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "CTEM Guide", item: `${SITE_URL}${PATH}` },
  ],
};

export default function ReadCtemGuidePage() {
  return (
    <main className="matrix-bg">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(articleJsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(breadcrumbJsonLd) }}
      />

      <section className="border-b border-tc-border grid-pattern">
        <div className="mx-auto max-w-7xl px-6 pt-28 pb-12">
          <div className="max-w-3xl">
            <div className="inline-block rounded-full border border-tc-green/20 bg-tc-green/5 px-4 py-1.5 text-sm font-mono text-tc-green mb-6">
              // FREE GUIDE — READ IT HERE, NO SIGNUP
            </div>
            <h1 className="text-4xl sm:text-5xl font-black tracking-tight leading-[1.08] mb-5">
              <span className="text-white">From </span>
              <span className="text-tc-green glow-green">VM to CTEM</span>
              <span className="text-white"> — the operator&apos;s guide</span>
            </h1>
            <p className="text-lg text-tc-text-dim leading-relaxed mb-6">
              Scanners produce tens of thousands of findings, the exploit window is measured in
              days, and the backlog outlives the engineers who started it. This is the playbook for
              the loop that replaces the queue — and a{" "}
              <span className="text-white font-semibold">{CHECKLIST_TOTAL}-control checklist</span>{" "}
              that scores where your program actually stands.
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-tc-text-dim">
              <span>⏱ {GUIDE_READ_MINUTES} min read</span>
              <span aria-hidden="true">·</span>
              <span>🔓 No paywall, no form</span>
              <span aria-hidden="true">·</span>
              <span>📄 PDF if you want it</span>
            </div>
          </div>
        </div>
      </section>

      <GuideReader />
    </main>
  );
}
