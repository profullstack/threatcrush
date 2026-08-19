import type { Metadata } from "next";
import { SITE_URL } from "@/lib/blog";
import { HireForm } from "@/components/HireForm";

export const metadata: Metadata = {
  title: "Hire Us — human-led security assessments",
  description:
    "Have our team run the scan for you and read the results by hand. Engagements start at $400 for a scan with human input and scale with the complexity of your application.",
  alternates: { canonical: "/hire" },
  openGraph: {
    title: "Hire Us · ThreatCrush",
    description:
      "Human-led security assessments built on the ThreatCrush engine. Starts at $400 for a scan with human input.",
    url: `${SITE_URL}/hire`,
    type: "website",
  },
};

const serviceJsonLd = {
  "@context": "https://schema.org",
  "@type": "Service",
  name: "ThreatCrush human-led security assessment",
  serviceType: "Application security assessment",
  url: `${SITE_URL}/hire`,
  provider: { "@type": "Organization", name: "ThreatCrush", url: SITE_URL },
  areaServed: "Worldwide",
  offers: {
    "@type": "Offer",
    priceCurrency: "USD",
    availability: "https://schema.org/InStock",
    url: `${SITE_URL}/hire`,
    priceSpecification: {
      "@type": "PriceSpecification",
      priceCurrency: "USD",
      minPrice: 400,
    },
  },
};

const breadcrumbJsonLd = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Hire Us", item: `${SITE_URL}/hire` },
  ],
};

const deliverables = [
  {
    title: "A scan you didn't have to run",
    body: "We point the ThreatCrush engine at your repositories and infrastructure, tune the rules to your stack, and re-run until the picture is complete.",
  },
  {
    title: "Findings read by a human",
    body: "Every finding is triaged by an engineer before you see it. False positives get dropped; real issues arrive with severity, reproduction steps, and a fix.",
  },
  {
    title: "A report you can hand to anyone",
    body: "One document for your engineers and one summary for whoever asked — customer, auditor, or board — mapped to MITRE ATT&CK and NIST CSF.",
  },
  {
    title: "A working session at the end",
    body: "We walk the findings with your team, answer questions, and agree what gets fixed first. A re-scan after your fixes land is part of the engagement.",
  },
];

const steps = [
  {
    n: "01",
    title: "Tell us about the app",
    body: "Stack, size, where it runs, and what you are worried about. A couple of minutes on the form below.",
  },
  {
    n: "02",
    title: "We scope it and send a number",
    body: "You get a fixed price and a timeline in writing before anything starts. No hourly surprises.",
  },
  {
    n: "03",
    title: "We scan, triage, and report",
    body: "Automated coverage first, then human review of everything it surfaced — plus the things a scanner cannot see.",
  },
  {
    n: "04",
    title: "You fix, we verify",
    body: "We re-run the assessment against your fixes so the close-out report shows the delta, not just the starting point.",
  },
];

export default function HirePage() {
  return (
    <div className="min-h-screen bg-tc-darker pt-24 pb-20">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(serviceJsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbJsonLd) }}
      />

      <main className="mx-auto max-w-4xl px-6">
        <p className="font-mono text-sm text-tc-green tracking-wider mb-3">// HIRE US</p>
        <h1 className="text-4xl sm:text-5xl font-bold text-white leading-tight">
          Let us run it,{" "}
          <span className="text-tc-green glow-green">and read the results</span>.
        </h1>
        <p className="mt-6 max-w-2xl text-lg text-tc-text-dim leading-relaxed">
          ThreatCrush is open source and you can run it yourself. When you would rather
          hand the whole thing to someone, our team scans your application, triages every
          finding by hand, and gives you a report that says what is actually broken and
          what to do about it.
        </p>

        {/* No public rate card, but the floor is stated plainly so nobody has to book a
            call just to find out whether they can afford us. */}
        <section className="mt-10 relative bg-tc-card border border-tc-border rounded-2xl overflow-hidden">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-tc-green to-transparent opacity-40" />
          <div className="p-8">
            <h2 className="text-2xl font-bold text-white">What it costs</h2>
            <p className="mt-3 text-tc-text-dim leading-relaxed">
              We don&apos;t quote prices up front, because no two applications are the
              same amount of work. What we can tell you is where it starts:{" "}
              <strong className="text-white">
                engagements begin at $400 for a scan with human input
              </strong>{" "}
              — the engine runs, and an engineer reads and triages what it found.
            </p>
            <p className="mt-3 text-tc-text-dim leading-relaxed">
              From there the price moves with the complexity of the app: how many
              services and repositories are in scope, what it is written in, whether
              there is infrastructure and cloud configuration to review, and how much
              manual testing the thing warrants. Tell us about it below and we come back
              with a fixed number and a timeline before any work begins.
            </p>
            <p className="mt-3 text-sm text-tc-text-dim">
              Prefer to self-serve? The{" "}
              <a href="/docs" className="text-tc-green hover:underline">
                docs
              </a>{" "}
              will get you scanning in a few minutes, and the{" "}
              <a href="/store" className="text-tc-green hover:underline">
                module store
              </a>{" "}
              covers what the agent can do.
            </p>
          </div>
        </section>

        <section className="mt-12">
          <h2 className="text-2xl font-bold text-white mb-5">What you get</h2>
          <ul className="grid gap-4 sm:grid-cols-2">
            {deliverables.map((d) => (
              <li key={d.title} className="bg-tc-card border border-tc-border rounded-xl p-5">
                <h3 className="text-white font-bold">{d.title}</h3>
                <p className="mt-2 text-sm text-tc-text-dim leading-relaxed">{d.body}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-12">
          <h2 className="text-2xl font-bold text-white mb-5">How it runs</h2>
          <ol className="space-y-4">
            {steps.map((s) => (
              <li key={s.n} className="flex gap-4">
                <span className="font-mono text-tc-green text-sm pt-1 shrink-0">{s.n}</span>
                <div>
                  <h3 className="text-white font-bold">{s.title}</h3>
                  <p className="mt-1 text-sm text-tc-text-dim leading-relaxed">{s.body}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <section className="mt-14" id="inquiry">
          <h2 className="text-2xl font-bold text-white">Tell us about your app</h2>
          <p className="mt-2 text-tc-text-dim">
            A few details is enough to scope it. We reply with a price and a timeline,
            usually the same business day.
          </p>
          <div className="mt-6">
            <HireForm />
          </div>
        </section>
      </main>
    </div>
  );
}
