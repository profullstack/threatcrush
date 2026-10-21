import type { Metadata } from "next";
import Link from "next/link";
import { CheckoutPanel } from "@/components/CheckoutPanel";
import { SITE_URL } from "@/lib/blog";
import { catalog, SCAN_PRICE_USD, type CatalogProduct } from "@/lib/catalog";
import { availableMethods } from "@/lib/checkout";
import { DAILY_LIMIT, UPGRADE } from "@/lib/reputation";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Pricing: free agent, paid extras, $400 human-reviewed scan",
  description:
    "ThreatCrush is free and open source. Reputation Pro is $15/mo, Link Watch $9/mo, and a human-reviewed security scan is $400. Pay with crypto or PayPal through CoinPay.",
  alternates: { canonical: "/pricing" },
  openGraph: {
    title: "ThreatCrush pricing",
    description: "Free agent and scanner. Reputation Pro $15/mo, Link Watch $9/mo, human-reviewed scan $400.",
    url: `${SITE_URL}/pricing`,
    type: "website",
  },
};

const FREE = [
  "CLI, daemon, desktop app and code scanner, open source",
  "Live attack map, bans, alerts by email, Slack, Discord or SMS",
  "Teams, fleets and agent keys",
  `${DAILY_LIMIT.free} IP reputation lookups a day`,
  "The community threat feed at /traffic",
];

const LINK_WATCH = [
  "crawls every site you list on a schedule",
  "alerts on 404s, 5xx and dead hosts, with the page that links to it",
  "runs inside the daemon you already have",
  "per organization: every site and server included",
];

const SCAN = [
  "we run the ThreatCrush engine on your repo, domain or app",
  "an engineer triages every finding by hand; false positives dropped",
  "a written report with severity, reproduction steps and fixes",
  "a re-scan after your fixes land",
];

function price(p: CatalogProduct): string {
  return p.plans
    .map((pl) => (pl.months === null ? `$${pl.amount_usd} one-time` : `$${pl.amount_usd}/${pl.months === 1 ? "mo" : "yr"}`))
    .join(" or ");
}

function Card({
  title,
  price: priceText,
  bullets,
  highlight = false,
  children,
}: {
  title: string;
  price: string;
  bullets: string[];
  highlight?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div
      className={`flex flex-col rounded-2xl border bg-tc-card p-6 ${highlight ? "border-tc-green/60 glow-box" : "border-tc-border"}`}
    >
      <h2 className="text-xl font-bold text-white">{title}</h2>
      <p className="mt-1 font-mono text-tc-green">{priceText}</p>
      <ul className="mt-4 flex-1 space-y-2 text-sm text-tc-text-dim">
        {bullets.map((b) => (
          <li key={b} className="flex gap-2">
            <span className="text-tc-green">+</span>
            <span>{b}</span>
          </li>
        ))}
      </ul>
      <div className="mt-6">{children}</div>
    </div>
  );
}

export default async function PricingPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const products = catalog();
  const { methods } = await availableMethods();
  const rep = products.find((p) => p.slug === "reputation-pro")!;
  const lw = products.find((p) => p.slug === "link-watch")!;
  const scan = products.find((p) => p.slug === "scan")!;

  return (
    <main className="min-h-screen bg-tc-darker pt-24 pb-20 text-tc-text">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <p className="font-mono text-sm tracking-wider text-tc-green">// PRICING</p>
        <h1 className="mt-3 text-4xl font-bold text-white sm:text-5xl">
          Free to run. <span className="text-tc-green glow-green">Pay for the extras.</span>
        </h1>
        <p className="mt-4 max-w-2xl text-lg text-tc-text-dim">
          The agent, the daemon and the scanner are free and open source. Pay only for the data, the modules and the
          people. Checkout is through CoinPay: 15 coins or PayPal.
        </p>

        {sp.payment === "cancelled" && (
          <p className="mt-6 rounded-lg border border-tc-border bg-tc-card p-4 text-sm text-tc-text-dim">
            Checkout was cancelled and nothing was charged. Pick a plan below to try again.
          </p>
        )}

        <div className="mt-10 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          <Card title="Free" price="$0" bullets={FREE}>
            <a
              href="/auth/signup?next=/dashboard"
              className="block w-full rounded-lg border border-tc-green/40 px-4 py-2.5 text-center text-sm font-bold text-tc-green hover:bg-tc-green/10"
            >
              Create a free account
            </a>
          </Card>

          <Card title="Reputation Pro" price={price(rep)} bullets={UPGRADE.adds} highlight>
            <CheckoutPanel
              product={rep.slug}
              plans={rep.plans}
              methods={methods}
              enabled={rep.enabled}
              cta="Upgrade to Pro"
              returnPath="/pricing"
            />
          </Card>

          <Card title="Link Watch" price={price(lw)} bullets={LINK_WATCH}>
            <CheckoutPanel
              product={lw.slug}
              plans={lw.plans}
              methods={methods}
              enabled={lw.enabled}
              cta="Turn on Link Watch"
              returnPath="/pricing"
            />
          </Card>

          <Card title="Security Scan" price={`$${SCAN_PRICE_USD} one-time`} bullets={SCAN}>
            <CheckoutPanel
              product={scan.slug}
              plans={scan.plans}
              methods={methods}
              enabled={scan.enabled}
              askTarget
              cta={`Book the $${SCAN_PRICE_USD} scan`}
              returnPath="/pricing"
            />
          </Card>
        </div>

        <section className="mt-14 grid gap-6 md:grid-cols-2">
          <div className="rounded-2xl border border-tc-border bg-tc-card p-6">
            <h2 className="text-xl font-bold text-white">Bigger than one app?</h2>
            <p className="mt-2 text-sm text-tc-text-dim">
              Several services, cloud configuration, manual testing: we scope it and send a fixed price before any work
              starts.{" "}
              <Link href="/hire" className="text-tc-green underline">
                Get a quote
              </Link>
              .
            </p>
          </div>
          <div className="rounded-2xl border border-tc-border bg-tc-card p-6">
            <h2 className="text-xl font-bold text-white">How paying works</h2>
            <ul className="mt-2 space-y-1 text-sm text-tc-text-dim">
              <li>Pick a coin or PayPal; CoinPay shows the amount and the address or the PayPal button.</li>
              <li>A subscription turns on for your organization as soon as the payment confirms.</li>
              <li>A scan is booked when the payment confirms; we write back within one business day.</li>
              <li>
                Questions:{" "}
                <a className="text-tc-green underline" href="mailto:hello@threatcrush.com">
                  hello@threatcrush.com
                </a>
              </li>
            </ul>
          </div>
        </section>
      </div>
    </main>
  );
}
