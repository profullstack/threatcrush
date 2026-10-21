import type { Metadata } from "next";
import Link from "next/link";
import { CheckoutPanel } from "@/components/CheckoutPanel";
import { PaymentNotice } from "@/components/PaymentNotice";
import { availableMethods } from "@/lib/checkout";
import { moduleSalesEnabled, PAID_MODULES } from "@/lib/paid-modules";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Link Watch — find broken links before your visitors do | ThreatCrush",
  description:
    "A ThreatCrush module that crawls your sites on a schedule and alerts on every broken link and asset: 404s, 5xx and dead hosts, once per break, with the page that links to it. $9/mo, paid with crypto or PayPal.",
};

const MOD = PAID_MODULES["link-watch"];

const WHAT = [
  "walks each site from its root and /sitemap.xml, every page you link to yourself",
  "checks every link, image, script, stylesheet and iframe on them, internal and external",
  "reports 404s, other 4xx, 5xx and hosts that no longer resolve; not bot walls (401/403/429)",
  "one event per break, when it first appears, with the pages that link to it",
  "events go through your existing ThreatCrush alert rules: email, Slack, Discord, SMS",
];

export default async function LinkWatchPage() {
  const onSale = moduleSalesEnabled(MOD);
  const { methods } = await availableMethods();
  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <section className="border-b border-tc-border bg-gradient-to-b from-tc-dark to-tc-darker">
        <div className="mx-auto max-w-5xl px-4 py-14 sm:py-20">
          <PaymentNotice success="Payment received. Link Watch turns on for your organization as soon as it confirms; the daemon picks it up on its next run." />
          <p className="font-mono text-sm text-tc-green">// module: link-watch</p>
          <h1 className="mt-3 text-3xl font-bold sm:text-4xl">Your site links to pages that 404.</h1>
          <p className="mt-4 max-w-2xl text-tc-text-dim">
            A renamed route, a deleted asset, a partner's dead domain: a broken link costs a signup without anyone
            noticing. Link Watch runs inside the ThreatCrush daemon you already have, crawls the sites you list on a
            schedule, and alerts the moment something breaks.
          </p>
        </div>
      </section>

      <section className="mx-auto grid max-w-5xl gap-8 px-4 py-12 md:grid-cols-2">
        <div className="rounded-lg border border-tc-border bg-tc-dark p-6">
          <h2 className="text-xl font-semibold">What it does</h2>
          <ul className="mt-4 list-disc space-y-1 pl-5 text-tc-text-dim">
            {WHAT.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg border border-tc-green/40 bg-tc-dark p-6">
          <h2 className="text-xl font-semibold">{MOD.name}</h2>
          <p className="mt-1 text-sm text-tc-text-dim">
            {MOD.plans.map((p) => `$${p.amount_usd} / ${p.months === 1 ? "month" : `${p.months} months`}`).join(" · ")}
            , per organization, every site and server included. Paid with any of 15 coins or PayPal through
            CoinPay.
          </p>
          <div className="mt-6">
            <CheckoutPanel
              product={MOD.slug}
              plans={MOD.plans}
              methods={methods}
              enabled={onSale}
              cta="Turn on Link Watch"
              returnPath="/link-watch"
            />
          </div>
        </div>
      </section>

      <section className="border-t border-tc-border bg-tc-dark">
        <div className="mx-auto max-w-5xl px-4 py-12">
          <h2 className="text-xl font-semibold">Set it up</h2>
          <pre className="mt-4 overflow-x-auto rounded-lg border border-tc-border bg-tc-darker p-4 font-mono text-sm text-tc-green">
            {`# /etc/threatcrush/threatcrushd.conf.d/link-watch.conf
[modules.link-watch]
sites = ["https://example.com"]
interval_hours = 24

# Subscribe (THREATCRUSH_API_KEY is an admin tc_agent_ key)
auth="Authorization: Bearer $THREATCRUSH_API_KEY"
curl -X POST -H "$auth" -H "content-type: application/json" \\
  -d '{"plan":"monthly","currency":"usdc_pol"}' https://threatcrush.com/api/v1/entitlements/link-watch/subscribe

# Is this org entitled?
curl -H "$auth" https://threatcrush.com/api/v1/entitlements/link-watch`}
          </pre>
          <p className="mt-4 text-tc-text-dim">
            Not a customer yet? <Link className="text-tc-green underline" href="/auth/signup">Create an account</Link>.
          </p>
        </div>
      </section>
    </main>
  );
}
