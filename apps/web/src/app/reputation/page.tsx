import type { Metadata } from "next";
import Link from "next/link";
import { CheckoutPanel } from "@/components/CheckoutPanel";
import { PaymentNotice } from "@/components/PaymentNotice";
import { availableMethods } from "@/lib/checkout";
import { DAILY_LIMIT, REPUTATION_PLANS, reputationProEnabled, UPGRADE } from "@/lib/reputation";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "IP reputation API — ThreatCrush Reputation Pro",
  description:
    "Look up any IP against the ThreatCrush community threat database. Free verdicts with an API key; Reputation Pro ($15/mo) adds 90-day history, /24 neighbourhood, ASN, watch lists and score reasons. Pay with crypto or PayPal.",
};

const FREE = [
  "listed or not, by the corroboration bar behind /traffic",
  "a 0-100 threat score, severity, reporters, last seen",
  "the last 7 days of community reports",
  `${DAILY_LIMIT.free} lookups a day with any free API key`,
];

export default async function ReputationPage() {
  const onSale = reputationProEnabled();
  const { methods } = await availableMethods();
  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <section className="border-b border-tc-border bg-gradient-to-b from-tc-dark to-tc-darker">
        <div className="mx-auto max-w-5xl px-4 py-14 sm:py-20">
          <PaymentNotice success="Payment received. Reputation Pro turns on for your organization as soon as it confirms, usually within minutes." />
          <p className="font-mono text-sm text-tc-green">// reputation api</p>
          <h1 className="mt-3 text-3xl font-bold sm:text-4xl">Is this address attacking anyone?</h1>
          <p className="mt-4 max-w-2xl text-tc-text-dim">
            Every linked ThreatCrush daemon reports the attacks it blocks. Look any IP up against that pooled database.
            The human-reviewed public cut is free and keyless on{" "}
            <a className="text-tc-green underline" href="https://nichedb.dev/reputation">
              nichedb.dev/reputation
            </a>
            , with abuse.ch malware IPs and domains beside it.
          </p>
        </div>
      </section>

      <section className="mx-auto grid max-w-5xl gap-8 px-4 py-12 md:grid-cols-2">
        <div className="rounded-lg border border-tc-border bg-tc-dark p-6">
          <h2 className="text-xl font-semibold">Free</h2>
          <ul className="mt-4 list-disc space-y-1 pl-5 text-tc-text-dim">
            {FREE.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg border border-tc-green/40 bg-tc-dark p-6">
          <h2 className="text-xl font-semibold">Reputation Pro</h2>
          <p className="mt-1 text-sm text-tc-text-dim">
            {REPUTATION_PLANS.map((p) => `$${p.amount_usd} / ${p.months === 1 ? "month" : `${p.months} months`}`).join(
              " · ",
            )}
            , paid with any of 15 coins or PayPal through CoinPay
          </p>
          <ul className="mt-4 list-disc space-y-1 pl-5 text-tc-text-dim">
            {UPGRADE.adds.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
          <div className="mt-6">
            <CheckoutPanel
              product="reputation-pro"
              plans={REPUTATION_PLANS}
              methods={methods}
              enabled={onSale}
              cta="Upgrade to Pro"
              returnPath="/reputation"
            />
          </div>
          <p className="mt-3 text-xs text-tc-text-dim">
            Or subscribe from the CLI or the API below. All plans: <Link className="text-tc-green underline" href="/pricing">pricing</Link>.
          </p>
        </div>
      </section>

      <section className="border-t border-tc-border bg-tc-dark">
        <div className="mx-auto max-w-5xl px-4 py-12">
          <h2 className="text-xl font-semibold">Use it</h2>
          <pre className="mt-4 overflow-x-auto rounded-lg border border-tc-border bg-tc-darker p-4 font-mono text-sm text-tc-green">
            {`# CLI
threatcrush reputation 45.148.10.7 evil.example     # one, or many in one bulk call
threatcrush reputation watch add mail.example.com --note "our MX"   # Pro: alerts on change
threatcrush reputation subscribe --plan pro-monthly --currency usdc_pol   # or paypal, btc, sol, doge ...

# MCP (agents): https://threatcrush.com/api/mcp  tools reputation_lookup, reputation_bulk

# API (THREATCRUSH_API_KEY is your tc_agent_ key)
auth="Authorization: Bearer $THREATCRUSH_API_KEY"
curl -H "$auth" https://threatcrush.com/api/v1/reputation/45.148.10.7
curl -X POST -H "$auth" -H "content-type: application/json" \\
  -d '{"indicators":["45.148.10.7","evil.example"]}' https://threatcrush.com/api/v1/reputation/bulk
curl -X POST -H "$auth" -H "content-type: application/json" \\
  -d '{"plan":"pro-monthly","currency":"usdc_pol"}' https://threatcrush.com/api/v1/reputation/subscribe`}
          </pre>
          <p className="mt-4 text-tc-text-dim">
            The pooled feed itself is at <Link className="text-tc-green underline" href="/traffic">/traffic</Link>.
          </p>
        </div>
      </section>
    </main>
  );
}
