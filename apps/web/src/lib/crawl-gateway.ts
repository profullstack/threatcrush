import { createGateway } from "@profullstack/x402-gateway";
import { x402Proxy } from "@profullstack/x402-gateway/next";

/**
 * Sells crawl access to AI training crawlers (GPTBot, ClaudeBot, CCBot,
 * meta-externalagent, Bytespider, Applebot-Extended, ...) by the day over
 * x402, settled by CoinPay in USDC. People, Googlebot and the retrieval
 * crawlers behind AI search pass through untouched.
 *
 * Runs inside the middleware, so nothing here may import Node-only modules.
 * The env is read through a non-literal key on purpose: Next inlines
 * `process.env.NAME` at build time, and these are runtime secrets. Without
 * COINPAY_X402_KEY and CRAWL_PAY_TO the gateway still answers training
 * crawlers with 402, just with an empty offer.
 */
const env = (name: string) => process.env[name];

/**
 * Every crawl pass sold lands in crawl_sales with the site it was for and the
 * payer (x402 only knows a wallet address), so a sale is visible here and not
 * only in CoinPay. Plain fetch to PostgREST: this runs in the middleware.
 * Errors are swallowed by the gateway, so a failed write never costs the
 * buyer the pass.
 */
async function recordCrawlSale(sale: import("@profullstack/x402-gateway").Sale): Promise<void> {
  const url = env("NEXT_PUBLIC_SUPABASE_URL");
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  console.log(
    "[x402] sale",
    JSON.stringify({ property: "threatcrush.com", payer: sale.payer, days: sale.days, cents: sale.totalCents }),
  );
  if (!url || !key) return;
  await fetch(`${url.replace(/\/+$/, "")}/rest/v1/crawl_sales`, {
    method: "POST",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({
      property: "threatcrush.com",
      payer: sale.payer,
      ref: sale.ref,
      user_agent: (sale.userAgent || "").slice(0, 500),
      days: sale.days,
      total_cents: sale.totalCents,
      currency: sale.currency,
      expires_at: sale.expiresAt,
    }),
  });
}

export const gateway = createGateway({
  siteUrl: env("SITE_URL") || env("NEXT_PUBLIC_SITE_URL") || "https://threatcrush.com",
  siteName: "ThreatCrush",
  coinpay: { apiKey: env("COINPAY_X402_KEY") },
  payTo: env("CRAWL_PAY_TO"),
  contact: "mailto:support@threatcrush.com",
  onSale: recordCrawlSale,
});

/** Resolves to a Response for a refused crawler, or undefined to carry on. */
export const gate = x402Proxy(gateway);
