import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { findPlan, findProduct } from "@/lib/catalog";
import { CHECKOUT_COINS, CheckoutError, normalizeMethod, PAYPAL_METHOD } from "@/lib/checkout";
import { feedPrincipal } from "@/lib/feed-auth";
import { beginPurchase, legacyPurchaseBody } from "@/lib/purchase";
import { REPUTATION_PLANS, reputationProEnabled } from "@/lib/reputation";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CURRENCIES = [...CHECKOUT_COINS.map((c) => c.toLowerCase()), PAYPAL_METHOD.toLowerCase()];

/** GET: the plans and currencies, so a client can render a choice without hard-coding prices. */
export async function GET() {
  return NextResponse.json({
    enabled: reputationProEnabled(),
    plans: REPUTATION_PLANS,
    currencies: CURRENCIES,
    checkout: "https://threatcrush.com/pricing",
  });
}

/**
 * POST { plan, currency, org_id? }: start a Reputation Pro payment through
 * CoinPay: any coin the business takes, or `paypal`. An agent key pays for its
 * own org and must be an admin key; a signed-in user names an org they own or
 * administer (or gets a personal one). The org turns Pro when CoinPay's
 * webhook confirms the payment. /api/checkout is the same thing for every product.
 */
export async function POST(req: NextRequest) {
  const product = findProduct("reputation-pro")!;
  if (!product.enabled) {
    return NextResponse.json(
      { error: "Reputation Pro is not on sale yet. The free lookup works with any ThreatCrush key." },
      { status: 403 },
    );
  }
  const principal = await feedPrincipal(req);
  if (!principal) return unauthorized("Sign in or use a ThreatCrush API key to subscribe.");

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send JSON: { plan, currency, org_id? }" }, { status: 400 });
  }
  const plan = findPlan(product, body.plan ?? "pro-monthly");
  if (!plan) {
    return NextResponse.json(
      { error: `Unknown plan. Plans: ${REPUTATION_PLANS.map((p) => p.id).join(", ")}` },
      { status: 400 },
    );
  }
  const method = normalizeMethod(body.currency ?? "usdc_pol");
  if (!method) {
    return NextResponse.json({ error: `Unsupported currency. Supported: ${CURRENCIES.join(", ")}` }, { status: 400 });
  }

  try {
    const r = await beginPurchase({
      admin: getSupabaseAdmin(),
      principal,
      product,
      plan,
      method,
      orgId: typeof body.org_id === "string" ? body.org_id : null,
    });
    return NextResponse.json(legacyPurchaseBody(r));
  } catch (err) {
    if (err instanceof CheckoutError) return NextResponse.json({ error: err.message }, { status: err.status });
    console.error("[reputation] CoinPay create failed", (err as Error).message);
    return NextResponse.json({ error: "Could not start the payment" }, { status: 502 });
  }
}
