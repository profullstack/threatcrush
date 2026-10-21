import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { findPlan, findProduct } from "@/lib/catalog";
import { CHECKOUT_COINS, CheckoutError, normalizeMethod, PAYPAL_METHOD } from "@/lib/checkout";
import { feedPrincipal } from "@/lib/feed-auth";
import { moduleSalesEnabled, paidModule } from "@/lib/paid-modules";
import { beginPurchase, legacyPurchaseBody } from "@/lib/purchase";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ module: string }> };

const CURRENCIES = [...CHECKOUT_COINS.map((c) => c.toLowerCase()), PAYPAL_METHOD.toLowerCase()];

/** GET: the module's plans and currencies, and whether it is on sale. */
export async function GET(_req: NextRequest, { params }: Ctx) {
  const mod = paidModule((await params).module);
  if (!mod) return NextResponse.json({ error: "Not a paid module." }, { status: 404 });
  return NextResponse.json({
    module: mod.slug,
    name: mod.name,
    enabled: moduleSalesEnabled(mod),
    plans: mod.plans,
    currencies: CURRENCIES,
    checkout: "https://threatcrush.com/pricing",
  });
}

/**
 * POST { plan, currency, org_id? }: start a payment for a paid module through
 * CoinPay (any coin the business takes, or `paypal`), exactly as Reputation
 * Pro does. The org is entitled when CoinPay's webhook confirms.
 */
export async function POST(req: NextRequest, { params }: Ctx) {
  const mod = paidModule((await params).module);
  if (!mod) return NextResponse.json({ error: "Not a paid module." }, { status: 404 });
  const product = findProduct(mod.slug);
  if (!product || !product.enabled) {
    return NextResponse.json({ error: `${mod.name} is not on sale yet.` }, { status: 403 });
  }
  const principal = await feedPrincipal(req);
  if (!principal) return unauthorized("Sign in or use a ThreatCrush API key to subscribe.");

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send JSON: { plan, currency, org_id? }" }, { status: 400 });
  }
  const plan = findPlan(product, body.plan ?? "monthly");
  if (!plan) {
    return NextResponse.json({ error: `Unknown plan. Plans: ${mod.plans.map((p) => p.id).join(", ")}` }, { status: 400 });
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
    return NextResponse.json({ ...legacyPurchaseBody(r), module: mod.slug });
  } catch (err) {
    if (err instanceof CheckoutError) return NextResponse.json({ error: err.message }, { status: err.status });
    console.error("[modules] CoinPay create failed", (err as Error).message);
    return NextResponse.json({ error: "Could not start the payment" }, { status: 502 });
  }
}
