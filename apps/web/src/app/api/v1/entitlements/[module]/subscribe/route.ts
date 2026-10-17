import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { createCoinpayPayment, CoinpayNotConfiguredError } from "@/lib/coinpay-client";
import { feedPrincipal } from "@/lib/feed-auth";
import { moduleSalesEnabled, modulePlan, paidModule } from "@/lib/paid-modules";
import { isReputationCurrency, orgFor, REPUTATION_CURRENCIES } from "@/lib/reputation";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ module: string }> };

/** GET: the module's plans and currencies, and whether it is on sale. */
export async function GET(_req: NextRequest, { params }: Ctx) {
  const mod = paidModule((await params).module);
  if (!mod) return NextResponse.json({ error: "Not a paid module." }, { status: 404 });
  return NextResponse.json({
    module: mod.slug,
    name: mod.name,
    enabled: moduleSalesEnabled(mod),
    plans: mod.plans,
    currencies: REPUTATION_CURRENCIES,
  });
}

/**
 * POST { plan, currency, org_id? }: start a payment for a paid module through
 * CoinPay (crypto only), exactly as Reputation Pro does. An agent key pays for
 * its own org and must be an admin key; a signed-in user names an org they
 * own or administer. The org is entitled when CoinPay's webhook confirms.
 */
export async function POST(req: NextRequest, { params }: Ctx) {
  const mod = paidModule((await params).module);
  if (!mod) return NextResponse.json({ error: "Not a paid module." }, { status: 404 });
  if (!moduleSalesEnabled(mod)) {
    return NextResponse.json({ error: `${mod.name} is not on sale yet.` }, { status: 403 });
  }
  const principal = await feedPrincipal(req);
  if (!principal) return unauthorized("Sign in or use a ThreatCrush API key to subscribe.");
  if (principal.kind === "agent" && principal.role !== "admin") {
    return NextResponse.json({ error: "Paying needs an admin key or a signed-in org owner." }, { status: 403 });
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send JSON: { plan, currency, org_id? }" }, { status: 400 });
  }
  const plan = modulePlan(mod, body.plan ?? "monthly");
  if (!plan) {
    return NextResponse.json({ error: `Unknown plan. Plans: ${mod.plans.map((p) => p.id).join(", ")}` }, { status: 400 });
  }
  const currency = body.currency ?? "usdc_pol";
  if (!isReputationCurrency(currency)) {
    return NextResponse.json({ error: `Unsupported currency. Supported: ${REPUTATION_CURRENCIES.join(", ")}` }, { status: 400 });
  }

  const admin = getSupabaseAdmin();
  const orgId = await orgFor(admin, principal, typeof body.org_id === "string" ? body.org_id : null);
  if (!orgId) return NextResponse.json({ error: "Name an org you own or administer as org_id." }, { status: 403 });

  const base = process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";
  try {
    const cp = await createCoinpayPayment({
      amount_usd: plan.amount_usd,
      currency,
      description: `ThreatCrush ${plan.name}`,
      redirect_url: `${base}/${mod.slug}?payment=success`,
      metadata: { type: "module_subscription", module: mod.slug, org_id: orgId, plan: plan.id },
    });
    const payment = (cp.payment ?? cp) as Record<string, unknown>;
    const paymentId = (payment.id as string | undefined) ?? cp.payment_id;
    if (!paymentId) return NextResponse.json({ error: "CoinPay did not return a payment id" }, { status: 502 });

    const { error } = await admin.from("module_subscriptions").insert({
      org_id: orgId,
      module: mod.slug,
      user_id: principal.kind === "user" ? principal.userId : null,
      plan: plan.id,
      months: plan.months,
      amount_usd: plan.amount_usd,
      currency,
      coinpay_payment_id: paymentId,
      status: "pending",
    });
    if (error) {
      console.error("[modules] subscription insert failed", error.message);
      return NextResponse.json({ error: "Could not record the payment" }, { status: 500 });
    }
    return NextResponse.json({
      payment_id: paymentId,
      module: mod.slug,
      plan: plan.id,
      amount_usd: plan.amount_usd,
      currency,
      address: payment.payment_address ?? payment.address ?? cp.address ?? null,
      amount_crypto: payment.amount_crypto ?? payment.crypto_amount ?? cp.amount_crypto ?? null,
      checkout_url: payment.checkout_url ?? cp.checkout_url ?? null,
      expires_at: payment.expires_at ?? cp.expires_at ?? null,
    });
  } catch (err) {
    if (err instanceof CoinpayNotConfiguredError) {
      return NextResponse.json({ error: "Payments are not configured on this server." }, { status: 503 });
    }
    console.error("[modules] CoinPay create failed", (err as Error).message);
    return NextResponse.json({ error: "Could not start the payment" }, { status: 502 });
  }
}
