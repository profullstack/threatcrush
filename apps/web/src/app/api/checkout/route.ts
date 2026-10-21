import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { catalog, findPlan, findProduct } from "@/lib/catalog";
import {
  availableMethods,
  CHECKOUT_COINS,
  CheckoutError,
  HOSTED_METHOD,
  hostedCheckoutAvailable,
  normalizeMethod,
  PAYPAL_METHOD,
} from "@/lib/checkout";
import { feedPrincipal } from "@/lib/feed-auth";
import { beginPurchase } from "@/lib/purchase";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET: everything on sale and how it can be paid for. */
export async function GET() {
  return NextResponse.json({ products: catalog(), ...(await availableMethods()) });
}

/**
 * POST { product, plan?, method?, org_id?, target?, notes? }
 *
 * Starts a payment and answers { url } to send the buyer to. Sign in (Bearer
 * session token) or use an admin tc_agent_ key. A subscription is for an org
 * (yours, or a personal one made for you); the scan is booked to you. The
 * tier turns on, or the scan is booked, when CoinPay's webhook confirms.
 */
export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send JSON: { product, plan?, method? }" }, { status: 400 });
  }
  const product = findProduct(body.product);
  if (!product) {
    return NextResponse.json(
      { error: `Unknown product. Products: ${catalog().map((p) => p.slug).join(", ")}` },
      { status: 400 },
    );
  }
  if (!product.enabled) {
    return NextResponse.json({ error: `${product.name} is not on sale right now.` }, { status: 403 });
  }
  const plan = findPlan(product, body.plan);
  if (!plan) {
    return NextResponse.json(
      { error: `Unknown plan. Plans: ${product.plans.map((p) => p.id).join(", ")}` },
      { status: 400 },
    );
  }

  const principal = await feedPrincipal(req);
  if (!principal) return unauthorized("Sign in to check out: https://threatcrush.com/auth/login?next=/pricing");

  let method = normalizeMethod(body.method);
  if (body.method !== undefined && body.method !== null && body.method !== "" && !method) {
    return NextResponse.json(
      { error: `Unsupported method. Use ${HOSTED_METHOD}, ${PAYPAL_METHOD} or a coin: ${CHECKOUT_COINS.join(", ")}` },
      { status: 400 },
    );
  }
  if (!method) method = (await hostedCheckoutAvailable()) ? HOSTED_METHOD : CHECKOUT_COINS[0];
  if (method === HOSTED_METHOD && !(await hostedCheckoutAvailable())) {
    return NextResponse.json(
      { error: "CoinPay checkout is not available yet. Pick a coin or PayPal.", ...(await availableMethods()) },
      { status: 409 },
    );
  }

  try {
    const r = await beginPurchase({
      admin: getSupabaseAdmin(),
      principal,
      product,
      plan,
      method,
      orgId: typeof body.org_id === "string" ? body.org_id : null,
      target: typeof body.target === "string" ? body.target : null,
      notes: typeof body.notes === "string" ? body.notes : null,
    });
    return NextResponse.json({
      payment_id: r.id,
      url: r.url,
      provider: r.provider,
      method: r.method,
      product: r.product,
      plan: r.plan,
      amount_usd: r.amount_usd,
      org_id: r.org_id,
      address: r.address ?? null,
      amount_crypto: r.amountCrypto ?? null,
      expires_at: r.expiresAt ?? null,
    });
  } catch (err) {
    if (err instanceof CheckoutError) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    console.error("[checkout] failed", (err as Error).message);
    return NextResponse.json({ error: "Could not start the payment" }, { status: 502 });
  }
}
