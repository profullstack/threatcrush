import "server-only";
import { randomUUID } from "crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Principal } from "./access";
import type { CatalogPlan, CatalogProduct } from "./catalog";
import {
  CheckoutError,
  startCheckout,
  type CheckoutMethod,
  type CheckoutStarted,
} from "./checkout";
import { orgFor } from "./reputation";

/**
 * Open a payment for a catalog product and record the pending order, so the
 * CoinPay webhook can find it by coinpay_payment_id and grant the tier or
 * book the scan. Shared by /api/checkout and the older per-product routes the
 * CLI calls (/api/v1/reputation/subscribe, /api/v1/entitlements/<m>/subscribe).
 */

const SITE = () => process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";

/** A slug that cannot collide with a hand-made org. */
function personalSlug(userId: string): string {
  return `u-${userId.replace(/-/g, "").slice(0, 12)}`;
}

/**
 * The org a subscription is for. An agent key pays for its own org and must be
 * an admin key. A user names an org they own or administer, or gets the first
 * one they do; a user with none gets a personal org made on the spot (most
 * signups never made one, and an org is what the tier attaches to).
 */
export async function billingOrgFor(
  admin: SupabaseClient,
  p: Principal,
  requested: string | null,
): Promise<string> {
  if (p.kind === "agent") {
    if (p.role !== "admin") throw new CheckoutError("Paying needs an admin key or a signed-in org owner.", 403);
    return p.orgId;
  }
  if (requested) {
    const org = await orgFor(admin, p, requested);
    if (!org) throw new CheckoutError("Name an org you own or administer as org_id.", 403);
    return org;
  }
  const { data: mine } = await admin
    .from("organization_members")
    .select("org_id, role, joined_at")
    .eq("user_id", p.userId)
    .in("role", ["owner", "admin"])
    .order("joined_at", { ascending: true })
    .limit(1);
  if (mine && mine.length > 0) return (mine[0] as { org_id: string }).org_id;

  const slug = personalSlug(p.userId);
  const { data: existing } = await admin.from("organizations").select("id").eq("slug", slug).maybeSingle();
  if (existing) return (existing as { id: string }).id;
  const label = (p.email ?? "").split("@")[0] || "My";
  const { data: created, error } = await admin
    .from("organizations")
    .insert({ name: `${label}'s org`.slice(0, 80), slug, created_by: p.userId })
    .select("id")
    .single();
  if (error || !created) {
    console.error("[checkout] personal org create failed", error?.message);
    throw new CheckoutError("Could not set up an organization for this account.", 500);
  }
  return (created as { id: string }).id;
}

export interface PurchaseInput {
  admin: SupabaseClient;
  principal: Principal;
  product: CatalogProduct;
  plan: CatalogPlan;
  method: CheckoutMethod;
  orgId?: string | null;
  /** Scan only: what to scan and anything we should know. */
  target?: string | null;
  notes?: string | null;
}

export interface PurchaseResult extends CheckoutStarted {
  product: string;
  plan: string;
  amount_usd: number;
  org_id: string | null;
}

export async function beginPurchase(input: PurchaseInput): Promise<PurchaseResult> {
  const { admin, principal, product, plan, method } = input;
  const email = principal.kind === "user" ? principal.email : null;
  const userId = principal.kind === "user" ? principal.userId : null;

  const orgId =
    product.kind === "scan"
      ? principal.kind === "agent"
        ? principal.orgId
        : null
      : await billingOrgFor(admin, principal, input.orgId ?? null);

  // The buyer, as CoinPay should see them: the user, or the org an agent key pays for.
  const accountId = userId ?? (orgId as string);
  const back = `${SITE()}${product.url}`;
  const started = await startCheckout(method, {
    amountUsd: plan.amount_usd,
    description: `ThreatCrush ${plan.name}`,
    email,
    accountId,
    product: product.slug,
    metadata: {
      type: product.kind === "reputation" ? "reputation_pro" : product.kind === "module" ? "module_subscription" : "scan_order",
      plan: plan.id,
      org_id: orgId,
      module: product.kind === "module" ? product.slug : null,
      user_id: userId,
    },
    successUrl: `${back}?payment=success`,
    cancelUrl: `${SITE()}/pricing?payment=cancelled`,
    idempotencyKey: `tc-${product.slug}-${randomUUID()}`,
  });

  const currency = method.toLowerCase();
  let error: { message: string } | null = null;
  if (product.kind === "reputation") {
    ({ error } = await admin.from("reputation_subscriptions").insert({
      org_id: orgId,
      user_id: userId,
      plan: plan.id,
      months: plan.months ?? 1,
      amount_usd: plan.amount_usd,
      currency,
      coinpay_payment_id: started.id,
      status: "pending",
    }));
  } else if (product.kind === "module") {
    ({ error } = await admin.from("module_subscriptions").insert({
      org_id: orgId,
      module: product.slug,
      user_id: userId,
      plan: plan.id,
      months: plan.months ?? 1,
      amount_usd: plan.amount_usd,
      currency,
      coinpay_payment_id: started.id,
      status: "pending",
    }));
  } else {
    ({ error } = await admin.from("scan_orders").insert({
      user_id: userId,
      org_id: orgId,
      email,
      target: input.target?.slice(0, 500) || null,
      notes: input.notes?.slice(0, 4000) || null,
      amount_usd: plan.amount_usd,
      currency,
      coinpay_payment_id: started.id,
      status: "pending",
    }));
  }
  if (error) {
    console.error(`[checkout] ${product.slug} order insert failed`, error.message);
    throw new CheckoutError("Could not record the order", 500);
  }

  return { ...started, product: product.slug, plan: plan.id, amount_usd: plan.amount_usd, org_id: orgId };
}

/** The JSON shape the older subscribe routes have always answered with, plus the new fields. */
export function legacyPurchaseBody(r: PurchaseResult) {
  return {
    payment_id: r.id,
    provider: r.provider,
    method: r.method,
    plan: r.plan,
    amount_usd: r.amount_usd,
    currency: r.method.toLowerCase(),
    address: r.address ?? null,
    amount_crypto: r.amountCrypto ?? null,
    checkout_url: r.url,
    expires_at: r.expiresAt ?? null,
    org_id: r.org_id,
  };
}
