import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * GitHub Marketplace `marketplace_purchase` webhook.
 *
 * Docs: https://docs.github.com/en/apps/github-marketplace/listing-an-app-on-github-marketplace/configuring-a-webhook-to-notify-you-of-plan-changes
 *
 * Everything here is pure so it can be tested without a request or a
 * database. The route is a thin shell over these functions.
 */

export const MARKETPLACE_ACTIONS = [
  "purchased",
  "changed",
  "cancelled",
  "pending_change",
  "pending_change_cancelled",
] as const;

export type MarketplaceAction = (typeof MARKETPLACE_ACTIONS)[number];

export function isMarketplaceAction(value: unknown): value is MarketplaceAction {
  return (MARKETPLACE_ACTIONS as readonly string[]).includes(String(value));
}

export type MarketplacePlan = {
  id?: number;
  name?: string;
  monthly_price_in_cents?: number;
  yearly_price_in_cents?: number;
};

export type MarketplaceAccount = {
  id?: number;
  login?: string;
  type?: string;
  node_id?: string;
  organization_billing_email?: string | null;
};

export type MarketplacePurchase = {
  account?: MarketplaceAccount;
  billing_cycle?: string | null;
  unit_count?: number | null;
  on_free_trial?: boolean | null;
  free_trial_ends_on?: string | null;
  next_billing_date?: string | null;
  plan?: MarketplacePlan;
};

export type MarketplaceEventPayload = {
  action?: string;
  effective_date?: string;
  sender?: { login?: string };
  marketplace_purchase?: MarketplacePurchase;
  previous_marketplace_purchase?: MarketplacePurchase;
};

/**
 * Verify X-Hub-Signature-256.
 *
 * The header is `sha256=<hex>` over the RAW request body, so the body must
 * be read as text before any JSON parsing. Re-serialising a parsed object
 * changes the bytes and the signature will never match.
 *
 * Returns false rather than throwing on every failure mode, including a
 * missing secret: an unconfigured deployment must reject deliveries, not
 * accept them.
 */
export function verifyGithubSignature(
  rawBody: string,
  signatureHeader: string | null | undefined,
  secret: string | null | undefined,
): boolean {
  if (!rawBody || !signatureHeader || !secret) return false;

  const expected = `sha256=${createHmac("sha256", secret).update(rawBody, "utf8").digest("hex")}`;

  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  // timingSafeEqual throws on a length mismatch, which would itself leak
  // the expected length through an exception path. Check first.
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Parse the body for either content type.
 *
 * JSON is what we configure and what GitHub recommends. The urlencoded
 * form sends the same JSON as a single `payload` field, and is accepted
 * here so that a mis-set content type in the listing UI degrades to a
 * working webhook instead of a silent parse failure.
 */
export function parseWebhookBody(
  rawBody: string,
  contentType: string | null | undefined,
): MarketplaceEventPayload | null {
  const type = (contentType ?? "").toLowerCase();
  try {
    if (type.includes("application/x-www-form-urlencoded")) {
      const encoded = new URLSearchParams(rawBody).get("payload");
      if (!encoded) return null;
      return JSON.parse(encoded) as MarketplaceEventPayload;
    }
    return JSON.parse(rawBody) as MarketplaceEventPayload;
  } catch {
    return null;
  }
}

function toIso(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

export type PurchaseRow = {
  github_account_id: number;
  github_account_login: string;
  github_account_type: string | null;
  github_account_node_id: string | null;
  organization_billing_email: string | null;
  plan_id: number | null;
  plan_name: string | null;
  plan_monthly_price_cents: number | null;
  plan_yearly_price_cents: number | null;
  billing_cycle: string | null;
  unit_count: number | null;
  on_free_trial: boolean;
  free_trial_ends_on: string | null;
  next_billing_date: string | null;
  status: string;
  pending_plan_id: number | null;
  pending_plan_name: string | null;
  pending_effective_date: string | null;
  sender_login: string | null;
  effective_date: string | null;
  last_action: string;
  updated_at: string;
};

/**
 * Which purchase object describes the plan the customer is on RIGHT NOW.
 *
 * For `pending_change` the top-level marketplace_purchase is the plan that
 * will take effect later, so the current plan is the previous one. Reading
 * the wrong one here downgrades a customer the moment they schedule a
 * downgrade, rather than at the end of their billing cycle.
 */
export function currentPurchaseFor(
  action: MarketplaceAction,
  payload: MarketplaceEventPayload,
): MarketplacePurchase {
  if (action === "pending_change") {
    return payload.previous_marketplace_purchase ?? payload.marketplace_purchase ?? {};
  }
  return payload.marketplace_purchase ?? {};
}

/**
 * Map a validated event onto the row we store. Returns null when the
 * payload has no usable account id, which is the only field we cannot
 * work without.
 */
export function buildPurchaseRow(
  action: MarketplaceAction,
  payload: MarketplaceEventPayload,
  now: string,
): PurchaseRow | null {
  const current = currentPurchaseFor(action, payload);
  const account = current.account ?? payload.marketplace_purchase?.account ?? {};
  const accountId = typeof account.id === "number" ? account.id : null;
  if (accountId === null) return null;

  const plan = current.plan ?? {};
  const effective = toIso(payload.effective_date);

  // pending_change carries the future plan at the top level; every other
  // action either has no pending change or resolves one.
  const incoming = payload.marketplace_purchase ?? {};
  const isPending = action === "pending_change";

  return {
    github_account_id: accountId,
    github_account_login: account.login ?? String(accountId),
    github_account_type: account.type ?? null,
    github_account_node_id: account.node_id ?? null,
    organization_billing_email: account.organization_billing_email ?? null,
    plan_id: typeof plan.id === "number" ? plan.id : null,
    plan_name: plan.name ?? null,
    plan_monthly_price_cents:
      typeof plan.monthly_price_in_cents === "number" ? plan.monthly_price_in_cents : null,
    plan_yearly_price_cents:
      typeof plan.yearly_price_in_cents === "number" ? plan.yearly_price_in_cents : null,
    billing_cycle: current.billing_cycle ?? null,
    unit_count: typeof current.unit_count === "number" ? current.unit_count : null,
    on_free_trial: current.on_free_trial === true,
    free_trial_ends_on: toIso(current.free_trial_ends_on),
    next_billing_date: toIso(current.next_billing_date),
    // A pending downgrade does not end the subscription, so only an actual
    // `cancelled` event moves the row out of active.
    status: action === "cancelled" ? "cancelled" : "active",
    pending_plan_id: isPending && typeof incoming.plan?.id === "number" ? incoming.plan.id : null,
    pending_plan_name: isPending ? (incoming.plan?.name ?? null) : null,
    pending_effective_date: isPending ? effective : null,
    sender_login: payload.sender?.login ?? null,
    effective_date: effective,
    last_action: action,
    updated_at: now,
  };
}

/**
 * GitHub does not resend failed deliveries, but it does not guarantee
 * order either, and a retry driven by us can arrive late. An event whose
 * effective_date predates what we already applied must not overwrite it.
 *
 * Equal timestamps are allowed through: `purchased` and `changed` can
 * share a second, and the later-arriving one is the one we want.
 */
export function isStaleEvent(
  storedEffectiveDate: string | null | undefined,
  incomingEffectiveDate: string | null | undefined,
): boolean {
  if (!storedEffectiveDate || !incomingEffectiveDate) return false;
  const stored = Date.parse(storedEffectiveDate);
  const incoming = Date.parse(incomingEffectiveDate);
  if (Number.isNaN(stored) || Number.isNaN(incoming)) return false;
  return incoming < stored;
}
