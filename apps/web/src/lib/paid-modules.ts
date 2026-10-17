import type { SupabaseClient } from "@supabase/supabase-js";
import type { Principal } from "./access";
import { isSettledStatus } from "./payment-status";
import { hasActivePeriod, periodEnd, type SubscriptionRow } from "./reputation";

/**
 * Paid first-party modules. The daemon module asks
 * GET /api/v1/entitlements/<module> with the key or session it already has;
 * an org may run the module while any settled module_subscriptions row's
 * period has not ended. Rows come from CoinPay payments (the webhook stamps
 * the period, stacking a renewal on the running one) or from a hand-made
 * 'comp' grant.
 *
 * Sales stay off per module until its env flag is set, so a price is never
 * charged before it is chosen; a comp grant works either way.
 */

export interface ModulePlan {
  id: string;
  name: string;
  months: number;
  amount_usd: number;
}

export interface PaidModule {
  slug: string;
  name: string;
  /** The page that explains it and how to buy it. */
  url: string;
  salesEnv: string;
  plans: ModulePlan[];
}

export const PAID_MODULES: Record<string, PaidModule> = {
  "link-watch": {
    slug: "link-watch",
    name: "Link Watch",
    url: "https://threatcrush.com/link-watch",
    salesEnv: "LINK_WATCH_SALES_ENABLED",
    plans: [
      { id: "monthly", name: "Link Watch, 1 month", months: 1, amount_usd: 9 },
      { id: "yearly", name: "Link Watch, 12 months", months: 12, amount_usd: 90 },
    ],
  },
};

export function paidModule(slug: unknown): PaidModule | null {
  return typeof slug === "string" && Object.hasOwn(PAID_MODULES, slug) ? PAID_MODULES[slug] : null;
}

export function moduleSalesEnabled(mod: PaidModule): boolean {
  return process.env[mod.salesEnv] === "true";
}

export function modulePlan(mod: PaidModule, id: unknown): ModulePlan | null {
  return mod.plans.find((p) => p.id === id) ?? null;
}

/** The latest settled period end among rows, or null. */
export function latestPeriodEnd(rows: SubscriptionRow[]): Date | null {
  let best: number | null = null;
  for (const r of rows) {
    if (!isSettledStatus(r.status) || !r.period_end) continue;
    const t = Date.parse(r.period_end);
    if (best === null || t > best) best = t;
  }
  return best === null ? null : new Date(best);
}

/** The orgs a caller can act for: an agent key's own org, a user's memberships. */
export async function orgsOf(admin: SupabaseClient, p: Principal): Promise<string[]> {
  if (p.kind === "agent") return [p.orgId];
  const { data } = await admin.from("organization_members").select("org_id").eq("user_id", p.userId);
  return (data ?? []).map((r: { org_id: string }) => r.org_id);
}

export interface Entitlement {
  module: string;
  active: boolean;
  until: string | null;
  org_id: string | null;
}

/** Whether any of these orgs may run the module now, and until when. */
export async function entitlementFor(
  admin: SupabaseClient,
  mod: PaidModule,
  orgIds: string[],
  now: number = Date.now(),
): Promise<Entitlement> {
  const none = { module: mod.slug, active: false, until: null, org_id: null };
  if (orgIds.length === 0) return none;
  const { data, error } = await admin
    .from("module_subscriptions")
    .select("org_id, status, period_end")
    .eq("module", mod.slug)
    .in("org_id", orgIds)
    .gt("period_end", new Date(now).toISOString());
  if (error || !data) return none;
  const rows = data as Array<SubscriptionRow & { org_id: string }>;
  if (!hasActivePeriod(rows, now)) return none;
  const best = rows
    .filter((r) => hasActivePeriod([r], now))
    .sort((a, b) => Date.parse(b.period_end as string) - Date.parse(a.period_end as string))[0];
  return { module: mod.slug, active: true, until: best.period_end, org_id: best.org_id };
}

/** When a new payment's period ends, stacked on the org's running period for this module. */
export async function nextPeriodEnd(
  admin: SupabaseClient,
  orgId: string,
  module: string,
  months: number,
  now: Date,
): Promise<Date> {
  const { data } = await admin
    .from("module_subscriptions")
    .select("status, period_end")
    .eq("org_id", orgId)
    .eq("module", module)
    .not("period_end", "is", null);
  return periodEnd(now, months, latestPeriodEnd((data ?? []) as SubscriptionRow[]));
}
