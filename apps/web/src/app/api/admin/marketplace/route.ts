import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";

/**
 * Admin view of the GitHub Marketplace listing's webhook.
 *
 * Reports whether the secret is configured, the current subscription per
 * GitHub account, and the most recent deliveries. GitHub does not resend
 * failed deliveries, so the delivery list is the thing to look at when a
 * customer says they paid and nothing happened.
 *
 * The secret itself is never returned, only whether one is set.
 */
export async function GET(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  const supabase = getSupabaseAdmin();

  const [subs, events] = await Promise.all([
    supabase
      .from("github_marketplace_purchases")
      .select(
        "id, github_account_id, github_account_login, github_account_type, plan_id, plan_name, plan_monthly_price_cents, billing_cycle, unit_count, on_free_trial, free_trial_ends_on, next_billing_date, status, pending_plan_name, pending_effective_date, effective_date, last_action, updated_at",
      )
      .order("updated_at", { ascending: false })
      .limit(200),
    supabase
      .from("github_marketplace_events")
      .select(
        "id, delivery_id, action, github_account_login, effective_date, applied, skip_reason, received_at",
      )
      .order("received_at", { ascending: false })
      .limit(50),
  ]);

  // A missing table is the expected state until the migration is applied
  // by hand, so say that plainly instead of returning a bare 500.
  const missingTable =
    subs.error?.code === "42P01" || events.error?.code === "42P01";
  if (missingTable) {
    return NextResponse.json({
      configured: Boolean(process.env.GITHUB_MARKETPLACE_WEBHOOK_SECRET),
      webhookPath: "/api/webhooks/github/marketplace",
      migrationApplied: false,
      subscriptions: [],
      events: [],
    });
  }

  if (subs.error || events.error) {
    return NextResponse.json({ error: "Failed to load marketplace data" }, { status: 500 });
  }

  return NextResponse.json({
    configured: Boolean(process.env.GITHUB_MARKETPLACE_WEBHOOK_SECRET),
    webhookPath: "/api/webhooks/github/marketplace",
    migrationApplied: true,
    subscriptions: subs.data ?? [],
    events: events.data ?? [],
  });
}
