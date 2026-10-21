import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { feedPrincipal } from "@/lib/feed-auth";
import { entitlementFor, orgsOf, PAID_MODULES } from "@/lib/paid-modules";
import { tierFor } from "@/lib/reputation";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET: what the caller pays for, per org, and their scan orders. Drives the
 * plan card on /account (the upgrade prompt for anyone still on Free).
 */
export async function GET(req: NextRequest) {
  const principal = await feedPrincipal(req);
  if (!principal) return unauthorized();
  const admin = getSupabaseAdmin();
  const orgIds = await orgsOf(admin, principal);

  const orgs = await Promise.all(
    orgIds.map(async (orgId) => {
      const modules: Record<string, { active: boolean; until: string | null }> = {};
      for (const mod of Object.values(PAID_MODULES)) {
        const e = await entitlementFor(admin, mod, [orgId]);
        modules[mod.slug] = { active: e.active, until: e.until };
      }
      return { org_id: orgId, reputation: await tierFor(admin, orgId), modules };
    }),
  );

  let scans: unknown[] = [];
  if (principal.kind === "user") {
    const { data } = await admin
      .from("scan_orders")
      .select("id, target, status, amount_usd, paid_at, created_at")
      .eq("user_id", principal.userId)
      .in("status", ["confirmed", "forwarded"])
      .order("created_at", { ascending: false })
      .limit(10);
    scans = data ?? [];
  }

  const paying = orgs.some((o) => o.reputation === "pro" || Object.values(o.modules).some((m) => m.active));
  return NextResponse.json({ plan: paying ? "paid" : "free", orgs, scans, pricing: "https://threatcrush.com/pricing" });
}
