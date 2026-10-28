import { NextRequest, NextResponse } from "next/server";
import { toCoinPayCosts } from "@profullstack/fleet";
import { unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal } from "@/lib/access";
import { inventoryOrgIds } from "@/lib/fleet-inventory";

// GET /api/fleet/costs — the recurring costs in every inventory the caller can
// read, in the shape CoinPay imports (toCoinPayCosts from @profullstack/fleet).
// `key` is stable per org + device, so a re-import updates instead of duplicating.
// Devices with no stated amount are left out, never guessed.
export async function GET(req: NextRequest) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return unauthorized();
    if (p.kind !== "user") {
      return NextResponse.json({ error: "Costs belong to people: use a signed-in session, not an agent key" }, { status: 403 });
    }

    const { data: memberships } = await admin.from("organization_members").select("org_id").eq("user_id", p.userId);
    const orgIds = await inventoryOrgIds(admin, p, (memberships ?? []).map((m) => m.org_id as string));
    if (orgIds.length === 0) return NextResponse.json({ organizations: [], costs: [] });

    const [{ data: orgRows }, { data: inventories, error }] = await Promise.all([
      admin.from("organizations").select("id, name, slug").in("id", orgIds),
      admin.from("fleet_inventories").select("org_id, document, updated_at").in("org_id", orgIds),
    ]);
    if (error) {
      console.error("Fleet costs: failed to load inventories:", error);
      return NextResponse.json({ error: "Failed to load costs" }, { status: 500 });
    }
    const orgs = new Map((orgRows ?? []).map((o) => [o.id as string, o as { id: string; name: string; slug: string }]));

    const organizations = [];
    const costs = [];
    for (const inv of inventories ?? []) {
      const org = orgs.get(inv.org_id as string);
      const source = `threatcrush:${org?.slug ?? inv.org_id}`;
      try {
        const rows = toCoinPayCosts(inv.document as object, { source }).map((c) => ({
          ...c,
          key: `${source}:${c.key}`,
          org: { id: inv.org_id, slug: org?.slug ?? null, name: org?.name ?? null },
        }));
        costs.push(...rows);
        organizations.push({ id: inv.org_id, slug: org?.slug ?? null, name: org?.name ?? null, updated_at: inv.updated_at, costs: rows.length });
      } catch (err) {
        console.error(`Fleet costs: inventory for ${inv.org_id} did not parse:`, err);
      }
    }
    return NextResponse.json({ organizations, costs });
  } catch (err) {
    console.error("Fleet costs error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
