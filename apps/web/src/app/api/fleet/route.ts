import { NextRequest, NextResponse } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, serverScopeIn, visibleIn } from "@/lib/access";
import { buildFleet } from "@/lib/fleet";

// GET /api/fleet — every ThreatCrush install the caller can see, across every
// organization they belong to (an agent key: its team's fleets), with a
// summary for the dashboard.
export async function GET(req: NextRequest) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return unauthorized();

    let orgIds: string[];
    if (p.kind === "agent") {
      orgIds = [p.orgId];
    } else {
      const { data: memberships, error: memberError } = await admin
        .from("organization_members")
        .select("org_id")
        .eq("user_id", p.userId);
      if (memberError) {
        console.error("Fleet: failed to load memberships:", memberError);
        return NextResponse.json({ error: "Failed to load fleet" }, { status: 500 });
      }
      orgIds = (memberships ?? []).map((m) => m.org_id as string);
    }

    const orgs = new Map<string, { name: string; slug: string }>();
    if (orgIds.length === 0) return NextResponse.json(buildFleet([], orgs));

    const [{ data: orgRows }, { data: rows, error }, { data: fleets }] = await Promise.all([
      admin.from("organizations").select("id, name, slug").in("id", orgIds),
      admin
        .from("servers")
        .select("id, name, hostname, ip_address, org_id, fleet_id, last_seen, threatcrushd_version, config, config_saved_at, created_at")
        .in("org_id", orgIds),
      admin.from("fleets").select("id, name").in("org_id", orgIds),
    ]);
    if (error) {
      console.error("Fleet: failed to load servers:", error);
      return NextResponse.json({ error: "Failed to load fleet" }, { status: 500 });
    }
    for (const o of orgRows ?? []) orgs.set(o.id, { name: o.name, slug: o.slug });

    const visible = [];
    for (const orgId of orgIds) {
      const scope = await serverScopeIn(admin, p, orgId);
      if (!scope) continue;
      visible.push(...visibleIn(scope, (rows ?? []).filter((r) => r.org_id === orgId)));
    }

    const fleetNames = new Map((fleets ?? []).map((f) => [f.id as string, f.name as string]));
    return NextResponse.json(buildFleet(visible, orgs, Date.now(), fleetNames));
  } catch (err) {
    console.error("Fleet error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
