import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { buildFleet } from "@/lib/fleet";

// GET /api/fleet — every ThreatCrush install across every organization the
// signed-in user belongs to, with a summary for the dashboard.
export async function GET(req: NextRequest) {
  try {
    const user = await getAuthenticatedRequestUser(req);
    if (!user) return unauthorized();

    const admin = getSupabaseAdmin();
    const { data: memberships, error: memberError } = await admin
      .from("organization_members")
      .select("org_id, organizations ( id, name, slug )")
      .eq("user_id", user.userId);

    if (memberError) {
      console.error("Fleet: failed to load memberships:", memberError);
      return NextResponse.json({ error: "Failed to load fleet" }, { status: 500 });
    }

    const orgs = new Map<string, { name: string; slug: string }>();
    for (const m of memberships ?? []) {
      const org = (Array.isArray(m.organizations) ? m.organizations[0] : m.organizations) as
        | { id: string; name: string; slug: string }
        | null;
      if (org) orgs.set(org.id, { name: org.name, slug: org.slug });
    }

    if (orgs.size === 0) {
      return NextResponse.json(buildFleet([], orgs));
    }

    const { data: rows, error } = await admin
      .from("servers")
      .select("id, name, hostname, ip_address, org_id, last_seen, threatcrushd_version, config, config_saved_at, created_at")
      .in("org_id", [...orgs.keys()]);

    if (error) {
      console.error("Fleet: failed to load servers:", error);
      return NextResponse.json({ error: "Failed to load fleet" }, { status: 500 });
    }

    return NextResponse.json(buildFleet(rows ?? [], orgs));
  } catch (err) {
    console.error("Fleet error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
