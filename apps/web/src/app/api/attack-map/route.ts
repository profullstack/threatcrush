import { NextRequest, NextResponse } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { getPrincipal, serverScopeIn, visibleIn } from "@/lib/access";
import { buildAttackMap, loadMapServers, parseWindow } from "@/lib/attack-map";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/attack-map?org=<id>&window=60 — where attacks on the caller's
// servers come from, and where those servers are. Without `org`: every server
// the caller can see across all their organizations (the /dashboard map).
// Clients poll it every few seconds; identical requests share a snapshot.
export async function GET(req: NextRequest) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return unauthorized();

    const windowMinutes = parseWindow(req.nextUrl.searchParams.get("window"));
    const requested = req.nextUrl.searchParams.get("org");

    let orgIds: string[];
    if (p.kind === "agent") {
      orgIds = [p.orgId];
    } else {
      const { data, error } = await admin.from("organization_members").select("org_id").eq("user_id", p.userId);
      if (error) throw new Error(`memberships: ${error.message}`);
      orgIds = (data ?? []).map((m) => m.org_id as string);
    }
    if (requested) {
      // Not a member and no such org look the same.
      if (!orgIds.includes(requested)) return NextResponse.json({ error: "Not found" }, { status: 404 });
      orgIds = [requested];
    }

    const rows = await loadMapServers(admin, orgIds);
    const visible = [];
    for (const orgId of orgIds) {
      const scope = await serverScopeIn(admin, p, orgId);
      if (scope) visible.push(...visibleIn(scope, rows.filter((r) => r.org_id === orgId)));
    }

    const data = await buildAttackMap(admin, visible, windowMinutes);
    return NextResponse.json(data, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    console.error("Attack map error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
