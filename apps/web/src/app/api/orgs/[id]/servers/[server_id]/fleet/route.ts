import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, serverRoleOf, teamRoleOf } from "@/lib/access";
import { fail, loadFleet, readJson } from "@/lib/teams";

type Params = { params: Promise<{ id: string; server_id: string }> };

// PUT /api/orgs/[id]/servers/[server_id]/fleet { fleet_id | null } — move a
// server into a fleet, between fleets, or out of every fleet. Needs admin
// where it is now and admin where it is going.
export async function PUT(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot move servers");
    const { id: orgId, server_id } = await params;

    const { data: server } = await admin
      .from("servers")
      .select("id, org_id, fleet_id, name")
      .eq("id", server_id)
      .eq("org_id", orgId)
      .maybeSingle();
    if (!server) return fail(404, "Server not found");
    if (!atLeast(await serverRoleOf(admin, p, server), "admin")) return fail(403, "You need admin on this server to move it");

    const body = await readJson(req);
    const target = body?.fleet_id ?? null;
    if (target !== null) {
      if (typeof target !== "string") return fail(400, "fleet_id must be a fleet id or null");
      const fleet = await loadFleet(admin, orgId, target);
      if (!fleet) return fail(404, "Fleet not found");
      if (!atLeast(await teamRoleOf(admin, p, { id: fleet.team_id, org_id: orgId }), "admin")) {
        return fail(403, "You need admin on the team that owns that fleet");
      }
    } else {
      // Out of every fleet means visible to every org member: org admins only.
      const { data: m } = await admin.from("organization_members").select("role").eq("org_id", orgId).eq("user_id", p.userId).maybeSingle();
      if (m?.role !== "owner" && m?.role !== "admin") return fail(403, "Only organization owners and admins can take a server out of every fleet");
    }

    const { data, error } = await admin
      .from("servers")
      .update({ fleet_id: target })
      .eq("id", server.id)
      .select("id, name, fleet_id")
      .single();
    if (error) return fail(500, "Could not move the server");
    return NextResponse.json({ server: data });
  } catch (err) {
    console.error("Move server error:", err);
    return fail(500, "Internal server error");
  }
}
