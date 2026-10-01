import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, teamRoleOf } from "@/lib/access";
import { cleanName, fail, loadFleet, loadTeam, readJson } from "@/lib/teams";

type Params = { params: Promise<{ id: string; fleet_id: string }> };

// PATCH /api/orgs/[id]/fleets/[fleet_id] { name?, team_id? } — rename it, or
// hand it to another team (admin on both teams).
export async function PATCH(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot change fleets");
    const { id: orgId, fleet_id } = await params;

    const fleet = await loadFleet(admin, orgId, fleet_id);
    if (!fleet) return fail(404, "Fleet not found");
    if (!atLeast(await teamRoleOf(admin, p, { id: fleet.team_id, org_id: orgId }), "admin")) {
      return fail(403, "Only admins of the fleet's team can change it");
    }

    const body = await readJson(req);
    const updates: Record<string, unknown> = {};
    if (body?.name !== undefined) {
      const name = cleanName(body.name);
      if (!name) return fail(400, "name cannot be empty");
      updates.name = name;
    }
    if (body?.team_id !== undefined && body.team_id !== fleet.team_id) {
      if (typeof body.team_id !== "string") return fail(400, "team_id must be a team id");
      const target = await loadTeam(admin, orgId, body.team_id);
      if (!target) return fail(404, "Target team not found");
      if (!atLeast(await teamRoleOf(admin, p, target), "admin")) return fail(403, "You must be an admin of the team you hand the fleet to");
      updates.team_id = target.id;
    }
    if (Object.keys(updates).length === 0) return fail(400, "Nothing to change");

    const { data, error } = await admin
      .from("fleets")
      .update(updates)
      .eq("id", fleet.id)
      .select("id, org_id, team_id, name, slug, created_at")
      .single();
    if (error) return fail(500, "Could not update the fleet");
    return NextResponse.json({ fleet: data });
  } catch (err) {
    console.error("Update fleet error:", err);
    return fail(500, "Internal server error");
  }
}

// DELETE /api/orgs/[id]/fleets/[fleet_id] — its servers stay, in no fleet.
export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot delete fleets");
    const { id: orgId, fleet_id } = await params;

    const fleet = await loadFleet(admin, orgId, fleet_id);
    if (!fleet) return fail(404, "Fleet not found");
    if (!atLeast(await teamRoleOf(admin, p, { id: fleet.team_id, org_id: orgId }), "admin")) {
      return fail(403, "Only admins of the fleet's team can delete it");
    }
    const { error } = await admin.from("fleets").delete().eq("id", fleet.id);
    if (error) return fail(500, "Could not delete the fleet");
    return NextResponse.json({ deleted: true });
  } catch (err) {
    console.error("Delete fleet error:", err);
    return fail(500, "Internal server error");
  }
}
