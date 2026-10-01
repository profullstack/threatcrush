import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, teamRoleOf } from "@/lib/access";
import { fail, loadTeam } from "@/lib/teams";

type Params = { params: Promise<{ id: string; team_id: string; invite_id: string }> };

// DELETE /api/orgs/[id]/teams/[team_id]/invites/[invite_id] — revoke a pending
// invite; its link then reads as expired.
export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot manage invites");
    const { id: orgId, team_id, invite_id } = await params;

    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");
    if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return fail(403, "Only team admins can revoke invites");

    const { data } = await admin
      .from("team_invites")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", invite_id)
      .eq("team_id", team.id)
      .is("accepted_at", null)
      .is("revoked_at", null)
      .select("id")
      .maybeSingle();
    if (!data) return fail(404, "No pending invite with that id");
    return NextResponse.json({ revoked: true });
  } catch (err) {
    console.error("Revoke invite error:", err);
    return fail(500, "Internal server error");
  }
}
