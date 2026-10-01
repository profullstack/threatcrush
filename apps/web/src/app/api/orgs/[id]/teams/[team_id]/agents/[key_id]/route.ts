import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, teamRoleOf } from "@/lib/access";
import { fail, loadTeam } from "@/lib/teams";

type Params = { params: Promise<{ id: string; team_id: string; key_id: string }> };

// DELETE /api/orgs/[id]/teams/[team_id]/agents/[key_id] — revoke a key. The
// next request made with it is refused.
export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot revoke agent keys");
    const { id: orgId, team_id, key_id } = await params;

    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");
    if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return fail(403, "Only team admins can revoke agent keys");

    const { data } = await admin
      .from("agent_keys")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", key_id)
      .eq("team_id", team.id)
      .is("revoked_at", null)
      .select("id")
      .maybeSingle();
    if (!data) return fail(404, "No active key with that id");
    return NextResponse.json({ revoked: true });
  } catch (err) {
    console.error("Revoke agent key error:", err);
    return fail(500, "Internal server error");
  }
}
