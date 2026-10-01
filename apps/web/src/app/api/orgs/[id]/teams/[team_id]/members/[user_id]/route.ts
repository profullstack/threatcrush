import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, isTeamRole, teamRoleOf } from "@/lib/access";
import { fail, loadTeam, readJson } from "@/lib/teams";

type Params = { params: Promise<{ id: string; team_id: string; user_id: string }> };

async function authorize(req: NextRequest, params: Params["params"]) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return { error: fail(401, "Not authenticated") };
  if (p.kind !== "user") return { error: fail(403, "Agent keys cannot manage members") };
  const { id: orgId, team_id, user_id } = await params;
  const team = await loadTeam(admin, orgId, team_id);
  if (!team) return { error: fail(404, "Team not found") };
  if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return { error: fail(403, "Only team admins can manage members") };
  return { admin, team, userId: user_id };
}

// PATCH /api/orgs/[id]/teams/[team_id]/members/[user_id] { role }
export async function PATCH(req: NextRequest, { params }: Params) {
  try {
    const auth = await authorize(req, params);
    if ("error" in auth) return auth.error;
    const role = (await readJson(req))?.role;
    if (!isTeamRole(role)) return fail(400, "role must be read, write or admin");

    const { data, error } = await auth.admin
      .from("team_members")
      .update({ role })
      .eq("team_id", auth.team.id)
      .eq("user_id", auth.userId)
      .select("user_id, role")
      .maybeSingle();
    if (error) return fail(500, "Could not change the role");
    if (!data) return fail(404, "Not a member of this team");
    return NextResponse.json({ member: data });
  } catch (err) {
    console.error("Update team member error:", err);
    return fail(500, "Internal server error");
  }
}

// DELETE /api/orgs/[id]/teams/[team_id]/members/[user_id] — off the team; they
// stay in the organization.
export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const auth = await authorize(req, params);
    if ("error" in auth) return auth.error;
    const { error } = await auth.admin.from("team_members").delete().eq("team_id", auth.team.id).eq("user_id", auth.userId);
    if (error) return fail(500, "Could not remove the member");
    return NextResponse.json({ removed: true });
  } catch (err) {
    console.error("Remove team member error:", err);
    return fail(500, "Internal server error");
  }
}
