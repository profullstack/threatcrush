import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, isTeamRole, teamRoleOf } from "@/lib/access";
import { fail, isEmail, loadTeam, readJson } from "@/lib/teams";
import { createTeamInvite } from "@/lib/invites";

type Params = { params: Promise<{ id: string; team_id: string }> };

// POST /api/orgs/[id]/teams/[team_id]/members { email, role } — a team admin
// adds someone who is already in the organization. Anyone else gets an invite.
export async function POST(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot manage members");
    const { id: orgId, team_id } = await params;

    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");
    if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return fail(403, "Only team admins can add members");

    const body = await readJson(req);
    const role = body?.role ?? "read";
    if (!isEmail(body?.email) || !isTeamRole(role)) return fail(400, "email and a role of read, write or admin are required");

    const { data: profile } = await admin
      .from("user_profiles")
      .select("id")
      .eq("email", (body!.email as string).toLowerCase().trim())
      .maybeSingle();
    const { data: membership } = profile
      ? await admin.from("organization_members").select("role").eq("org_id", orgId).eq("user_id", profile.id).maybeSingle()
      : { data: null };

    // Not in the org yet (no account, or an account that never joined): invite
    // them to this team instead of dead-ending.
    if (!profile || !membership) {
      const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
      const invite = await createTeamInvite(admin, {
        orgId,
        teamId: team.id,
        teamName: team.name,
        email: (body!.email as string).toLowerCase().trim(),
        role,
        invitedBy: p.userId,
        inviterEmail: p.email,
        orgName: org?.name ?? "your organization",
      });
      if (!invite) return fail(500, "Could not create the invite");
      return NextResponse.json({ invited: true, email: invite.invite.email, url: invite.url, emailed: invite.emailed }, { status: 201 });
    }

    const { error } = await admin
      .from("team_members")
      .upsert({ team_id: team.id, user_id: profile.id, role }, { onConflict: "team_id,user_id" });
    if (error) return fail(500, "Could not add the member");
    return NextResponse.json({ member: { user_id: profile.id, role } }, { status: 201 });
  } catch (err) {
    console.error("Add team member error:", err);
    return fail(500, "Internal server error");
  }
}
