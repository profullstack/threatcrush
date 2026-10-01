import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, hashSecret, isTeamRole, newSecret, teamRoleOf } from "@/lib/access";
import { appUrl, fail, isEmail, loadTeam, readJson, sendInviteEmail } from "@/lib/teams";

type Params = { params: Promise<{ id: string; team_id: string }> };

// POST /api/orgs/[id]/teams/[team_id]/invites { email, role } — a team admin
// invites someone by email. The link is emailed and also returned once, so it
// can be passed on by hand; only its hash is stored.
export async function POST(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot send invites");
    const { id: orgId, team_id } = await params;

    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");
    if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return fail(403, "Only team admins can invite people");

    const body = await readJson(req);
    const role = body?.role ?? "read";
    if (!isEmail(body?.email) || !isTeamRole(role)) return fail(400, "email and a role of read, write or admin are required");
    const email = (body!.email as string).trim().toLowerCase();

    // One live invite per address: re-inviting replaces the old link.
    await admin
      .from("team_invites")
      .update({ revoked_at: new Date().toISOString() })
      .eq("team_id", team.id)
      .eq("email", email)
      .is("accepted_at", null)
      .is("revoked_at", null);

    const token = newSecret();
    const { data: invite, error } = await admin
      .from("team_invites")
      .insert({ org_id: orgId, team_id: team.id, email, role, token_hash: hashSecret(token), invited_by: p.userId })
      .select("id, email, role, created_at, expires_at")
      .single();
    if (error || !invite) {
      console.error("Create invite failed:", error);
      return fail(500, "Could not create the invite");
    }

    const url = `${appUrl()}/invite/${token}`;
    const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
    const emailed = await sendInviteEmail({
      to: email,
      orgName: org?.name ?? "your organization",
      teamName: team.name,
      role,
      inviter: p.email,
      url,
    });

    return NextResponse.json({ invite, url, emailed }, { status: 201 });
  } catch (err) {
    console.error("Create invite error:", err);
    return fail(500, "Internal server error");
  }
}
