import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, orgRoleOf, teamRoleOf, type TeamRole } from "@/lib/access";
import { cleanName, fail, readJson, uniqueSlug } from "@/lib/teams";

type Params = { params: Promise<{ id: string }> };

// GET /api/orgs/[id]/teams — the teams the caller can see, with their role.
// Org owners and admins see every team; others see the teams they are on; an
// agent key sees its own team.
export async function GET(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    const { id: orgId } = await params;

    const { data: teams } = await admin
      .from("teams")
      .select("id, org_id, name, slug, created_at, team_members(count), fleets(count)")
      .eq("org_id", orgId)
      .order("name");

    const visible: Array<Record<string, unknown>> = [];
    for (const t of teams ?? []) {
      const role: TeamRole | null = await teamRoleOf(admin, p, t);
      if (!role) continue;
      visible.push({
        id: t.id,
        name: t.name,
        slug: t.slug,
        created_at: t.created_at,
        my_role: role,
        member_count: (t.team_members as Array<{ count: number }>)?.[0]?.count ?? 0,
        fleet_count: (t.fleets as Array<{ count: number }>)?.[0]?.count ?? 0,
      });
    }
    if (visible.length === 0 && p.kind === "user" && !(await orgRoleOf(admin, p, orgId))) {
      return fail(403, "Not a member of this organization");
    }
    return NextResponse.json({ teams: visible });
  } catch (err) {
    console.error("List teams error:", err);
    return fail(500, "Internal server error");
  }
}

// POST /api/orgs/[id]/teams { name } — org owners and admins create teams.
export async function POST(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot create teams");
    const { id: orgId } = await params;

    const role = await orgRoleOf(admin, p, orgId);
    if (role !== "owner" && role !== "admin") return fail(403, "Only organization owners and admins can create teams");

    const body = await readJson(req);
    const name = cleanName(body?.name);
    if (!name) return fail(400, "A team name is required");

    const { data: team, error } = await admin
      .from("teams")
      .insert({ org_id: orgId, name, slug: await uniqueSlug(admin, "teams", orgId, name), created_by: p.userId })
      .select("id, org_id, name, slug, created_at")
      .single();
    if (error || !team) {
      console.error("Create team failed:", error);
      return fail(500, "Could not create the team");
    }
    // The creator runs the team they made.
    await admin.from("team_members").insert({ team_id: team.id, user_id: p.userId, role: "admin" });
    return NextResponse.json({ team: { ...team, my_role: "admin" } }, { status: 201 });
  } catch (err) {
    console.error("Create team error:", err);
    return fail(500, "Internal server error");
  }
}
