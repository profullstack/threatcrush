import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, teamRoleOf } from "@/lib/access";
import { cleanName, fail, loadTeam, readJson, uniqueSlug } from "@/lib/teams";

type Params = { params: Promise<{ id: string }> };

// GET /api/orgs/[id]/fleets — the fleets the caller can see, with their team
// and the caller's role on each.
export async function GET(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    const { id: orgId } = await params;

    const { data: fleets } = await admin
      .from("fleets")
      .select("id, org_id, team_id, name, slug, created_at, teams(name), servers(count)")
      .eq("org_id", orgId)
      .order("name");

    const roles = new Map<string, Awaited<ReturnType<typeof teamRoleOf>>>();
    const visible: Array<Record<string, unknown>> = [];
    for (const f of fleets ?? []) {
      if (!roles.has(f.team_id)) roles.set(f.team_id, await teamRoleOf(admin, p, { id: f.team_id, org_id: orgId }));
      const role = roles.get(f.team_id);
      if (!role) continue;
      const team = (Array.isArray(f.teams) ? f.teams[0] : f.teams) as { name: string } | null;
      visible.push({
        id: f.id,
        name: f.name,
        slug: f.slug,
        team_id: f.team_id,
        team_name: team?.name ?? null,
        created_at: f.created_at,
        server_count: (f.servers as Array<{ count: number }>)?.[0]?.count ?? 0,
        my_role: role,
      });
    }
    return NextResponse.json({ fleets: visible });
  } catch (err) {
    console.error("List fleets error:", err);
    return fail(500, "Internal server error");
  }
}

// POST /api/orgs/[id]/fleets { team_id, name } — a team admin creates a fleet
// owned by that team.
export async function POST(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot create fleets");
    const { id: orgId } = await params;

    const body = await readJson(req);
    const name = cleanName(body?.name);
    if (!name || typeof body?.team_id !== "string") return fail(400, "team_id and name are required");

    const team = await loadTeam(admin, orgId, body.team_id);
    if (!team) return fail(404, "Team not found");
    if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return fail(403, "Only team admins can create fleets");

    const { data: fleet, error } = await admin
      .from("fleets")
      .insert({ org_id: orgId, team_id: team.id, name, slug: await uniqueSlug(admin, "fleets", orgId, name), created_by: p.userId })
      .select("id, org_id, team_id, name, slug, created_at")
      .single();
    if (error || !fleet) {
      console.error("Create fleet failed:", error);
      return fail(500, "Could not create the fleet");
    }
    return NextResponse.json({ fleet }, { status: 201 });
  } catch (err) {
    console.error("Create fleet error:", err);
    return fail(500, "Internal server error");
  }
}
