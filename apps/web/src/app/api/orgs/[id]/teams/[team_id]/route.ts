import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, getPrincipal, orgRoleOf, teamRoleOf } from "@/lib/access";
import { cleanName, fail, loadTeam, readJson } from "@/lib/teams";

type Params = { params: Promise<{ id: string; team_id: string }> };

// GET /api/orgs/[id]/teams/[team_id] — the team, its members and fleets; for
// team admins also its pending invites and agent keys (never the secrets).
export async function GET(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    const { id: orgId, team_id } = await params;

    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");
    const role = await teamRoleOf(admin, p, team);
    if (!role) return fail(404, "Team not found");

    const [{ data: members }, { data: fleets }] = await Promise.all([
      admin
        .from("team_members")
        .select("user_id, role, added_at, user_profiles(email, display_name)")
        .eq("team_id", team.id)
        .order("added_at"),
      admin.from("fleets").select("id, name, slug, created_at, servers(count)").eq("team_id", team.id).order("name"),
    ]);

    const result: Record<string, unknown> = {
      team: { ...team, my_role: role },
      members: (members ?? []).map((m) => {
        const up = (Array.isArray(m.user_profiles) ? m.user_profiles[0] : m.user_profiles) as
          | { email: string; display_name: string | null }
          | null;
        return { user_id: m.user_id, role: m.role, added_at: m.added_at, email: up?.email ?? null, display_name: up?.display_name ?? null };
      }),
      fleets: (fleets ?? []).map((f) => ({
        id: f.id,
        name: f.name,
        slug: f.slug,
        created_at: f.created_at,
        server_count: (f.servers as Array<{ count: number }>)?.[0]?.count ?? 0,
      })),
    };

    if (atLeast(role, "admin") && p.kind === "user") {
      const now = new Date().toISOString();
      const [{ data: invites }, { data: keys }] = await Promise.all([
        admin
          .from("team_invites")
          .select("id, email, role, created_at, expires_at")
          .eq("team_id", team.id)
          .is("accepted_at", null)
          .is("revoked_at", null)
          .gt("expires_at", now)
          .order("created_at", { ascending: false }),
        admin
          .from("agent_keys")
          .select("id, name, role, key_prefix, created_at, last_used_at")
          .eq("team_id", team.id)
          .is("revoked_at", null)
          .order("created_at", { ascending: false }),
      ]);
      result.invites = invites ?? [];
      result.agent_keys = keys ?? [];
    }
    return NextResponse.json(result);
  } catch (err) {
    console.error("Get team error:", err);
    return fail(500, "Internal server error");
  }
}

// PATCH /api/orgs/[id]/teams/[team_id] { name } — team admins rename it.
export async function PATCH(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot change teams");
    const { id: orgId, team_id } = await params;

    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");
    if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return fail(403, "Only team admins can rename the team");

    const name = cleanName((await readJson(req))?.name);
    if (!name) return fail(400, "A team name is required");

    const { data, error } = await admin
      .from("teams")
      .update({ name })
      .eq("id", team.id)
      .select("id, org_id, name, slug, created_at")
      .single();
    if (error) return fail(500, "Could not rename the team");
    return NextResponse.json({ team: data });
  } catch (err) {
    console.error("Update team error:", err);
    return fail(500, "Internal server error");
  }
}

// DELETE /api/orgs/[id]/teams/[team_id] — org owners and admins only. Its
// fleets go with it; their servers stay, back in no fleet.
export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot delete teams");
    const { id: orgId, team_id } = await params;

    const role = await orgRoleOf(admin, p, orgId);
    if (role !== "owner" && role !== "admin") return fail(403, "Only organization owners and admins can delete teams");
    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");

    const { error } = await admin.from("teams").delete().eq("id", team.id);
    if (error) return fail(500, "Could not delete the team");
    return NextResponse.json({ deleted: true });
  } catch (err) {
    console.error("Delete team error:", err);
    return fail(500, "Internal server error");
  }
}
