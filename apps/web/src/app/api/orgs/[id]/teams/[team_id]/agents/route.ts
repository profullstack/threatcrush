import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { AGENT_KEY_PREFIX, atLeast, getPrincipal, hashSecret, isTeamRole, newSecret, teamRoleOf } from "@/lib/access";
import { cleanName, fail, loadTeam, readJson } from "@/lib/teams";

type Params = { params: Promise<{ id: string; team_id: string }> };

// POST /api/orgs/[id]/teams/[team_id]/agents { name, role } — a team admin
// creates a key for an AI agent, a script or CI. The key acts on this team's
// fleets with this role and nothing else. It is shown once; only its hash is
// stored.
export async function POST(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Not authenticated");
    if (p.kind !== "user") return fail(403, "Agent keys cannot create agent keys");
    const { id: orgId, team_id } = await params;

    const team = await loadTeam(admin, orgId, team_id);
    if (!team) return fail(404, "Team not found");
    if (!atLeast(await teamRoleOf(admin, p, team), "admin")) return fail(403, "Only team admins can create agent keys");

    const body = await readJson(req);
    const name = cleanName(body?.name);
    const role = body?.role ?? "read";
    if (!name || !isTeamRole(role)) return fail(400, "name and a role of read, write or admin are required");

    const key = `${AGENT_KEY_PREFIX}${newSecret()}`;
    const { data, error } = await admin
      .from("agent_keys")
      .insert({
        org_id: orgId,
        team_id: team.id,
        name,
        role,
        key_prefix: key.slice(0, AGENT_KEY_PREFIX.length + 6),
        key_hash: hashSecret(key),
        created_by: p.userId,
      })
      .select("id, name, role, key_prefix, created_at, last_used_at")
      .single();
    if (error || !data) {
      console.error("Create agent key failed:", error);
      return fail(500, "Could not create the key");
    }
    return NextResponse.json({ agent_key: data, key }, { status: 201 });
  } catch (err) {
    console.error("Create agent key error:", err);
    return fail(500, "Internal server error");
  }
}
