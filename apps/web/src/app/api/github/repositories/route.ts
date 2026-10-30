import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, orgRoleOf, isOrgAdmin, hashSecret, newSecret } from "@/lib/access";
import { isUuid } from "@/lib/incidents/report";

export const runtime = "nodejs";
const columns = "id, org_id, team_id, full_name, silence_warnings, silence_examples, last_report_at, last_counts";
const publicRepository = (row: Record<string, unknown>) => Object.fromEntries(columns.split(", ").map((key) => [key, row[key]]));

export async function GET(req: NextRequest) {
  const admin = getSupabaseAdmin(), p = await getPrincipal(req, admin);
  if (!p || p.kind !== "user") return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const memberships = await admin.from("organization_members").select("org_id, role, organizations(name, slug)").eq("user_id", p.userId);
  if (memberships.error) return NextResponse.json({ error: "Could not load organizations" }, { status: 500 });
  const orgs = (memberships.data ?? []).filter((m) => isOrgAdmin(m.role)).map((m) => {
    const o = (Array.isArray(m.organizations) ? m.organizations[0] : m.organizations) as { name: string; slug: string };
    return { id: m.org_id, name: o?.name ?? m.org_id, slug: o?.slug };
  });
  if (!orgs.length) return NextResponse.json({ repositories: [], organizations: [], teams: [] });
  const ids = orgs.map((o) => o.id);
  const [repos, teams] = await Promise.all([
    admin.from("github_repository_policies").select(columns).in("org_id", ids).order("full_name"),
    admin.from("teams").select("id, name, org_id").in("org_id", ids),
  ]);
  if (repos.error || teams.error) return NextResponse.json({ error: "Could not load repository settings" }, { status: 500 });
  return NextResponse.json({ repositories: (repos.data ?? []).map(publicRepository), organizations: orgs, teams: teams.data }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(req: NextRequest) { return save(req, true); }
export async function PATCH(req: NextRequest) { return save(req, false); }

async function save(req: NextRequest, create: boolean) {
  const admin = getSupabaseAdmin(), p = await getPrincipal(req, admin);
  if (!p || p.kind !== "user") return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const body = await req.json().catch(() => null);
  if (!body || !isUuid(body.org_id) || (!create && !isUuid(body.id))) return NextResponse.json({ error: "Valid organization and repository IDs required" }, { status: 400 });
  if (!isOrgAdmin(await orgRoleOf(admin, p, body.org_id))) return NextResponse.json({ error: "Organization admin access required" }, { status: 403 });
  const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
  for (const key of ["silence_warnings", "silence_examples"]) {
    if (body[key] !== undefined) {
      if (typeof body[key] !== "boolean") return NextResponse.json({ error: `${key} must be a boolean` }, { status: 400 });
      patch[key] = body[key];
    }
  }
  if (body.team_id !== undefined) {
    if (body.team_id !== null) {
      if (!isUuid(body.team_id)) return NextResponse.json({ error: "Invalid team" }, { status: 400 });
      const team = await admin.from("teams").select("id").eq("id", body.team_id).eq("org_id", body.org_id).maybeSingle();
      if (team.error) return NextResponse.json({ error: "Could not verify team" }, { status: 500 });
      if (!team.data) return NextResponse.json({ error: "Team not found in organization" }, { status: 400 });
    }
    patch.team_id = body.team_id;
  }
  let token: string | undefined;
  if (create || body.rotate_token === true) { token = `tc_repo_${newSecret()}`; patch.token_hash = hashSecret(token); }
  if (create) {
    if (typeof body.full_name !== "string" || !/^[\w.-]+\/[\w.-]+$/.test(body.full_name) || body.full_name.length > 200) return NextResponse.json({ error: "Use owner/repository" }, { status: 400 });
    patch.org_id = body.org_id; patch.full_name = body.full_name.toLowerCase();
  } else if (Object.keys(patch).length === 1) return NextResponse.json({ error: "No settings supplied" }, { status: 400 });
  const query = create ? admin.from("github_repository_policies").insert(patch)
    : admin.from("github_repository_policies").update(patch).eq("id", body.id).eq("org_id", body.org_id);
  const saved = await query.select(columns).maybeSingle();
  if (saved.error) return NextResponse.json({ error: saved.error.code === "23505" ? "Repository already connected" : "Could not save settings" }, { status: saved.error.code === "23505" ? 409 : 500 });
  if (!saved.data) return NextResponse.json({ error: "Repository not found" }, { status: 404 });
  return NextResponse.json({ repository: publicRepository(saved.data), ...(token ? { token } : {}) }, { status: create ? 201 : 200, headers: { "Cache-Control": "no-store" } });
}
