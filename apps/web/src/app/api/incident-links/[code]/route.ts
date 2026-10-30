import { NextResponse, type NextRequest } from "next/server";
import { getPrincipal, incidentRoleOf } from "@/lib/access";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";

/** Resolve a six-digit or legacy short code only for a caller who can read it. */
export async function GET(req: NextRequest, { params }: { params: Promise<{ code: string }> }) {
  const { code: raw } = await params;
  const humanCode = /^[0-9]{6}$/.test(raw);
  if (!humanCode && !/^[a-z0-9]{10,40}$/i.test(raw)) {
    return NextResponse.json({ error: "Incident not found" }, { status: 404 });
  }

  const admin = getSupabaseAdmin();
  const principal = await getPrincipal(req, admin);
  if (!principal) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

  const { data: incident } = await admin.from("incidents")
    .select("id, org_id, team_id")
    .eq(humanCode ? "human_code" : "short_code", humanCode ? raw : raw.toLowerCase())
    .maybeSingle();
  if (!incident || !(await incidentRoleOf(admin, principal, incident))) {
    // Unknown and unreadable incidents intentionally have the same response.
    return NextResponse.json({ error: "Incident not found" }, { status: 404 });
  }

  const { data: org } = await admin.from("organizations").select("slug").eq("id", incident.org_id).maybeSingle();
  if (!org || typeof org.slug !== "string") {
    return NextResponse.json({ error: "Incident not found" }, { status: 404 });
  }

  return NextResponse.json({ href: `/org/${encodeURIComponent(org.slug)}/incidents/${incident.id}` });
}
