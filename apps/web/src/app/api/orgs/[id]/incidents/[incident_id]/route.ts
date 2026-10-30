import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal } from "@/lib/access";
import { getIncident, IncidentError, updateIncident } from "@/lib/incidents/store";

export const runtime = "nodejs";

type Ctx = { params: Promise<{ id: string; incident_id: string }> };

// GET /api/orgs/[id]/incidents/[incident_id] — findings, timeline, recommendations, notes, pages sent.
export async function GET(req: NextRequest, { params }: Ctx) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId, incident_id } = await params;
  try {
    return NextResponse.json(await getIncident(admin, p, orgId, incident_id));
  } catch (e) {
    if (e instanceof IncidentError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error("[incidents] get", (e as Error).message);
    return NextResponse.json({ error: "Failed to load the incident" }, { status: 500 });
  }
}

// PATCH { status?, assignee_id?, note?, resolution?: { reason, action, verification } } — needs write. Resolving requires a resolution record.
export async function PATCH(req: NextRequest, { params }: Ctx) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId, incident_id } = await params;
  const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body !== "object" || Array.isArray(body)) return NextResponse.json({ error: "Body must be a JSON object" }, { status: 400 });
  try {
    return NextResponse.json(await updateIncident(admin, p, orgId, incident_id, body));
  } catch (e) {
    if (e instanceof IncidentError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error("[incidents] update", (e as Error).message);
    return NextResponse.json({ error: "Failed to update the incident" }, { status: 500 });
  }
}
