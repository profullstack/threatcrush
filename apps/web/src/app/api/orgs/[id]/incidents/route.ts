import { after, NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal } from "@/lib/access";
import { IncidentError, listIncidents, pageable, raiseIncident } from "@/lib/incidents/store";
import { notifyIncident, reachable, recipientsFor } from "@/lib/incidents/notify";
import { INCIDENT_MAX_BODY_BYTES } from "@/lib/incidents/http";

export const runtime = "nodejs";

// GET /api/orgs/[id]/incidents?status=open,acknowledged&team_id=…&limit=100
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId } = await params;
  const s = new URL(req.url).searchParams;
  try {
    return NextResponse.json(await listIncidents(admin, p, orgId, { status: s.get("status"), team_id: s.get("team_id"), limit: s.get("limit") }));
  } catch (e) {
    if (e instanceof IncidentError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error("[incidents] list", (e as Error).message);
    return NextResponse.json({ error: "Failed to list incidents" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/incidents — raise a report (investigate --raise, daemon,
// MCP). Same dedupe_key while open = folded in, and the team is paged once.
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId } = await params;
  const text = await req.text().catch(() => "");
  if (text.length > INCIDENT_MAX_BODY_BYTES) return NextResponse.json({ error: `Body exceeds ${INCIDENT_MAX_BODY_BYTES} bytes` }, { status: 413 });
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return NextResponse.json({ error: "Body must be JSON" }, { status: 400 });
  }
  try {
    const out = await raiseIncident(admin, p, orgId, body);
    let queued = { sms: 0, email: 0 };
    if (out.page) {
      queued = await reachable(admin, await recipientsFor(admin, out.incident));
      const incident = pageable(out.incident);
      after(() => notifyIncident(incident).then(() => undefined));
    }
    return NextResponse.json(
      { incident: out.incident, created: out.created, paged: out.page, notified: { ...queued, queued: out.page } },
      { status: out.created ? 201 : 200 },
    );
  } catch (e) {
    if (e instanceof IncidentError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error("[incidents] raise", (e as Error).message);
    return NextResponse.json({ error: "Failed to raise the incident" }, { status: 500 });
  }
}
