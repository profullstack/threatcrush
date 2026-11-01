import { NextResponse, type NextRequest } from "next/server";
import { getPrincipal, orgRoleOf } from "@/lib/access";
import { getSupabaseAdmin } from "@/lib/supabase";
import { syncPsaIncident } from "@/lib/psa/halo";

export const runtime = "nodejs";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string; integration_id: string }> }) {
  const { id: orgId, integration_id: integrationId } = await params;
  const admin = getSupabaseAdmin();
  const principal = await getPrincipal(req, admin);
  if (!principal) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  if (principal.kind !== "user" || !["owner", "admin"].includes((await orgRoleOf(admin, principal, orgId)) ?? "")) {
    return NextResponse.json({ error: "Organization admin access required" }, { status: 403 });
  }
  const body = await req.json().catch(() => null) as { incident_id?: unknown } | null;
  const incidentId = typeof body?.incident_id === "string" ? body.incident_id : "";
  if (!incidentId) return NextResponse.json({ error: "incident_id is required" }, { status: 400 });
  const { data: integration } = await admin.from("psa_integrations").select("id")
    .eq("id", integrationId).eq("organization_id", orgId).maybeSingle();
  if (!integration) return NextResponse.json({ error: "PSA integration not found" }, { status: 404 });
  const { data: incident } = await admin.from("incidents").select("id")
    .eq("id", incidentId).eq("org_id", orgId).maybeSingle();
  if (!incident) return NextResponse.json({ error: "Incident not found" }, { status: 404 });
  await syncPsaIncident(admin, incidentId, integrationId);
  const { data: link } = await admin.from("psa_ticket_links").select("external_ticket_id, sync_status, last_error, last_synced_at")
    .eq("integration_id", integrationId).eq("incident_id", incidentId).maybeSingle();
  return NextResponse.json({ link: link ?? null });
}
