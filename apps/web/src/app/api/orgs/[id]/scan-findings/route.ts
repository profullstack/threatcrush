import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, findingsRoleOf, getPrincipal } from "@/lib/access";
import { listFindings, triageFindings, TriageError } from "@/lib/scan-findings";

// GET /api/orgs/[id]/scan-findings?status=open,acknowledged&severity=high&source=ai-scan&property_id=…&limit=100&offset=0
// Default status filter is open + acknowledged: what still needs a decision.
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId } = await params;
  if (!atLeast(await findingsRoleOf(admin, p, orgId), "read")) return NextResponse.json({ error: "Not authorized" }, { status: 403 });
  const s = new URL(req.url).searchParams;
  try {
    return NextResponse.json(await listFindings(admin, orgId, {
      status: s.get("status"), severity: s.get("severity"), source: s.get("source"),
      property_id: s.get("property_id"), limit: s.get("limit"), offset: s.get("offset"),
    }));
  } catch (e) {
    console.error("[scan-findings] list", (e as Error).message);
    return NextResponse.json({ error: "Failed to list findings" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id]/scan-findings  { ids: [...], status?, note? } — triage one or many.
export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId } = await params;
  if (!atLeast(await findingsRoleOf(admin, p, orgId), "write")) return NextResponse.json({ error: "Not authorized" }, { status: 403 });
  const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  try {
    const updated = await triageFindings(admin, orgId, { userId: p.kind === "user" ? p.userId : null }, body ?? {});
    return NextResponse.json({ updated });
  } catch (e) {
    if (e instanceof TriageError) return NextResponse.json({ error: e.message }, { status: 400 });
    console.error("[scan-findings] triage", (e as Error).message);
    return NextResponse.json({ error: "Failed to update findings" }, { status: 500 });
  }
}
