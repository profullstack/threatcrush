import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, findingsRoleOf, getPrincipal } from "@/lib/access";
import { getFinding } from "@/lib/scan-findings";

// GET /api/orgs/[id]/scan-findings/[finding_id] — one finding with its details and property.
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string; finding_id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId, finding_id } = await params;
  if (!atLeast(await findingsRoleOf(admin, p, orgId), "read")) return NextResponse.json({ error: "Not authorized" }, { status: 403 });
  try {
    const finding = await getFinding(admin, orgId, finding_id);
    return finding ? NextResponse.json({ finding }) : NextResponse.json({ error: "Not found" }, { status: 404 });
  } catch (e) {
    console.error("[scan-findings] get", (e as Error).message);
    return NextResponse.json({ error: "Failed to load finding" }, { status: 500 });
  }
}
