import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal } from "@/lib/access";
import { handleFindingsReport } from "@/lib/findings-report";

// POST /api/orgs/[id]/scan-findings/report — see lib/findings-report.ts.
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const p = await getPrincipal(req, getSupabaseAdmin());
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId } = await params;
  return handleFindingsReport(req, p, orgId);
}
