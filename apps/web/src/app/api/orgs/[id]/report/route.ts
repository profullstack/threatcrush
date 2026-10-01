import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { loadFixReport, renderFixPrompt } from "@/lib/fix-report";

// GET /api/orgs/[id]/report — the org's open findings and recent attacks as a
// fix prompt (the "Copy fix prompt" button). Any member may read it.
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await getAuthenticatedRequestUser(req);
    if (!user) return unauthorized();

    const { id: orgId } = await params;
    const admin = getSupabaseAdmin();
    const { data: membership } = await admin
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", user.userId)
      .maybeSingle();
    if (!membership) {
      return NextResponse.json({ error: "Not a member of this organization" }, { status: 403 });
    }

    const report = await loadFixReport(admin, orgId);
    if (!report) return NextResponse.json({ error: "Organization not found" }, { status: 404 });

    return NextResponse.json({ prompt: renderFixPrompt(report), report });
  } catch (err) {
    console.error("Fix report error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
