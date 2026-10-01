import { NextRequest, NextResponse } from "next/server";
import { roleInScope } from "@/lib/access";
import { requireOrgScope } from "@/lib/route-access";
import { loadFixReport, renderFixPrompt } from "@/lib/fix-report";

// GET /api/orgs/[id]/report — open findings and recent attacks on the servers
// the caller can see, as a fix prompt (the "Copy fix prompt" button).
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: orgId } = await params;
    const access = await requireOrgScope(req, orgId);
    if ("error" in access) return access.error;

    const { scope } = access;
    const report = await loadFixReport(
      access.admin,
      orgId,
      new Date(),
      scope.all ? undefined : (server) => roleInScope(scope, server) !== null,
    );
    if (!report) return NextResponse.json({ error: "Organization not found" }, { status: 404 });

    return NextResponse.json({ prompt: renderFixPrompt(report), report });
  } catch (err) {
    console.error("Fix report error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
