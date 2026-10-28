import { NextResponse, type NextRequest } from "next/server";
import { feedPrincipal } from "@/lib/feed-auth";
import { handleFindingsReport } from "@/lib/findings-report";

// POST /api/v1/findings/report — the same upload as
// /api/orgs/[id]/scan-findings/report, for CI: a tc_agent_ key (Bearer,
// X-API-Key) reports into its own org, so the pipeline needs no org id.
// A person's session token passes ?org_id=.
export async function POST(req: NextRequest) {
  const p = await feedPrincipal(req);
  if (!p) return NextResponse.json({ error: "Not authenticated: send a tc_agent_ key or a session token" }, { status: 401 });
  const orgId = p.kind === "agent" ? p.orgId : new URL(req.url).searchParams.get("org_id");
  if (!orgId) return NextResponse.json({ error: "org_id required for a session token" }, { status: 400 });
  return handleFindingsReport(req, p, orgId);
}
