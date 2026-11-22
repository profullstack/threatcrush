import { NextRequest, NextResponse } from "next/server";
import { requireOrgScope, visibleServerIds } from "@/lib/route-access";
import { detectionHistory, HistoryError } from "@/lib/detection-history";

export const runtime = "nodejs";

// GET /api/orgs/[id]/detections/[detection_id]/history — one detection with
// everything related to it (same source IP or key fingerprint across the org,
// same host, same rule on that host) for the detail view the dashboard and the
// desktop app share, plus the address's origin and the linked incident.
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; detection_id: string }> },
) {
  const { id: orgId, detection_id } = await params;
  const access = await requireOrgScope(req, orgId);
  if ("error" in access) return access.error;
  try {
    const visible = await visibleServerIds(access.admin, orgId, access.scope);
    return NextResponse.json(await detectionHistory(access.admin, orgId, detection_id, visible));
  } catch (e) {
    if (e instanceof HistoryError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error("[detections] history", (e as Error).message);
    return NextResponse.json({ error: "Failed to load the detection history" }, { status: 500 });
  }
}
