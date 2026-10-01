import { NextRequest, NextResponse } from "next/server";
import { parsePaginationParam } from "@/lib/pagination";
import { requireServer } from "@/lib/route-access";

// GET /api/orgs/[id]/servers/[server_id]/detections — Server-scoped detections (read access)
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; server_id: string }> }
) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "read", "id, org_id, fleet_id");
    if ("error" in access) return access.error;
    const admin = access.admin;

    const url = new URL(req.url);
    const severity = url.searchParams.get("severity");
    const status = url.searchParams.get("status");
    const limit = parsePaginationParam(url.searchParams.get("limit"), 50, { min: 1, max: 200 });
    const offset = parsePaginationParam(url.searchParams.get("offset"), 0);

    let query = admin.from("detections").select("*", { count: "exact" })
      .eq("organization_id", orgId)
      .eq("server_id", server_id)
      .order("detected_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (severity) query = query.eq("severity", severity);
    if (status) query = query.eq("status", status);

    const { data: detections, error, count } = await query;
    if (error) return NextResponse.json({ error: "Failed to fetch detections" }, { status: 500 });

    return NextResponse.json({ detections: detections || [], total: count || 0 });
  } catch (err) {
    console.error("Server detections error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
