import { NextRequest, NextResponse } from "next/server";
import { parsePaginationParam } from "@/lib/pagination";
import { atLeast } from "@/lib/access";
import { requireOrgScope, serverRolesIn, visibleServerIds } from "@/lib/route-access";

// GET /api/orgs/[id]/detections — detections on the servers the caller can see
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: orgId } = await params;
    const access = await requireOrgScope(req, orgId);
    if ("error" in access) return access.error;
    const admin = access.admin;

    const url = new URL(req.url);
    const detectionId = url.searchParams.get("id");
    if (detectionId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(detectionId)) {
      return NextResponse.json({ error: "Invalid id" }, { status: 400 });
    }
    const severity = url.searchParams.get("severity");
    const serverId = url.searchParams.get("server_id");
    const status = url.searchParams.get("status");
    const ruleId = url.searchParams.get("rule_id");
    const since = url.searchParams.get("since");
    const until = url.searchParams.get("until");
    const limit = parsePaginationParam(url.searchParams.get("limit"), 50, { min: 1, max: 200 });
    const offset = parsePaginationParam(url.searchParams.get("offset"), 0);

    const visible = await visibleServerIds(admin, orgId, access.scope);
    if (visible && visible.length === 0) return NextResponse.json({ detections: [], total: 0 });

    let query = admin.from("detections").select("*", { count: "exact" })
      .eq("organization_id", orgId)
      .order("detected_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (visible) query = query.in("server_id", visible);
    if (detectionId) query = query.eq("id", detectionId);
    if (severity) query = query.eq("severity", severity);
    if (serverId) query = query.eq("server_id", serverId);
    if (status) query = query.eq("status", status);
    if (ruleId) query = query.eq("rule_id", ruleId);
    if (since) query = query.gte("detected_at", since);
    if (until) query = query.lte("detected_at", until);

    const { data: detections, error, count } = await query;
    if (error) {
      console.error("Failed to fetch detections:", error);
      return NextResponse.json({ error: "Failed to fetch detections" }, { status: 500 });
    }

    return NextResponse.json({ detections: detections || [], total: count || 0 });
  } catch (err) {
    console.error("List detections error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id]/detections — Bulk update detection status. Needs write
// on the server behind every detection named.
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: orgId } = await params;
    const access = await requireOrgScope(req, orgId);
    if ("error" in access) return access.error;
    const admin = access.admin;

    const body = await req.json();
    const { ids, status: newStatus } = body as { ids: string[]; status: string };

    if (!Array.isArray(ids) || !ids.length || !newStatus) {
      return NextResponse.json({ error: "ids and status required" }, { status: 400 });
    }

    if (!["new", "acknowledged", "resolved"].includes(newStatus)) {
      return NextResponse.json({ error: "Invalid status" }, { status: 400 });
    }

    if (!access.scope.all) {
      const roles = await serverRolesIn(admin, orgId, access.scope);
      const { data: rows } = await admin.from("detections").select("id, server_id").eq("organization_id", orgId).in("id", ids);
      const denied = (rows ?? []).some((r) => !r.server_id || !atLeast(roles.get(r.server_id) ?? null, "write"));
      if (denied || (rows ?? []).length !== ids.length) {
        return NextResponse.json({ error: "Not authorized for every detection named" }, { status: 403 });
      }
    }

    const { error } = await admin.from("detections")
      .update({ status: newStatus })
      .eq("organization_id", orgId)
      .in("id", ids);

    if (error) {
      return NextResponse.json({ error: "Failed to update" }, { status: 500 });
    }

    return NextResponse.json({ success: true, updated: ids.length });
  } catch (err) {
    console.error("Bulk update detections error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
