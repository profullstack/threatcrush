import { NextRequest, NextResponse } from "next/server";
import { parsePaginationParam } from "@/lib/pagination";
import { atLeast } from "@/lib/access";
import { requireOrgScope, serverRolesIn, visibleServerIds } from "@/lib/route-access";
import { detectionUsername } from "@/lib/detection-display";

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

    const normalized = (detections || []).map((detection) => ({
      ...detection,
      username: detectionUsername(detection),
    }));

    // Critical detections are folded into incidents by server + rule. Return
    // that relationship with each detection so the feed can link to the place
    // where operators assign, investigate, and record a resolution.
    const critical = normalized.filter((detection) => detection.severity === "critical" && detection.server_id);
    const incidentKeys = [...new Set(critical.map((detection) =>
      `detection:${detection.server_id}:${detection.rule_id || detection.title}`.slice(0, 200),
    ))];
    const incidentsByKey = new Map<string, {
      id: string;
      status: string;
      assignee_id: string | null;
    }>();
    if (incidentKeys.length) {
      let incidentQuery = admin.from("incidents")
        .select("id, dedupe_key, status, assignee_id, last_seen_at")
        .eq("org_id", orgId)
        .in("dedupe_key", incidentKeys)
        .order("last_seen_at", { ascending: false });
      if (visible) {
        const visibleDetectionServers = [...new Set(critical.map((detection) => detection.server_id))];
        incidentQuery = incidentQuery.in("server_id", visibleDetectionServers);
      }
      const { data: linkedIncidents, error: incidentError } = await incidentQuery;
      if (incidentError) {
        // Keep the detections feed available if incident linkage is unavailable.
        console.error("Failed to link detections to incidents:", incidentError);
      } else {
        for (const incident of linkedIncidents ?? []) {
          const current = incidentsByKey.get(incident.dedupe_key);
          if (!current || (current.status === "resolved" && incident.status !== "resolved")) {
            incidentsByKey.set(incident.dedupe_key, {
              id: incident.id,
              status: incident.status,
              assignee_id: incident.assignee_id,
            });
          }
        }
      }
    }

    const withIncidents = normalized.map((detection) => {
      if (detection.severity !== "critical" || !detection.server_id) return detection;
      const key = `detection:${detection.server_id}:${detection.rule_id || detection.title}`.slice(0, 200);
      return { ...detection, incident: incidentsByKey.get(key) ?? null };
    });
    return NextResponse.json({ detections: withIncidents, total: count || 0 });
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
