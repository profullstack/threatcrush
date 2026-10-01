import { NextRequest, NextResponse } from "next/server";
import { parsePaginationParam } from "@/lib/pagination";
import { atLeast, serverRoleOf } from "@/lib/access";
import { requireOrgScope, visibleServerIds } from "@/lib/route-access";

// GET /api/orgs/[id]/remediations — actions on the servers the caller can see
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
    const serverId = url.searchParams.get("server_id");
    const status = url.searchParams.get("status");
    const limit = parsePaginationParam(url.searchParams.get("limit"), 50, { min: 1, max: 200 });
    const offset = parsePaginationParam(url.searchParams.get("offset"), 0);

    const visible = await visibleServerIds(admin, orgId, access.scope);
    if (visible && visible.length === 0) return NextResponse.json({ remediations: [], total: 0 });

    let query = admin.from("remediation_actions").select("*", { count: "exact" })
      .eq("organization_id", orgId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (visible) query = query.in("server_id", visible);
    if (serverId) query = query.eq("server_id", serverId);
    if (status) query = query.eq("status", status);

    const { data: remediations, error, count } = await query;
    if (error) return NextResponse.json({ error: "Failed to fetch remediations" }, { status: 500 });

    return NextResponse.json({ remediations: remediations || [], total: count || 0 });
  } catch (err) {
    console.error("List remediations error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/remediations — Execute a remediation action
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: orgId } = await params;
    const access = await requireOrgScope(req, orgId);
    if ("error" in access) return access.error;
    const admin = access.admin;

    const body = await req.json();
    const { server_id, action_type, target_value, ttl_seconds, detection_id } = body as {
      server_id: string;
      action_type: string;
      target_value: string;
      ttl_seconds?: number;
      detection_id?: string;
    };

    if (!server_id || !action_type || !target_value) {
      return NextResponse.json({ error: "server_id, action_type, and target_value required" }, { status: 400 });
    }

    if (!["block", "unblock", "allowlist_add", "allowlist_remove"].includes(action_type)) {
      return NextResponse.json({ error: "Invalid action_type" }, { status: 400 });
    }

    // TC-20: server_id and detection_id came straight from the body and were
    // never checked against this org, so an admin of one org could queue a
    // remediation against another org's server.
    const { data: server } = await admin.from("servers")
      .select("id, org_id, fleet_id")
      .eq("org_id", orgId)
      .eq("id", server_id)
      .maybeSingle();

    // A ban is write on that server; changing who can never be banned is admin.
    const role = server ? await serverRoleOf(admin, access.p, server) : null;
    if (!server || !role) {
      return NextResponse.json(
        { error: "Server not found in this organization" },
        { status: 404 },
      );
    }
    const needed = action_type.startsWith("allowlist_") ? "admin" : "write";
    if (!atLeast(role, needed)) {
      return NextResponse.json({ error: `This needs ${needed} access to the server` }, { status: 403 });
    }

    if (detection_id) {
      const { data: detection } = await admin.from("detections")
        .select("id")
        .eq("organization_id", orgId)
        .eq("id", detection_id)
        .maybeSingle();

      if (!detection) {
        return NextResponse.json(
          { error: "Detection not found in this organization" },
          { status: 404 },
        );
      }
    }

    // Check allowlist — never block allowlisted IPs
    if (action_type === "block") {
      const { data: allowlisted } = await admin.from("allowlists")
        .select("id")
        .eq("organization_id", orgId)
        .eq("value", target_value)
        .single();

      if (allowlisted) {
        return NextResponse.json({ error: "Target is allowlisted" }, { status: 409 });
      }
    }

    const expires_at = ttl_seconds
      ? new Date(Date.now() + ttl_seconds * 1000).toISOString()
      : null;

    const { data: action, error } = await admin.from("remediation_actions").insert({
      organization_id: orgId,
      server_id,
      detection_id: detection_id || null,
      action_type,
      target_value,
      status: "pending",
      expires_at,
    }).select().single();

    if (error) return NextResponse.json({ error: "Failed to create action" }, { status: 500 });

    return NextResponse.json({ action }, { status: 201 });
  } catch (err) {
    console.error("Create remediation error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
