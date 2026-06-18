import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/orgs/[id]/remediations
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

    const url = new URL(req.url);
    const serverId = url.searchParams.get("server_id");
    const status = url.searchParams.get("status");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 200);
    const offset = parseInt(url.searchParams.get("offset") || "0");

    let query = admin.from("remediation_actions").select("*", { count: "exact" })
      .eq("organization_id", orgId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

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
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

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
