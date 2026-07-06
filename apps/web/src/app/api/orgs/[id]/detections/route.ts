import { NextRequest, NextResponse } from "next/server";
import { parsePaginationParam } from "@/lib/pagination";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/orgs/[id]/detections — List detections for org
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
    const severity = url.searchParams.get("severity");
    const serverId = url.searchParams.get("server_id");
    const status = url.searchParams.get("status");
    const ruleId = url.searchParams.get("rule_id");
    const since = url.searchParams.get("since");
    const until = url.searchParams.get("until");
    const limit = parsePaginationParam(url.searchParams.get("limit"), 50, { min: 1, max: 200 });
    const offset = parsePaginationParam(url.searchParams.get("offset"), 0);

    let query = admin.from("detections").select("*", { count: "exact" })
      .eq("organization_id", orgId)
      .order("detected_at", { ascending: false })
      .range(offset, offset + limit - 1);

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

// PATCH /api/orgs/[id]/detections — Bulk update detection status
export async function PATCH(
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
    const { ids, status: newStatus } = body as { ids: string[]; status: string };

    if (!ids?.length || !newStatus) {
      return NextResponse.json({ error: "ids and status required" }, { status: 400 });
    }

    if (!["new", "acknowledged", "resolved"].includes(newStatus)) {
      return NextResponse.json({ error: "Invalid status" }, { status: 400 });
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
