import { NextRequest, NextResponse } from "next/server";
import { parsePaginationParam } from "@/lib/pagination";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/orgs/[id]/servers/[server_id]/detections — Server-scoped detections
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; server_id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId, server_id } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

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
