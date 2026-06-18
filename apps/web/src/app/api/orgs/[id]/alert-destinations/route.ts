import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/orgs/[id]/alert-destinations
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

    const { data: destinations, error } = await admin.from("alert_destinations")
      .select("id, organization_id, name, type, enabled, created_at")
      .eq("organization_id", orgId).order("created_at", { ascending: false });

    if (error) return NextResponse.json({ error: "Failed to fetch" }, { status: 500 });

    return NextResponse.json({ destinations: destinations || [] });
  } catch (err) {
    console.error("List alert destinations error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/alert-destinations
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
    const { name, type, config, enabled } = body as {
      name: string; type: string; config: Record<string, unknown>; enabled?: boolean;
    };

    if (!name || !type || !config) {
      return NextResponse.json({ error: "name, type, and config required" }, { status: 400 });
    }

    const validTypes = ["slack", "discord", "email", "webhook", "pagerduty", "push"];
    if (!validTypes.includes(type)) {
      return NextResponse.json({ error: `Invalid type. Must be one of: ${validTypes.join(", ")}` }, { status: 400 });
    }

    const { data: dest, error } = await admin.from("alert_destinations").insert({
      organization_id: orgId,
      name,
      type,
      config,
      enabled: enabled !== false,
    }).select("id, organization_id, name, type, enabled, created_at").single();

    if (error) return NextResponse.json({ error: "Failed to create" }, { status: 500 });

    return NextResponse.json({ destination: dest }, { status: 201 });
  } catch (err) {
    console.error("Create alert destination error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
