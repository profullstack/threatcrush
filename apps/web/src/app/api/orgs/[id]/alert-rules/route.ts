import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/orgs/[id]/alert-rules
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

    const { data: rules, error } = await admin.from("alert_rules")
      .select("*").eq("organization_id", orgId).order("created_at", { ascending: false });

    if (error) return NextResponse.json({ error: "Failed to fetch" }, { status: 500 });

    return NextResponse.json({ rules: rules || [] });
  } catch (err) {
    console.error("List alert rules error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/alert-rules
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
    const { name, min_severity, server_scope, destination_id, rate_limit_per_hour, enabled } = body as {
      name: string; min_severity: string; server_scope?: string[];
      destination_id: string; rate_limit_per_hour?: number; enabled?: boolean;
    };

    if (!name || !min_severity || !destination_id) {
      return NextResponse.json({ error: "name, min_severity, and destination_id required" }, { status: 400 });
    }

    // Verify destination belongs to this org
    const { data: dest } = await admin.from("alert_destinations")
      .select("id").eq("id", destination_id).eq("organization_id", orgId).single();
    if (!dest) return NextResponse.json({ error: "Destination not found" }, { status: 404 });

    const { data: rule, error } = await admin.from("alert_rules").insert({
      organization_id: orgId,
      name,
      min_severity,
      server_scope: server_scope || [],
      destination_id,
      rate_limit_per_hour: rate_limit_per_hour || 60,
      enabled: enabled !== false,
    }).select().single();

    if (error) return NextResponse.json({ error: "Failed to create" }, { status: 500 });

    return NextResponse.json({ rule }, { status: 201 });
  } catch (err) {
    console.error("Create alert rule error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id]/alert-rules — Update a rule
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
    const { rule_id, ...updates } = body as { rule_id: string; [key: string]: unknown };

    if (!rule_id) return NextResponse.json({ error: "rule_id required" }, { status: 400 });

    const allowed = ["name", "min_severity", "server_scope", "destination_id", "rate_limit_per_hour", "enabled"];
    const filtered: Record<string, unknown> = {};
    for (const key of allowed) {
      if (key in updates) filtered[key] = updates[key];
    }

    if (Object.keys(filtered).length === 0) {
      return NextResponse.json({ error: "No valid fields" }, { status: 400 });
    }

    const { data: rule, error } = await admin.from("alert_rules")
      .update(filtered)
      .eq("id", rule_id)
      .eq("organization_id", orgId)
      .select()
      .single();

    if (error) return NextResponse.json({ error: "Failed to update" }, { status: 500 });

    return NextResponse.json({ rule });
  } catch (err) {
    console.error("Update alert rule error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id]/alert-rules
export async function DELETE(
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

    const url = new URL(req.url);
    const ruleId = url.searchParams.get("rule_id");
    if (!ruleId) return NextResponse.json({ error: "rule_id required" }, { status: 400 });

    const { error } = await admin.from("alert_rules")
      .delete().eq("id", ruleId).eq("organization_id", orgId);

    if (error) return NextResponse.json({ error: "Failed to delete" }, { status: 500 });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Delete alert rule error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
