import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/orgs/[id]/allowlists
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

    const { data: entries, error } = await admin.from("allowlists")
      .select("*").eq("organization_id", orgId).order("created_at", { ascending: false });

    if (error) return NextResponse.json({ error: "Failed to fetch allowlists" }, { status: 500 });

    return NextResponse.json({ entries: entries || [] });
  } catch (err) {
    console.error("List allowlists error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/allowlists
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
    const { type, value, note } = body as { type: string; value: string; note?: string };

    if (!type || !value) return NextResponse.json({ error: "type and value required" }, { status: 400 });
    if (!["ip", "cidr", "user"].includes(type)) {
      return NextResponse.json({ error: "Invalid type" }, { status: 400 });
    }

    const { data: entry, error } = await admin.from("allowlists").insert({
      organization_id: orgId,
      type,
      value,
      note: note || null,
    }).select().single();

    if (error) {
      if (error.code === "23505") return NextResponse.json({ error: "Already exists" }, { status: 409 });
      return NextResponse.json({ error: "Failed to add" }, { status: 500 });
    }

    return NextResponse.json({ entry }, { status: 201 });
  } catch (err) {
    console.error("Add allowlist error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id]/allowlists
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
    const entryId = url.searchParams.get("entry_id");
    if (!entryId) return NextResponse.json({ error: "entry_id required" }, { status: 400 });

    const { error } = await admin.from("allowlists")
      .delete().eq("id", entryId).eq("organization_id", orgId);

    if (error) return NextResponse.json({ error: "Failed to delete" }, { status: 500 });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Delete allowlist error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
