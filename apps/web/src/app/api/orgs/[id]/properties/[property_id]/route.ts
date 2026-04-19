import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

const ALLOWED_KINDS = ["url", "api", "domain", "ip", "repo"] as const;

async function authUserId(req: NextRequest): Promise<string | null> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) return null;
  const { data: { user } } = await getSupabaseAdmin().auth.getUser(token);
  return user?.id ?? null;
}

async function requireMembership(orgId: string, userId: string, minRole?: "admin" | "owner") {
  const { data } = await getSupabaseAdmin()
    .from("organization_members")
    .select("role")
    .eq("org_id", orgId)
    .eq("user_id", userId)
    .single();
  if (!data) return null;
  if (minRole) {
    const allowed =
      minRole === "owner"
        ? data.role === "owner"
        : data.role === "owner" || data.role === "admin";
    if (!allowed) return null;
  }
  return data.role;
}

// GET /api/orgs/[id]/properties/[property_id]
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; property_id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId, property_id } = await params;
    const role = await requireMembership(orgId, userId);
    if (!role) return NextResponse.json({ error: "Not a member of this organization" }, { status: 403 });

    const { data: property, error } = await getSupabaseAdmin()
      .from("properties")
      .select("*")
      .eq("id", property_id)
      .eq("org_id", orgId)
      .single();

    if (error || !property) {
      return NextResponse.json({ error: "Property not found" }, { status: 404 });
    }

    return NextResponse.json({ property });
  } catch (err) {
    console.error("Get property error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id]/properties/[property_id]
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; property_id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId, property_id } = await params;
    const role = await requireMembership(orgId, userId, "admin");
    if (!role) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

    const body = await req.json();
    const updates: Record<string, unknown> = {};

    if (typeof body.name === "string" && body.name.trim()) updates.name = body.name.trim();
    if (typeof body.kind === "string") {
      if (!ALLOWED_KINDS.includes(body.kind)) {
        return NextResponse.json({ error: `kind must be one of: ${ALLOWED_KINDS.join(", ")}` }, { status: 400 });
      }
      updates.kind = body.kind;
    }
    if (typeof body.target === "string" && body.target.trim()) updates.target = body.target.trim();
    if ("description" in body) updates.description = body.description?.trim() || null;
    if (Array.isArray(body.tags)) updates.tags = body.tags;
    if (typeof body.enabled === "boolean") updates.enabled = body.enabled;
    if ("schedule" in body) {
      const VALID = ["hourly", "daily", "weekly", "monthly", null];
      if (!VALID.includes(body.schedule)) {
        return NextResponse.json({ error: "schedule must be hourly, daily, weekly, monthly, or null" }, { status: 400 });
      }
      updates.schedule = body.schedule;
      // If enabling a schedule for the first time, set next_run_at to now.
      if (body.schedule && !body.next_run_at) {
        updates.next_run_at = new Date().toISOString();
      } else if (body.schedule === null) {
        updates.next_run_at = null;
      }
    }
    if ("next_run_at" in body) updates.next_run_at = body.next_run_at;
    if (typeof body.last_run_status === "string") updates.last_run_status = body.last_run_status;
    if ("last_run_at" in body) updates.last_run_at = body.last_run_at;

    if (Object.keys(updates).length === 0) {
      return NextResponse.json({ error: "No updatable fields provided" }, { status: 400 });
    }

    const { data: property, error } = await getSupabaseAdmin()
      .from("properties")
      .update(updates)
      .eq("id", property_id)
      .eq("org_id", orgId)
      .select()
      .single();

    if (error || !property) {
      if (error?.code === "23505") {
        return NextResponse.json({ error: "Another property with that name already exists" }, { status: 409 });
      }
      console.error("Failed to update property:", error);
      return NextResponse.json({ error: "Failed to update property" }, { status: 500 });
    }

    return NextResponse.json({ property });
  } catch (err) {
    console.error("Update property error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id]/properties/[property_id]
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; property_id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId, property_id } = await params;
    const role = await requireMembership(orgId, userId, "admin");
    if (!role) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

    const { error } = await getSupabaseAdmin()
      .from("properties")
      .delete()
      .eq("id", property_id)
      .eq("org_id", orgId);

    if (error) {
      console.error("Failed to delete property:", error);
      return NextResponse.json({ error: "Failed to delete property" }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Delete property error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
