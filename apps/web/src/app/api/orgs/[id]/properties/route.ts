import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

const ALLOWED_KINDS = ["url", "api", "domain", "ip", "repo"] as const;
type PropertyKind = (typeof ALLOWED_KINDS)[number];

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

// GET /api/orgs/[id]/properties — list properties in an org
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId } = await params;
    const role = await requireMembership(orgId, userId);
    if (!role) return NextResponse.json({ error: "Not a member of this organization" }, { status: 403 });

    const url = new URL(req.url);
    const kind = url.searchParams.get("kind");

    let query = getSupabaseAdmin()
      .from("properties")
      .select("*")
      .eq("org_id", orgId)
      .order("created_at", { ascending: false });

    if (kind && ALLOWED_KINDS.includes(kind as PropertyKind)) {
      query = query.eq("kind", kind);
    }

    const { data: properties, error } = await query;
    if (error) {
      console.error("Failed to fetch properties:", error);
      return NextResponse.json({ error: "Failed to fetch properties" }, { status: 500 });
    }

    return NextResponse.json({ properties: properties || [] });
  } catch (err) {
    console.error("List properties error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/properties — add a property
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId } = await params;
    const role = await requireMembership(orgId, userId, "admin");
    if (!role) return NextResponse.json({ error: "Not authorized to add properties" }, { status: 403 });

    const body = await req.json();
    const { name, kind, target, description, tags, enabled, schedule } = body as {
      name?: string;
      kind?: PropertyKind;
      target?: string;
      description?: string;
      tags?: string[];
      enabled?: boolean;
      schedule?: "hourly" | "daily" | "weekly" | "monthly" | null;
    };

    if (!name || name.trim().length < 1) {
      return NextResponse.json({ error: "Property name is required" }, { status: 400 });
    }
    if (!kind || !ALLOWED_KINDS.includes(kind)) {
      return NextResponse.json({ error: `kind must be one of: ${ALLOWED_KINDS.join(", ")}` }, { status: 400 });
    }
    if (!target || target.trim().length < 1) {
      return NextResponse.json({ error: "target is required" }, { status: 400 });
    }

    const VALID_SCHEDULES = ["hourly", "daily", "weekly", "monthly"];
    const normalizedSchedule = schedule && VALID_SCHEDULES.includes(schedule) ? schedule : null;
    const firstRun = normalizedSchedule ? new Date().toISOString() : null;

    const { data: property, error } = await getSupabaseAdmin()
      .from("properties")
      .insert({
        org_id: orgId,
        name: name.trim(),
        kind,
        target: target.trim(),
        description: description?.trim() || null,
        tags: Array.isArray(tags) ? tags : [],
        enabled: enabled !== false,
        schedule: normalizedSchedule,
        next_run_at: firstRun,
        created_by: userId,
      })
      .select()
      .single();

    if (error) {
      if (error.code === "23505") {
        return NextResponse.json({ error: "A property with that name already exists in this org" }, { status: 409 });
      }
      console.error("Failed to create property:", error);
      return NextResponse.json({ error: "Failed to create property" }, { status: 500 });
    }

    return NextResponse.json({ property }, { status: 201 });
  } catch (err) {
    console.error("Create property error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
