import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

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
    const ok =
      minRole === "owner"
        ? data.role === "owner"
        : data.role === "owner" || data.role === "admin";
    if (!ok) return null;
  }
  return data.role;
}

// GET /api/orgs/[id]/properties/[property_id]/runs
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; property_id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId, property_id } = await params;
    const role = await requireMembership(orgId, userId);
    if (!role) return NextResponse.json({ error: "Not a member" }, { status: 403 });

    const url = new URL(req.url);
    const limit = Math.min(100, parseInt(url.searchParams.get("limit") || "25", 10) || 25);

    const { data: runs, error } = await getSupabaseAdmin()
      .from("property_runs")
      .select("*")
      .eq("org_id", orgId)
      .eq("property_id", property_id)
      .order("queued_at", { ascending: false })
      .limit(limit);

    if (error) {
      console.error("List runs error:", error);
      return NextResponse.json({ error: "Failed to list runs" }, { status: 500 });
    }

    return NextResponse.json({ runs: runs || [] });
  } catch (err) {
    console.error("List runs error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/properties/[property_id]/runs — enqueue a new run
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; property_id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId, property_id } = await params;
    const role = await requireMembership(orgId, userId, "admin");
    if (!role) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

    const body = await req.json().catch(() => ({}));
    const type = body.type === "scan" ? "scan" : body.type === "pentest" ? "pentest" : null;
    const trigger = ["manual", "api", "cli", "schedule"].includes(body.trigger) ? body.trigger : "manual";

    // Make sure property belongs to this org.
    const { data: property, error: propErr } = await getSupabaseAdmin()
      .from("properties")
      .select("id, kind")
      .eq("id", property_id)
      .eq("org_id", orgId)
      .single();

    if (propErr || !property) {
      return NextResponse.json({ error: "Property not found" }, { status: 404 });
    }

    const runType = type || (property.kind === "repo" ? "scan" : "pentest");

    const { data: run, error } = await getSupabaseAdmin()
      .from("property_runs")
      .insert({
        org_id: orgId,
        property_id: property.id,
        type: runType,
        status: "queued",
        trigger,
        created_by: userId,
      })
      .select()
      .single();

    if (error) {
      console.error("Enqueue run error:", error);
      return NextResponse.json({ error: "Failed to enqueue run" }, { status: 500 });
    }

    return NextResponse.json({ run }, { status: 201 });
  } catch (err) {
    console.error("Enqueue run error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
