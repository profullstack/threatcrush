import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

async function authUserId(req: NextRequest): Promise<string | null> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) return null;
  const { data: { user } } = await getSupabaseAdmin().auth.getUser(token);
  return user?.id ?? null;
}

async function requireMembership(orgId: string, userId: string) {
  const { data } = await getSupabaseAdmin()
    .from("organization_members")
    .select("role")
    .eq("org_id", orgId)
    .eq("user_id", userId)
    .single();
  return data?.role ?? null;
}

// GET /api/orgs/[id]/runs/pending — list queued runs for this org (read-only)
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId } = await params;
    if (!(await requireMembership(orgId, userId))) {
      return NextResponse.json({ error: "Not a member" }, { status: 403 });
    }

    const { data: runs, error } = await getSupabaseAdmin()
      .from("property_runs")
      .select("*, property:properties(id, name, kind, target)")
      .eq("org_id", orgId)
      .eq("status", "queued")
      .order("queued_at", { ascending: true })
      .limit(10);

    if (error) {
      console.error("Pending runs error:", error);
      return NextResponse.json({ error: "Failed to load pending runs" }, { status: 500 });
    }

    return NextResponse.json({ runs: runs || [] });
  } catch (err) {
    console.error("Pending runs error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/runs/pending — atomically claim the next queued run.
// Body: { worker_id: string }
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId } = await params;
    const role = await requireMembership(orgId, userId);
    if (!role || !["owner", "admin", "member"].includes(role)) {
      return NextResponse.json({ error: "Not a member" }, { status: 403 });
    }

    const body = await req.json().catch(() => ({}));
    const workerId = typeof body.worker_id === "string" ? body.worker_id.slice(0, 128) : `worker-${userId.slice(0, 8)}`;

    const { data, error } = await getSupabaseAdmin().rpc("claim_next_property_run", {
      p_worker_id: workerId,
      p_org_ids: [orgId],
    });

    if (error) {
      console.error("Claim run error:", error);
      return NextResponse.json({ error: "Failed to claim run" }, { status: 500 });
    }

    const claimed = Array.isArray(data) && data.length > 0 ? data[0] : null;
    if (!claimed) {
      return NextResponse.json({ run: null });
    }

    // Hydrate with property for convenience.
    const { data: property } = await getSupabaseAdmin()
      .from("properties")
      .select("id, name, kind, target")
      .eq("id", claimed.property_id)
      .single();

    return NextResponse.json({ run: { ...claimed, property } });
  } catch (err) {
    console.error("Claim run error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
