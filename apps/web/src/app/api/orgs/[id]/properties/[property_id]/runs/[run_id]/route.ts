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

// GET /api/orgs/[id]/properties/[property_id]/runs/[run_id]
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; property_id: string; run_id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId, property_id, run_id } = await params;
    if (!(await requireMembership(orgId, userId))) {
      return NextResponse.json({ error: "Not a member" }, { status: 403 });
    }

    const { data: run, error } = await getSupabaseAdmin()
      .from("property_runs")
      .select("*")
      .eq("id", run_id)
      .eq("org_id", orgId)
      .eq("property_id", property_id)
      .single();

    if (error || !run) {
      return NextResponse.json({ error: "Run not found" }, { status: 404 });
    }

    return NextResponse.json({ run });
  } catch (err) {
    console.error("Get run error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id]/properties/[property_id]/runs/[run_id] — update status/results
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; property_id: string; run_id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId, property_id, run_id } = await params;
    if (!(await requireMembership(orgId, userId, "admin"))) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const body = await req.json();
    const updates: Record<string, unknown> = {};

    if (typeof body.status === "string") {
      if (!["queued", "running", "succeeded", "failed", "cancelled"].includes(body.status)) {
        return NextResponse.json({ error: "invalid status" }, { status: 400 });
      }
      updates.status = body.status;
      if (body.status === "running" && !body.started_at) updates.started_at = new Date().toISOString();
      if (["succeeded", "failed", "cancelled"].includes(body.status)) {
        updates.completed_at = new Date().toISOString();
      }
    }
    if (typeof body.findings_count === "number") updates.findings_count = body.findings_count;
    if (body.severity_summary && typeof body.severity_summary === "object") updates.severity_summary = body.severity_summary;
    if (typeof body.summary === "string") updates.summary = body.summary;
    if (typeof body.output === "string") updates.output = body.output.slice(0, 200_000);
    if (body.findings && typeof body.findings === "object") updates.findings = body.findings;
    if (typeof body.error === "string") updates.error = body.error;
    if (typeof body.worker_id === "string") updates.worker_id = body.worker_id;
    if (typeof body.source === "string") updates.source = body.source;

    if (Object.keys(updates).length === 0) {
      return NextResponse.json({ error: "No updatable fields" }, { status: 400 });
    }

    const { data: run, error } = await getSupabaseAdmin()
      .from("property_runs")
      .update(updates)
      .eq("id", run_id)
      .eq("org_id", orgId)
      .eq("property_id", property_id)
      .select()
      .single();

    if (error || !run) {
      console.error("Update run error:", error);
      return NextResponse.json({ error: "Failed to update run" }, { status: 500 });
    }

    // Mirror the latest run state onto the parent property for quick display.
    if (typeof body.status === "string" && ["succeeded", "failed", "cancelled"].includes(body.status)) {
      await getSupabaseAdmin()
        .from("properties")
        .update({ last_run_at: run.completed_at, last_run_status: run.status })
        .eq("id", property_id)
        .eq("org_id", orgId);
    }

    return NextResponse.json({ run });
  } catch (err) {
    console.error("Update run error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
