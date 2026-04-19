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

function advanceFrom(base: Date, schedule: string): Date {
  const next = new Date(base);
  switch (schedule) {
    case "hourly":  next.setUTCHours(next.getUTCHours() + 1); break;
    case "daily":   next.setUTCDate(next.getUTCDate() + 1); break;
    case "weekly":  next.setUTCDate(next.getUTCDate() + 7); break;
    case "monthly": next.setUTCMonth(next.getUTCMonth() + 1); break;
    default:        next.setUTCDate(next.getUTCDate() + 1);
  }
  return next;
}

// POST /api/orgs/[id]/schedules/tick
// Finds enabled properties whose next_run_at has passed, enqueues a run for
// each, and advances next_run_at. Idempotent enough for polling workers.
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const userId = await authUserId(req);
    if (!userId) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const { id: orgId } = await params;
    const role = await requireMembership(orgId, userId);
    if (!role) return NextResponse.json({ error: "Not a member" }, { status: 403 });

    const admin = getSupabaseAdmin();
    const now = new Date();

    const { data: overdue, error } = await admin
      .from("properties")
      .select("id, kind, schedule, next_run_at")
      .eq("org_id", orgId)
      .eq("enabled", true)
      .not("schedule", "is", null)
      .or(`next_run_at.is.null,next_run_at.lte.${now.toISOString()}`);

    if (error) {
      console.error("Schedule tick error:", error);
      return NextResponse.json({ error: "Failed to scan schedules" }, { status: 500 });
    }

    const enqueued: Array<{ property_id: string; run_id: string }> = [];
    for (const prop of overdue || []) {
      const runType = prop.kind === "repo" ? "scan" : "pentest";

      // Skip if there's already a queued or running run for this property.
      const { count } = await admin
        .from("property_runs")
        .select("id", { count: "exact", head: true })
        .eq("property_id", prop.id)
        .eq("org_id", orgId)
        .in("status", ["queued", "running"]);
      if ((count || 0) > 0) {
        // Still advance the cursor so we don't keep retrying this minute.
        await admin
          .from("properties")
          .update({ next_run_at: advanceFrom(now, prop.schedule as string).toISOString() })
          .eq("id", prop.id)
          .eq("org_id", orgId);
        continue;
      }

      const { data: run, error: insertErr } = await admin
        .from("property_runs")
        .insert({
          org_id: orgId,
          property_id: prop.id,
          type: runType,
          status: "queued",
          trigger: "schedule",
        })
        .select("id")
        .single();

      if (insertErr || !run) {
        console.error("Failed to enqueue scheduled run:", insertErr);
        continue;
      }
      enqueued.push({ property_id: prop.id, run_id: run.id });

      await admin
        .from("properties")
        .update({ next_run_at: advanceFrom(now, prop.schedule as string).toISOString() })
        .eq("id", prop.id)
        .eq("org_id", orgId);
    }

    return NextResponse.json({ enqueued });
  } catch (err) {
    console.error("Schedule tick error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
