import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";

// PATCH /api/orgs/[id]/remediations/[action_id]
// Body: { status: 'executed'|'failed', error?, dry_run?, executed_at? }
// The daemon reports the outcome of an action it claimed. Only an `executing`
// action can be completed; anything else is a 409 so a stale or duplicate
// report can't overwrite a result.
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; action_id: string }> },
) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const { id: orgId, action_id: actionId } = await params;
    const admin = getSupabaseAdmin();

    const { data: membership } = await admin
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", auth.userId)
      .maybeSingle();
    if (!membership) return NextResponse.json({ error: "Not a member" }, { status: 403 });

    const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "JSON body required" }, { status: 400 });
    }
    const { status, error: errorText, dry_run: dryRun, executed_at: executedAt } = body;
    if (status !== "executed" && status !== "failed") {
      return NextResponse.json({ error: "status must be executed or failed" }, { status: 400 });
    }
    if (errorText !== undefined && errorText !== null && (typeof errorText !== "string" || errorText.length > 2000)) {
      return NextResponse.json({ error: "error must be a string of at most 2000 characters" }, { status: 400 });
    }
    if (dryRun !== undefined && typeof dryRun !== "boolean") {
      return NextResponse.json({ error: "dry_run must be a boolean" }, { status: 400 });
    }
    let executedIso = new Date().toISOString();
    if (executedAt !== undefined && executedAt !== null) {
      const ms = typeof executedAt === "string" ? Date.parse(executedAt) : NaN;
      if (!Number.isFinite(ms)) {
        return NextResponse.json({ error: "executed_at must be an ISO timestamp" }, { status: 400 });
      }
      executedIso = new Date(ms).toISOString();
    }

    const { data: current } = await admin
      .from("remediation_actions")
      .select("id, status, metadata")
      .eq("organization_id", orgId)
      .eq("id", actionId)
      .maybeSingle();
    if (!current) return NextResponse.json({ error: "Remediation not found" }, { status: 404 });
    if (current.status !== "executing") {
      return NextResponse.json(
        { error: `Remediation is ${current.status}, not executing` },
        { status: 409 },
      );
    }

    const metadata: Record<string, unknown> = { ...(current.metadata ?? {}) };
    if (typeof errorText === "string") metadata.error = errorText;
    if (typeof dryRun === "boolean") metadata.dry_run = dryRun;

    // The status guard makes this a compare-and-set: if the lease lapsed and
    // the action was re-queued or re-claimed since the read, nothing matches.
    const { data: action, error } = await admin
      .from("remediation_actions")
      .update({ status, executed_at: executedIso, metadata })
      .eq("organization_id", orgId)
      .eq("id", actionId)
      .eq("status", "executing")
      .select()
      .maybeSingle();
    if (error) {
      console.error("Complete remediation error:", error);
      return NextResponse.json({ error: "Failed to update remediation" }, { status: 500 });
    }
    if (!action) {
      return NextResponse.json({ error: "Remediation is no longer executing" }, { status: 409 });
    }

    return NextResponse.json({ action });
  } catch (err) {
    console.error("Complete remediation error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
