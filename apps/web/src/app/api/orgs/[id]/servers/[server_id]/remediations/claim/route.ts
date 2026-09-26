import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";

type ClaimedRow = {
  id: string;
  action_type: string;
  target_value: string;
  expires_at: string | null;
  metadata: Record<string, unknown> | null;
  created_at: string;
};

// POST /api/orgs/[id]/servers/[server_id]/remediations/claim
// The linked daemon takes up to 50 pending dashboard-issued actions for its
// server. They move to `executing`; a claim not reported back within 5 minutes
// returns to `pending` on a later claim.
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; server_id: string }> },
) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const { id: orgId, server_id: serverId } = await params;
    const admin = getSupabaseAdmin();

    const { data: membership } = await admin
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", auth.userId)
      .maybeSingle();
    if (!membership) return NextResponse.json({ error: "Not a member" }, { status: 403 });

    const { data: server } = await admin
      .from("servers")
      .select("id")
      .eq("org_id", orgId)
      .eq("id", serverId)
      .maybeSingle();
    if (!server) {
      return NextResponse.json({ error: "Server not found in this organization" }, { status: 404 });
    }

    const { data, error } = await admin.rpc("claim_server_remediations", {
      p_org_id: orgId,
      p_server_id: serverId,
      p_limit: 50,
    });
    if (error) {
      console.error("Claim remediations error:", error);
      return NextResponse.json({ error: "Failed to claim remediations" }, { status: 500 });
    }

    const actions = ((data ?? []) as ClaimedRow[])
      .map((row) => ({
        id: row.id,
        action_type: row.action_type,
        target_value: row.target_value,
        expires_at: row.expires_at,
        metadata: row.metadata ?? {},
        created_at: row.created_at,
      }))
      .sort((a, b) => a.created_at.localeCompare(b.created_at));

    return NextResponse.json({ actions });
  } catch (err) {
    console.error("Claim remediations error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
