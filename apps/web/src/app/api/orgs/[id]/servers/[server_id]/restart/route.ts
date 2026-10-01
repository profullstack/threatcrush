import { NextRequest, NextResponse } from "next/server";
import { requireServer } from "@/lib/route-access";
import { queueRestart } from "@/lib/restart";

// POST /api/orgs/[id]/servers/[server_id]/restart — queue a restart of one
// server's daemon. Admin access on that server (a control action, not a
// per-detection response).
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; server_id: string }> },
) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "admin", "id, org_id, fleet_id");
    if ("error" in access) return access.error;

    await queueRestart(access.admin, orgId, [server_id]);
    return NextResponse.json({ queued: 1 });
  } catch (err) {
    console.error("Restart server error:", err);
    return NextResponse.json({ error: (err as Error).message || "Internal server error" }, { status: 500 });
  }
}
