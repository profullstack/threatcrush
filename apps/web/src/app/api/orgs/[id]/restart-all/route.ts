import { NextRequest, NextResponse } from "next/server";
import { atLeast } from "@/lib/access";
import { requireOrgScope, serverRolesIn } from "@/lib/route-access";
import { queueRestart } from "@/lib/restart";

// POST /api/orgs/[id]/restart-all — queue a restart for every server the caller
// is an admin of in this org. The "restart all" shortcut.
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id: orgId } = await params;
    const access = await requireOrgScope(req, orgId);
    if ("error" in access) return access.error;

    const roles = await serverRolesIn(access.admin, orgId, access.scope);
    const ids = [...roles.entries()].filter(([, role]) => atLeast(role, "admin")).map(([id]) => id);
    if (ids.length === 0) {
      return NextResponse.json({ error: "You are not an admin of any server in this organization" }, { status: 403 });
    }

    const queued = await queueRestart(access.admin, orgId, ids);
    return NextResponse.json({ queued });
  } catch (err) {
    console.error("Restart-all error:", err);
    return NextResponse.json({ error: (err as Error).message || "Internal server error" }, { status: 500 });
  }
}
