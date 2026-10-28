import { NextRequest, NextResponse } from "next/server";
import { atLeast } from "@/lib/access";
import { compareVersions } from "@/lib/fleet";
import { latestPublishedVersion } from "@/lib/latest-release";
import { requireOrgScope, serverRolesIn } from "@/lib/route-access";
import { queueUpdate } from "@/lib/restart";

// POST /api/orgs/[id]/update-all — "Update all": every server the caller is an
// admin of that runs older than the newest published release gets an update
// (or, on a daemon too old to know that action, a restart that makes its
// auto-updater check). See queueUpdate in lib/restart.ts.
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id: orgId } = await params;
    const access = await requireOrgScope(req, orgId);
    if ("error" in access) return access.error;

    const roles = await serverRolesIn(access.admin, orgId, access.scope);
    const ids = [...roles.entries()].filter(([, role]) => atLeast(role, "admin")).map(([id]) => id);
    if (ids.length === 0) {
      return NextResponse.json({ error: "You are not an admin of any server in this organization" }, { status: 403 });
    }
    const { data: rows, error } = await access.admin
      .from("servers").select("id, threatcrushd_version").eq("org_id", orgId).in("id", ids);
    if (error) throw new Error("Could not load servers");

    const latest = await latestPublishedVersion();
    const behind = (rows ?? []).filter((r) => !latest || compareVersions(r.threatcrushd_version, latest) < 0);
    const queued = await queueUpdate(access.admin, orgId, behind.map((r) => ({ id: r.id, version: r.threatcrushd_version })));
    return NextResponse.json({ latest, ...queued, current: (rows ?? []).length - behind.length });
  } catch (err) {
    console.error("Update-all error:", err);
    return NextResponse.json({ error: (err as Error).message || "Internal server error" }, { status: 500 });
  }
}
