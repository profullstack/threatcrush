import { NextRequest, NextResponse } from "next/server";
import { requireServer } from "@/lib/route-access";

type Params = { params: Promise<{ id: string; server_id: string }> };

// GET /api/orgs/[id]/servers/[server_id]/findings (read access)
export async function GET(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "read", "id, org_id, fleet_id");
    if ("error" in access) return access.error;

    const { data: findings, error } = await access.admin.from("hardening_findings")
      .select("*")
      .eq("organization_id", orgId)
      .eq("server_id", server_id)
      .order("severity", { ascending: false });

    if (error) return NextResponse.json({ error: "Failed to fetch findings" }, { status: 500 });

    // Compute hardening score
    const total = (findings || []).length;
    const passed = (findings || []).filter(f => f.status === "pass").length;
    const score = total > 0 ? Math.round((passed / total) * 100) : 100;

    return NextResponse.json({ findings: findings || [], score });
  } catch (err) {
    console.error("Server findings error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id]/servers/[server_id]/findings — Update finding status (write access)
export async function PATCH(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "write", "id, org_id, fleet_id");
    if ("error" in access) return access.error;

    const body = await req.json();
    const { finding_id, status: newStatus } = body as { finding_id: string; status: string };

    if (!finding_id || !newStatus) {
      return NextResponse.json({ error: "finding_id and status required" }, { status: 400 });
    }

    if (!["pass", "warn", "fail", "acknowledged", "resolved"].includes(newStatus)) {
      return NextResponse.json({ error: "Invalid status" }, { status: 400 });
    }

    const updates: Record<string, unknown> = { status: newStatus };
    if (newStatus === "resolved") updates.resolved_at = new Date().toISOString();

    const { error } = await access.admin.from("hardening_findings")
      .update(updates)
      .eq("id", finding_id)
      .eq("organization_id", orgId)
      .eq("server_id", server_id);

    if (error) return NextResponse.json({ error: "Failed to update finding" }, { status: 500 });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Update finding error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
