import { NextRequest, NextResponse } from "next/server";
import { requireServer } from "@/lib/route-access";

type Params = { params: Promise<{ id: string; server_id: string }> };

// GET /api/orgs/[org_id]/servers/[id] — Get server details (read access)
export async function GET(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "read");
    if ("error" in access) return access.error;
    return NextResponse.json({ server: { ...access.server, my_role: access.role } });
  } catch (err) {
    console.error("Get server error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[org_id]/servers/[id] — Update server metadata (admin access)
export async function PATCH(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "admin", "id, org_id, fleet_id");
    if ("error" in access) return access.error;

    const body = await req.json();
    const allowedFields = ["name", "hostname", "ip_address", "port", "ssh_username"];
    const updates: Record<string, unknown> = {};

    for (const field of allowedFields) {
      if (field in body) {
        updates[field] = body[field];
      }
    }

    if (Object.keys(updates).length === 0) {
      return NextResponse.json({ error: "No valid fields to update" }, { status: 400 });
    }

    const { data: server, error } = await access.admin
      .from("servers")
      .update(updates)
      .eq("org_id", orgId)
      .eq("id", server_id)
      .select()
      .single();

    if (error) {
      console.error("Failed to update server:", error);
      return NextResponse.json({ error: "Failed to update server" }, { status: 500 });
    }

    return NextResponse.json({ server });
  } catch (err) {
    console.error("Update server error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[org_id]/servers/[id] — Remove server (admin access)
export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "admin", "id, org_id, fleet_id");
    if ("error" in access) return access.error;

    const { error } = await access.admin
      .from("servers")
      .delete()
      .eq("org_id", orgId)
      .eq("id", server_id);

    if (error) {
      console.error("Failed to remove server:", error);
      return NextResponse.json({ error: "Failed to remove server" }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Remove server error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
