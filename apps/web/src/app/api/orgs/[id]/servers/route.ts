import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { roleInScope, visibleIn } from "@/lib/access";
import { requireOrgScope } from "@/lib/route-access";

// GET /api/orgs/[org_id]/servers — the org's servers the caller can see (team
// fleets, agent keys: see lib/access), with the caller's role on each.
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: orgId } = await params;
    const access = await requireOrgScope(req, orgId);
    if ("error" in access) return access.error;

    const { data: servers, error } = await access.admin
      .from("servers")
      .select("*")
      .eq("org_id", orgId)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Failed to fetch servers:", error);
      return NextResponse.json({ error: "Failed to fetch servers" }, { status: 500 });
    }

    const visible = visibleIn(access.scope, servers || []).map((s) => ({ ...s, my_role: roleInScope(access.scope, s) }));
    return NextResponse.json({ servers: visible });
  } catch (err) {
    console.error("List servers error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[org_id]/servers — Register a new server
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { data: { user } } = await getSupabaseAdmin().auth.getUser(token);
    if (!user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { id: orgId } = await params;

    // Check user is admin/owner
    const { data: membership } = await getSupabaseAdmin()
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", user.id)
      .single();

    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized to add servers" }, { status: 403 });
    }

    const body = await req.json();
    const { name, hostname, ip_address, port = 22, ssh_username } = body as {
      name: string;
      hostname?: string;
      ip_address?: string;
      port?: number;
      ssh_username?: string;
    };

    if (!name || name.trim().length < 1) {
      return NextResponse.json({ error: "Server name is required" }, { status: 400 });
    }

    if (!hostname && !ip_address) {
      return NextResponse.json({ error: "Either hostname or ip_address is required" }, { status: 400 });
    }

    const { data: server, error } = await getSupabaseAdmin()
      .from("servers")
      .insert({
        org_id: orgId,
        name: name.trim(),
        hostname: hostname || null,
        ip_address: ip_address || null,
        port,
        ssh_username: ssh_username || null,
        created_by: user.id,
      })
      .select()
      .single();

    if (error) {
      console.error("Failed to register server:", error);
      return NextResponse.json({ error: "Failed to register server" }, { status: 500 });
    }

    return NextResponse.json({ server }, { status: 201 });
  } catch (err) {
    console.error("Register server error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
