import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// Helper: verify user is a member of the org that owns this server
async function verifyServerAccess(serverId: string, userId: string) {
  const { data: server } = await getSupabaseAdmin()
    .from("servers")
    .select("org_id")
    .eq("id", serverId)
    .single();

  if (!server) return { ok: false as const, error: "Server not found", status: 404 as const };

  const { data: membership } = await getSupabaseAdmin()
    .from("organization_members")
    .select("role")
    .eq("org_id", server.org_id)
    .eq("user_id", userId)
    .single();

  if (!membership) return { ok: false as const, error: "Not authorized", status: 403 as const };
  return { ok: true as const, server, role: membership.role };
}

// POST /api/servers/[id]/heartbeat — Server checks in to report status
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

    const { id } = await params;

    // Verify user has access to this server
    const access = await verifyServerAccess(id, user.id);
    if (!access.ok) {
      return NextResponse.json({ error: access.error }, { status: access.status });
    }

    const body = await req.json();
    const { version, status = "online" } = body as { version?: string; status?: string };

    const updates: Record<string, unknown> = {
      last_seen: new Date().toISOString(),
      status: ["online", "offline", "unreachable"].includes(status) ? status : "online",
    };

    if (version) {
      updates.threatcrushd_version = version;
    }

    const { data: server, error } = await getSupabaseAdmin()
      .from("servers")
      .update(updates)
      .eq("id", id)
      .select()
      .single();

    if (error) {
      console.error("Failed to update heartbeat:", error);
      return NextResponse.json({ error: "Failed to update heartbeat" }, { status: 500 });
    }

    return NextResponse.json({ server });
  } catch (err) {
    console.error("Heartbeat error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// GET /api/servers/[id] — Get server details
export async function GET(
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

    const { id } = await params;

    // Verify user has access to this server
    const access = await verifyServerAccess(id, user.id);
    if (!access.ok) {
      return NextResponse.json({ error: access.error }, { status: access.status });
    }

    const { data: server, error } = await getSupabaseAdmin()
      .from("servers")
      .select("*")
      .eq("id", id)
      .single();

    if (error || !server) {
      return NextResponse.json({ error: "Server not found" }, { status: 404 });
    }

    return NextResponse.json({ server });
  } catch (err) {
    console.error("Get server error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
