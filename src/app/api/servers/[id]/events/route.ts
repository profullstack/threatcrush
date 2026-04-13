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

// POST /api/servers/[id]/events — Server pushes threat events
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

    const { id: serverId } = await params;

    // Verify user has access to this server
    const access = await verifyServerAccess(serverId, user.id);
    if (!access.ok) {
      return NextResponse.json({ error: access.error }, { status: access.status });
    }

    const body = await req.json();
    const { events } = body as { events?: Array<Record<string, unknown>> };

    if (!events || !Array.isArray(events)) {
      return NextResponse.json({ error: "Events array is required" }, { status: 400 });
    }

    // For now, just acknowledge receipt. In production, you'd store these in an events table.
    await getSupabaseAdmin()
      .from("servers")
      .update({ last_seen: new Date().toISOString() })
      .eq("id", serverId);

    return NextResponse.json({
      success: true,
      received: events.length,
      message: `Processed ${events.length} event(s)`,
    });
  } catch (err) {
    console.error("Submit events error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// GET /api/servers/[id]/events — Get recent events for a server
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

    const { id: serverId } = await params;

    // Verify user has access to this server
    const access = await verifyServerAccess(serverId, user.id);
    if (!access.ok) {
      return NextResponse.json({ error: access.error }, { status: access.status });
    }

    // For now, return empty events. In production, query the events table.
    return NextResponse.json({ events: [] });
  } catch (err) {
    console.error("Get events error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
