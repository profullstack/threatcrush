import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

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

    // Verify server exists
    const { data: server } = await getSupabaseAdmin()
      .from("servers")
      .select("org_id")
      .eq("id", serverId)
      .single();

    if (!server) {
      return NextResponse.json({ error: "Server not found" }, { status: 404 });
    }

    const body = await req.json();
    const { events } = body as { events?: Array<Record<string, unknown>> };

    if (!events || !Array.isArray(events)) {
      return NextResponse.json({ error: "Events array is required" }, { status: 400 });
    }

    // For now, just acknowledge receipt. In production, you'd store these in an events table.
    // For the MVP, we'll just update the server's last_seen and return success.
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

    // Check user has access to the server's org
    const { data: server } = await getSupabaseAdmin()
      .from("servers")
      .select(`
        id,
        name,
        hostname,
        status,
        last_seen,
        threatcrushd_version,
        organizations!inner (
          id,
          organization_members (
            user_id
          )
        )
      `)
      .eq("id", serverId)
      .single();

    if (!server) {
      return NextResponse.json({ error: "Server not found" }, { status: 404 });
    }

    // Verify user is a member of the org
    const orgMembers = (server as any).organizations?.organization_members || [];
    const isMember = orgMembers.some((m: Record<string, string>) => m.user_id === user.id);

    if (!isMember) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    // For now, return empty events. In production, query the events table.
    return NextResponse.json({ events: [] });
  } catch (err) {
    console.error("Get events error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
