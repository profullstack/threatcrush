import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// POST /api/ingest — Daemon pushes normalized detections + heartbeats
export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) {
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

    const body = await req.json();
    const { events } = body as { events?: Array<Record<string, unknown>> };

    if (!events || !Array.isArray(events) || events.length === 0) {
      return NextResponse.json({ error: "events array is required" }, { status: 400 });
    }

    // Batch limit
    if (events.length > 500) {
      return NextResponse.json({ error: "Max 500 events per batch" }, { status: 400 });
    }

    let detectionsInserted = 0;
    let heartbeatsProcessed = 0;
    const errors: string[] = [];

    for (const event of events) {
      try {
        if (event.type === "heartbeat") {
          const serverId = event.server_id as string;
          if (!serverId) { errors.push("heartbeat missing server_id"); continue; }

          // Verify server access
          const { data: server } = await admin.from("servers").select("org_id").eq("id", serverId).single();
          if (!server) { errors.push(`server ${serverId} not found`); continue; }

          const { data: membership } = await admin.from("organization_members")
            .select("role").eq("org_id", server.org_id).eq("user_id", user.id).single();
          if (!membership) { errors.push(`no access to server ${serverId}`); continue; }

          const updates: Record<string, unknown> = { last_seen: new Date().toISOString(), status: "online" };
          if (event.version) updates.threatcrushd_version = event.version;
          await admin.from("servers").update(updates).eq("id", serverId);
          heartbeatsProcessed++;

        } else if (event.type === "detection") {
          const serverId = event.server_id as string;
          if (!serverId) { errors.push("detection missing server_id"); continue; }
          if (!event.severity) { errors.push("detection missing severity"); continue; }
          if (!event.title) { errors.push("detection missing title"); continue; }

          // Verify server access
          const { data: server } = await admin.from("servers").select("org_id").eq("id", serverId).single();
          if (!server) { errors.push(`server ${serverId} not found`); continue; }

          const { data: membership } = await admin.from("organization_members")
            .select("role").eq("org_id", server.org_id).eq("user_id", user.id).single();
          if (!membership) { errors.push(`no access to server ${serverId}`); continue; }

          const { error: insertError } = await admin.from("detections").insert({
            organization_id: server.org_id,
            server_id: serverId,
            rule_id: event.rule_id || null,
            severity: event.severity,
            title: event.title,
            description: event.description || null,
            source_ip: event.source_ip || null,
            username: event.username || null,
            raw_metadata: event.raw_metadata || {},
            detected_at: event.detected_at || new Date().toISOString(),
            status: "new",
          });

          if (insertError) { errors.push(`insert failed: ${insertError.message}`); continue; }
          detectionsInserted++;
        } else {
          errors.push(`unknown event type: ${event.type}`);
        }
      } catch (err) {
        errors.push(`event processing error: ${(err as Error).message}`);
      }
    }

    return NextResponse.json({
      success: true,
      detections_inserted: detectionsInserted,
      heartbeats_processed: heartbeatsProcessed,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (err) {
    console.error("Ingest API error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
