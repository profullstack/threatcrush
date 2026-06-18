import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// PATCH /api/orgs/[id]/alert-destinations/[dest_id]
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; dest_id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId, dest_id } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const body = await req.json();
    const updates: Record<string, unknown> = {};
    if (body.name !== undefined) updates.name = body.name;
    if (body.config !== undefined) updates.config = body.config;
    if (body.enabled !== undefined) updates.enabled = body.enabled;

    if (Object.keys(updates).length === 0) {
      return NextResponse.json({ error: "No fields to update" }, { status: 400 });
    }

    const { data: dest, error } = await admin.from("alert_destinations")
      .update(updates)
      .eq("id", dest_id)
      .eq("organization_id", orgId)
      .select("id, organization_id, name, type, enabled, created_at")
      .single();

    if (error) return NextResponse.json({ error: "Failed to update" }, { status: 500 });

    return NextResponse.json({ destination: dest });
  } catch (err) {
    console.error("Update alert destination error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id]/alert-destinations/[dest_id]
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; dest_id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId, dest_id } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const { error } = await admin.from("alert_destinations")
      .delete().eq("id", dest_id).eq("organization_id", orgId);

    if (error) return NextResponse.json({ error: "Failed to delete" }, { status: 500 });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Delete alert destination error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/alert-destinations/[dest_id] — Test alert
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; dest_id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId, dest_id } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const { data: dest } = await admin.from("alert_destinations")
      .select("*").eq("id", dest_id).eq("organization_id", orgId).single();

    if (!dest) return NextResponse.json({ error: "Destination not found" }, { status: 404 });

    // Send test alert based on type
    const testMessage = {
      title: "ThreatCrush Test Alert",
      severity: "info",
      message: "This is a test alert from ThreatCrush. If you received this, your alert destination is configured correctly.",
      timestamp: new Date().toISOString(),
    };

    try {
      switch (dest.type) {
        case "webhook": {
          const url = dest.config.url as string;
          if (!url) return NextResponse.json({ error: "Webhook URL not configured" }, { status: 400 });
          await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(testMessage),
          });
          break;
        }
        case "slack": {
          const url = dest.config.webhook_url as string;
          if (!url) return NextResponse.json({ error: "Slack webhook not configured" }, { status: 400 });
          await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: `:white_check_mark: ${testMessage.title}\n${testMessage.message}` }),
          });
          break;
        }
        case "discord": {
          const url = dest.config.webhook_url as string;
          if (!url) return NextResponse.json({ error: "Discord webhook not configured" }, { status: 400 });
          await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: `**${testMessage.title}**\n${testMessage.message}` }),
          });
          break;
        }
        default:
          return NextResponse.json({ message: `Test for ${dest.type} acknowledged (delivery not yet implemented server-side)` });
      }
    } catch (sendErr) {
      return NextResponse.json({ error: `Test failed: ${(sendErr as Error).message}` }, { status: 502 });
    }

    return NextResponse.json({ success: true, message: "Test alert sent" });
  } catch (err) {
    console.error("Test alert error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
