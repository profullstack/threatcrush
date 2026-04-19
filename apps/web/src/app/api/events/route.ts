import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

export async function GET(req: NextRequest) {
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

    const { data: profile } = await admin
      .from("user_profiles")
      .select("id")
      .eq("id", user.id)
      .single();

    if (!profile) {
      return NextResponse.json({ error: "Profile not found" }, { status: 404 });
    }

    // Query events from the state DB is per-user via phone_verification_codes or a future events table
    // For now, return threat stats derived from phone_verification_codes activity
    // and any future event tables that get created
    const { count: threatCount } = await admin
      .from("phone_verification_codes")
      .select("*", { count: "exact", head: true })
      .gt("attempts", 0);

    return NextResponse.json({
      events: [],
      stats: {
        threats: threatCount || 0,
        warnings: 0,
        eventsToday: 0,
        modulesRunning: 0,
      },
    });
  } catch (err) {
    console.error("Events API error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
