import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient } from "@/lib/supabase";

// POST /api/auth/refresh — trade a refresh token for a new session.
//
// /api/auth/login hands bearer clients (mobile, CLI) a Supabase session whose
// access token lasts an hour. Without this they had to ask for the password
// again every hour; the refresh token rotates on each use.
export async function POST(req: NextRequest) {
  try {
    let refreshToken: unknown;
    try {
      const body: unknown = await req.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      refreshToken = "refresh_token" in body ? body.refresh_token : undefined;
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    if (typeof refreshToken !== "string" || !refreshToken || refreshToken.length > 4096) {
      return NextResponse.json({ error: "refresh_token is required" }, { status: 400 });
    }

    const { data, error } = await getSupabaseClient().auth.refreshSession({
      refresh_token: refreshToken,
    });
    if (error || !data.session) {
      return NextResponse.json({ error: "Session expired. Sign in again." }, { status: 401 });
    }

    const { session } = data;
    return NextResponse.json({
      session: {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_at: session.expires_at ?? null,
      },
      user: { id: session.user.id, email: session.user.email ?? null },
    });
  } catch (err) {
    console.error("Refresh error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
