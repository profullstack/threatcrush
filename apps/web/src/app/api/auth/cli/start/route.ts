import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  POLL_INTERVAL_SECONDS,
  cleanDeviceName,
  generateUserCode,
  isValidChallenge,
} from "@/lib/cli-login";

// POST /api/auth/cli/start — the CLI opens a login request and gets a link.
// Unauthenticated by design: the request is worthless until someone signed in
// approves it, and only the holder of the PKCE verifier can redeem it.
export async function POST(req: NextRequest) {
  try {
    let body: Record<string, unknown>;
    try {
      const parsed: unknown = await req.json();
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      body = parsed as Record<string, unknown>;
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    if (body.code_challenge_method !== "S256" || !isValidChallenge(body.code_challenge)) {
      return NextResponse.json(
        { error: "code_challenge must be an S256 challenge (code_challenge_method: S256)" },
        { status: 400 },
      );
    }

    const userCode = generateUserCode();
    const { data, error } = await getSupabaseAdmin()
      .from("cli_login_requests")
      .insert({
        code_challenge: body.code_challenge,
        user_code: userCode,
        device_name: cleanDeviceName(body.device_name),
      })
      .select("id, expires_at")
      .single();

    if (error || !data) {
      console.error("CLI login start failed:", error);
      return NextResponse.json({ error: "Could not start login" }, { status: 500 });
    }

    const appUrl = (process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com").replace(/\/$/, "");
    return NextResponse.json({
      request_id: data.id,
      user_code: userCode,
      verification_url: `${appUrl}/cli/login?request=${data.id}`,
      expires_at: data.expires_at,
      interval: POLL_INTERVAL_SECONDS,
    });
  } catch (err) {
    console.error("CLI login start error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
