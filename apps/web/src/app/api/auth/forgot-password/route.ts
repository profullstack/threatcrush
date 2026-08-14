import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient } from "@/lib/supabase";

/**
 * TC-15: `redirectTo` went straight into the password-reset email. An attacker
 * could send a victim a genuine reset link that lands on their own host, taking
 * the recovery token with it. Only our own origin is allowed.
 */
function safeRedirectTo(redirectTo: unknown, requestUrl: string): string | undefined {
  if (typeof redirectTo !== "string" || !redirectTo) return undefined;

  const appOrigin = process.env.NEXT_PUBLIC_APP_URL || new URL(requestUrl).origin;
  try {
    const target = new URL(redirectTo, appOrigin);
    return target.origin === new URL(appOrigin).origin ? target.href : undefined;
  } catch {
    return undefined;
  }
}

export async function POST(req: NextRequest) {
  try {
    const { email, redirectTo } = await req.json();
    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 });
    }

    const supabase = getSupabaseClient();
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: safeRedirectTo(redirectTo, req.url),
    });

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("Forgot password error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
