import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";

const supabaseUrl = SUPABASE_URL || "";
const supabaseKey = SUPABASE_SERVICE_KEY || "";

function generateReferralCode(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

/**
 * GET /api/auth/callback
 * Handles OAuth callback from Supabase Auth (GitHub, etc).
 * Creates user_profiles row if first login.
 */
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get("code");
  const ref = searchParams.get("ref") || "";
  const nextParam = searchParams.get("next") || "/account";
  const nextPath = nextParam.startsWith("/") ? nextParam : "/account";

  if (!code) {
    return NextResponse.redirect(`${APP_URL}/auth/login?error=no_code`);
  }

  if (!supabaseUrl || !supabaseKey) {
    // Supabase not configured — redirect to login with env-missing hint
    return NextResponse.redirect(`${APP_URL}/auth/login?error=env_missing`);
  }

  const sb = createClient(supabaseUrl, supabaseKey);

  // Exchange code for session
  const { data: sessionData, error: sessionError } = await sb.auth.exchangeCodeForSession(code);

  if (sessionError || !sessionData.user) {
    return NextResponse.redirect(`${APP_URL}/auth/login?error=auth_failed`);
  }

  const user = sessionData.user;
  const email = user.email || "";
  const displayName =
    user.user_metadata?.full_name ||
    user.user_metadata?.user_name ||
    user.user_metadata?.preferred_username ||
    email.split("@")[0];
  const avatarUrl = user.user_metadata?.avatar_url || null;

  // Check if profile exists
  const { data: existing } = await sb
    .from("user_profiles")
    .select("id")
    .eq("id", user.id)
    .single();

  if (!existing) {
    // Create profile on first OAuth login
    await sb.from("user_profiles").insert({
      id: user.id,
      email,
      display_name: displayName,
      avatar_url: avatarUrl,
      email_verified: true, // OAuth emails are pre-verified
      referral_code: generateReferralCode(),
      referred_by: ref || null,
    });
  }

  // Redirect to account page with session token in hash
  const accessToken = sessionData.session?.access_token || "";
  const refreshToken = sessionData.session?.refresh_token || "";

  return NextResponse.redirect(
    `${APP_URL}${nextPath}#access_token=${accessToken}&refresh_token=${refreshToken}&type=oauth`
  );
}
