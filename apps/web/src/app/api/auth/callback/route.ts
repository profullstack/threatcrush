import { createClient } from "@supabase/supabase-js";
import { NextRequest, NextResponse } from "next/server";
import { createOAuthCookieStorage } from "@/lib/oauth-cookie-storage";
import { safeRedirectPath } from "@/lib/safe-redirect";
import { getSupabaseAdmin } from "@/lib/supabase";

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
  const nextPath = safeRedirectPath(searchParams.get("next"));
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";

  if (!code) {
    return NextResponse.redirect(`${appUrl}/auth/login?error=no_code`);
  }

  if (!supabaseUrl || !supabaseAnonKey || !serviceKey) {
    return NextResponse.redirect(`${appUrl}/auth/login?error=env_missing`);
  }

  const { storage, applyVerifierCookies } = createOAuthCookieStorage(request.cookies);
  const sb = createClient(supabaseUrl, supabaseAnonKey, {
    auth: {
      flowType: "pkce",
      storage,
      persistSession: true,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  const { data: sessionData, error: sessionError } = await sb.auth.exchangeCodeForSession(code);

  if (sessionError || !sessionData.user) {
    const response = NextResponse.redirect(`${appUrl}/auth/login?error=auth_failed`);
    applyVerifierCookies(response, new URL(appUrl).protocol === "https:");
    return response;
  }

  const user = sessionData.user;
  const admin = getSupabaseAdmin();
  const email = user.email || "";
  const displayName =
    user.user_metadata?.full_name ||
    user.user_metadata?.user_name ||
    user.user_metadata?.preferred_username ||
    email.split("@")[0];
  const avatarUrl = user.user_metadata?.avatar_url || null;

  const { data: existing } = await admin
    .from("user_profiles")
    .select("id")
    .eq("id", user.id)
    .single();

  if (!existing) {
    await admin.from("user_profiles").insert({
      id: user.id,
      email,
      display_name: displayName,
      avatar_url: avatarUrl,
      email_verified: true,
      referral_code: generateReferralCode(),
      referred_by: ref || null,
    });
  }

  const accessToken = sessionData.session?.access_token || "";
  const refreshToken = sessionData.session?.refresh_token || "";
  const response = NextResponse.redirect(
    `${appUrl}${nextPath}#access_token=${accessToken}&refresh_token=${refreshToken}&type=oauth`
  );
  applyVerifierCookies(response, new URL(appUrl).protocol === "https:");
  return response;
}
