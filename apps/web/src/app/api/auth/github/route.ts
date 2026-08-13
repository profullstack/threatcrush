import { createClient } from "@supabase/supabase-js";
import { NextRequest, NextResponse } from "next/server";
import { createOAuthCookieStorage } from "@/lib/oauth-cookie-storage";
import { safeRedirectPath } from "@/lib/safe-redirect";

/**
 * GET /api/auth/github
 * Initiates GitHub OAuth flow via Supabase Auth.
 */
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const ref = searchParams.get("ref") || "";
  const nextPath = safeRedirectPath(searchParams.get("next"));
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";

  if (!supabaseUrl || !supabaseAnonKey) {
    return NextResponse.json({ error: "Supabase is not configured" }, { status: 500 });
  }

  const { storage, applyVerifierCookies } = createOAuthCookieStorage(request.cookies);
  const sb = createClient(supabaseUrl, supabaseAnonKey, {
    auth: {
      flowType: "pkce",
      storage,
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  const redirectTo = `${appUrl}/api/auth/callback?ref=${encodeURIComponent(ref)}&next=${encodeURIComponent(nextPath)}`;

  const { data, error } = await sb.auth.signInWithOAuth({
    provider: "github",
    options: {
      redirectTo,
      scopes: "user:email",
    },
  });

  if (error || !data.url) {
    return NextResponse.json({ error: error?.message || "OAuth failed" }, { status: 500 });
  }

  const response = NextResponse.redirect(data.url);
  applyVerifierCookies(response, new URL(appUrl).protocol === "https:");
  return response;
}
