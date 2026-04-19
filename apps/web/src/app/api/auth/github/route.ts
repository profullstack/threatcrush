import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";

/**
 * GET /api/auth/github
 * Initiates GitHub OAuth flow via Supabase Auth.
 */
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const ref = searchParams.get("ref") || "";
  const next = searchParams.get("next") || "/account";

  const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

  const redirectTo = `${APP_URL}/api/auth/callback?ref=${encodeURIComponent(ref)}&next=${encodeURIComponent(next)}`;

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

  return NextResponse.redirect(data.url);
}
