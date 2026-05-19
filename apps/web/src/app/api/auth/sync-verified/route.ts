import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient } from "@/lib/supabase";
import { syncEmailVerifiedIfConfirmed } from "@/lib/auth-sync";

/**
 * POST /api/auth/sync-verified
 * Called by the /auth/verify page right after the Supabase email-confirm
 * redirect drops an access_token in the URL hash. Bridges Supabase's auth
 * confirmation back into user_profiles.email_verified.
 */
export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("authorization");
  const token = authHeader?.replace("Bearer ", "");
  if (!token) {
    return NextResponse.json({ error: "Missing bearer token" }, { status: 401 });
  }

  const supabase = getSupabaseClient();
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) {
    return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  }

  const synced = await syncEmailVerifiedIfConfirmed(data.user.id);
  return NextResponse.json({ email_verified: synced });
}
