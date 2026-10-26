import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient } from "@/lib/supabase";
import { syncEmailVerifiedIfConfirmed } from "@/lib/auth-sync";
import { clearInviteCookie, INVITE_META_KEY, inviteCookie, onSignedIn } from "@/lib/credit-codes";

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

  // Email just confirmed: accept the invite the account signed up with and pay
  // the invite bonus if it now qualifies (never throws).
  const meta = (data.user.user_metadata ?? {}) as Record<string, unknown>;
  const invite = inviteCookie(req) || (typeof meta[INVITE_META_KEY] === "string" ? (meta[INVITE_META_KEY] as string) : "");
  await onSignedIn(data.user.id, invite);

  const res = NextResponse.json({ email_verified: synced });
  clearInviteCookie(req, res);
  return res;
}
