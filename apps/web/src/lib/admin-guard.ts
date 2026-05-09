import "server-only";
import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient, getSupabaseAdmin } from "./supabase";

export type AdminUser = {
  id: string;
  email: string;
  is_admin: true;
};

/**
 * Verify the request is from a signed-in admin. Returns either the admin
 * user record or a NextResponse to short-circuit the route handler with.
 *
 * Usage:
 *   const guard = await requireAdmin(req);
 *   if (guard instanceof NextResponse) return guard;
 *   const admin = guard;
 */
export async function requireAdmin(
  req: NextRequest,
): Promise<AdminUser | NextResponse> {
  const authHeader = req.headers.get("authorization");
  const token = authHeader?.replace(/^Bearer\s+/i, "");
  if (!token) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const supabase = getSupabaseClient();
  const { data: userData, error: userErr } = await supabase.auth.getUser(token);
  const userId = userData?.user?.id;
  if (userErr || !userId) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  const { data: profile, error: profileErr } = await admin
    .from("user_profiles")
    .select("id, email, is_admin")
    .eq("id", userId)
    .single();

  if (profileErr || !profile) {
    return NextResponse.json({ error: "Profile not found" }, { status: 404 });
  }

  if (!profile.is_admin) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  return { id: profile.id, email: profile.email, is_admin: true };
}
