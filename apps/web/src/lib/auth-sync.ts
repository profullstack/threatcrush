import "server-only";
import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * Mirror auth.users.email_confirmed_at into user_profiles.email_verified.
 *
 * Supabase's hosted email confirmation flips email_confirmed_at on the auth
 * user but never touches our user_profiles row, so the column drifts and the
 * module-publish gate stays closed even after a successful click-through.
 * Idempotent: returns the post-sync value, true only if the auth user is
 * actually confirmed.
 */
export async function syncEmailVerifiedIfConfirmed(userId: string): Promise<boolean> {
  const admin = getSupabaseAdmin();

  const { data: authData, error: authErr } = await admin.auth.admin.getUserById(userId);
  if (authErr || !authData?.user?.email_confirmed_at) return false;

  const { error: updErr } = await admin
    .from("user_profiles")
    .update({ email_verified: true, updated_at: new Date().toISOString() })
    .eq("id", userId)
    .eq("email_verified", false);

  if (updErr) {
    console.error("[auth-sync] update failed:", updErr);
    return false;
  }

  return true;
}
