import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";
import { syncEmailVerifiedIfConfirmed } from "@/lib/auth-sync";
import { SIGNUP_GRANT_COOKIE, verifySignupGrant } from "@/lib/signup-grant";

export async function GET(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization");
    const supabase = getSupabaseClient();

    const token = authHeader?.replace("Bearer ", "");
    let userId: string | null = null;

    if (token) {
      const { data: { user } } = await supabase.auth.getUser(token);
      userId = user?.id ?? null;
    } else {
      const { data: { session } } = await supabase.auth.getSession();
      userId = session?.user?.id ?? null;
    }

    // No session yet? The verify page polls here straight after signup, before
    // signUp() has produced one. A signed signup grant stands in for the
    // session. This used to accept a bare ?email= parameter instead, which
    // turned the endpoint into an unauthenticated profile-disclosure and
    // account-existence oracle (TC-02).
    if (!userId) {
      userId = verifySignupGrant(req.cookies.get(SIGNUP_GRANT_COOKIE)?.value)?.userId ?? null;
    }

    if (!userId) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const admin = getSupabaseAdmin();

    const { data: profile, error } = await admin
      .from("user_profiles")
      .select("id, email, phone, email_verified, phone_verified, license_status")
      .eq("id", userId)
      .single();

    if (error || !profile) {
      return NextResponse.json({ error: "Profile not found" }, { status: 404 });
    }

    // Self-heal: if the auth user is email-confirmed but our profile flag
    // never synced, fix it now so the caller sees the truth on this response.
    let emailVerified = profile.email_verified;
    if (!emailVerified && profile.id) {
      const synced = await syncEmailVerifiedIfConfirmed(profile.id);
      if (synced) emailVerified = true;
    }

    const canPay = emailVerified && profile.phone_verified;

    return NextResponse.json({
      email: profile.email,
      phone: profile.phone,
      email_verified: emailVerified,
      phone_verified: profile.phone_verified,
      license_status: profile.license_status,
      can_proceed_to_payment: canPay,
    });
  } catch (err) {
    console.error("Auth check error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
