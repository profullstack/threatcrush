import { NextRequest, NextResponse } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { getSupabaseClient, updatePasswordWithAccessToken } from "@/lib/supabase";
import { passwordPolicyError } from "@/lib/password-policy";

const LINK_EXPIRED = "This password reset link is invalid or has expired. Request a new one.";

// POST /api/auth/reset-password — set a new password from a recovery link.
//
// The recovery email lands the user back here with a short-lived GoTrue
// session in the URL hash; the reset page sends that access token as the
// Bearer. Nothing handled that session before, so a reset link just signed the
// user in and the password could never actually be changed.
export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
    if (!token) return unauthorized(LINK_EXPIRED);

    let password: unknown;
    let confirmPassword: unknown;
    try {
      const body: unknown = await req.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      password = "password" in body ? body.password : undefined;
      confirmPassword = "confirm_password" in body ? body.confirm_password : undefined;
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    if (typeof password !== "string" || typeof confirmPassword !== "string") {
      return NextResponse.json(
        { error: "password and confirm_password are required" },
        { status: 400 },
      );
    }
    if (password !== confirmPassword) {
      return NextResponse.json({ error: "Passwords do not match." }, { status: 400 });
    }
    const policyError = passwordPolicyError(password);
    if (policyError) {
      return NextResponse.json({ error: policyError }, { status: 400 });
    }

    const { error } = await updatePasswordWithAccessToken(token, password);
    if (error) {
      // 401/403: bad, expired or already-used token (its session is gone).
      if (error.status === 401 || error.status === 403) return unauthorized(LINK_EXPIRED);
      // 400/422: GoTrue's own password policy, e.g. "same_password".
      if (error.status === 400 || error.status === 422) {
        return NextResponse.json({ error: error.message }, { status: 400 });
      }
      console.error("Reset password: GoTrue update-user failed", error.status, error.code);
      return NextResponse.json({ error: "Could not update password" }, { status: 502 });
    }

    // End every session the user has, including this recovery one, so the
    // link cannot be replayed and anyone holding an old session is signed out.
    // The password is already changed, so a failure here is not the user's.
    try {
      await getSupabaseClient().auth.admin.signOut(token, "global");
    } catch {
      // ignore
    }

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("Reset password error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
