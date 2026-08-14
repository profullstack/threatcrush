import "server-only";
import { createHmac, timingSafeEqual } from "node:crypto";
import type { NextResponse } from "next/server";

/**
 * TC-02 / TC-05: the signup and phone-verification routes used to accept a bare
 * `email` parameter as proof of identity, because signUp() with email
 * confirmation returns no session and the verify page has no Bearer token.
 * That let anyone read a stranger's profile or point their phone number at a
 * stranger's account just by knowing the address.
 *
 * A signup grant replaces the bare email: a short-lived HMAC-signed token,
 * issued only to someone who just proved they control the account (completed
 * signup, or supplied the right password), and carried in an HttpOnly cookie so
 * page JavaScript — and any attacker — cannot mint or read one.
 */

export const SIGNUP_GRANT_COOKIE = "tc_signup_grant";

/** Long enough to survive "check your email, come back after lunch". */
export const SIGNUP_GRANT_TTL_SECONDS = 24 * 60 * 60;

export interface SignupGrant {
  userId: string;
  email: string;
}

function signingKey(): Buffer {
  // A dedicated secret is preferred, but the service role key is always present
  // server-side, so derive from it rather than failing closed on a fresh deploy.
  const secret = process.env.SIGNUP_GRANT_SECRET || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!secret) {
    throw new Error(
      "[signup-grant] Set SIGNUP_GRANT_SECRET or SUPABASE_SERVICE_ROLE_KEY to sign signup grants.",
    );
  }
  return createHmac("sha256", secret).update("threatcrush.signup-grant.v1").digest();
}

function sign(payload: string): string {
  return createHmac("sha256", signingKey()).update(payload).digest("base64url");
}

export function issueSignupGrant(grant: SignupGrant): string {
  const payload = Buffer.from(
    JSON.stringify({
      uid: grant.userId,
      email: grant.email.toLowerCase().trim(),
      exp: Math.floor(Date.now() / 1000) + SIGNUP_GRANT_TTL_SECONDS,
    }),
  ).toString("base64url");
  return `v1.${payload}.${sign(payload)}`;
}

export function verifySignupGrant(token: string | undefined | null): SignupGrant | null {
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const [, payload, signature] = parts;

  const expected = Buffer.from(sign(payload));
  const actual = Buffer.from(signature);
  // timingSafeEqual throws on a length mismatch, so check that first.
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;

  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf-8")) as {
      uid?: unknown;
      email?: unknown;
      exp?: unknown;
    };
    if (typeof claims.uid !== "string" || typeof claims.email !== "string") return null;
    if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now()) return null;
    return { userId: claims.uid, email: claims.email };
  } catch {
    return null;
  }
}

export function setSignupGrantCookie(res: NextResponse, grant: SignupGrant): NextResponse {
  res.cookies.set(SIGNUP_GRANT_COOKIE, issueSignupGrant(grant), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SIGNUP_GRANT_TTL_SECONDS,
  });
  return res;
}

export function clearSignupGrantCookie(res: NextResponse): NextResponse {
  res.cookies.set(SIGNUP_GRANT_COOKIE, "", { path: "/", maxAge: 0 });
  return res;
}
