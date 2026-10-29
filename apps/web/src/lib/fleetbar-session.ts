import "server-only";
import type { NextResponse } from "next/server";
import { getSupabaseAdmin, getSupabaseClient } from "@/lib/supabase";

/**
 * The <fleet-bar> panel (@profullstack/fleetbar) calls /api/fleetbar with
 * `credentials: "same-origin"` and no Authorization header, but a ThreatCrush
 * session is a bearer token in localStorage. /fleet bridges the two: it hands
 * the token to POST /api/fleet-session, which mirrors it into this httpOnly
 * cookie scoped to /api/fleetbar only, so the panel's requests carry it and
 * nothing else on the site ever sees it.
 */
export const FLEETBAR_COOKIE = "tc_fleetbar";
export const FLEETBAR_COOKIE_PATH = "/api/fleetbar";
/** Supabase access tokens live an hour; the cookie never outlives that. */
export const FLEETBAR_COOKIE_MAX_AGE = 60 * 60;

/** Expires the /fleet cookie on a response (sign-out). */
export function clearFleetbarCookie(res: NextResponse): NextResponse {
  res.cookies.set(FLEETBAR_COOKIE, "", { path: FLEETBAR_COOKIE_PATH, maxAge: 0 });
  return res;
}

export interface FleetbarUser {
  email: string;
  emailVerified: boolean;
}

function bearer(request: Request): string | null {
  const header = request.headers.get("authorization");
  const token = header?.replace(/^Bearer\s+/i, "").trim();
  return token || null;
}

function cookieValue(request: Request, name: string): string | null {
  const raw = request.headers.get("cookie");
  if (!raw) return null;
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const value = part.slice(eq + 1).trim();
    try {
      return decodeURIComponent(value) || null;
    } catch {
      return null;
    }
  }
  return null;
}

/** The access token behind this request: a Bearer header first, else the /fleet cookie. */
export function fleetbarToken(request: Request): string | null {
  return bearer(request) ?? cookieValue(request, FLEETBAR_COOKIE);
}

/**
 * The signed-in user for the fleetbar handler, or null. `emailVerified` is
 * true only when ThreatCrush has verified the address: the profile's
 * email_verified flag, or GoTrue's email_confirmed_at (the two can drift; see
 * lib/auth-sync.ts). crawlproof trusts this email, so never loosen it.
 */
export async function getFleetbarUser(request: Request): Promise<FleetbarUser | null> {
  const token = fleetbarToken(request);
  if (!token) return null;

  const { data, error } = await getSupabaseClient().auth.getUser(token);
  const user = data?.user;
  if (error || !user?.email) return null;

  const { data: profile } = await getSupabaseAdmin()
    .from("user_profiles")
    .select("email_verified")
    .eq("id", user.id)
    .maybeSingle();

  const verified = profile?.email_verified === true || Boolean(user.email_confirmed_at);
  return { email: user.email, emailVerified: verified };
}
