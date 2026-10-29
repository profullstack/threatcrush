import { NextResponse } from "next/server";
import {
  FLEETBAR_COOKIE,
  FLEETBAR_COOKIE_MAX_AGE,
  FLEETBAR_COOKIE_PATH,
} from "@/lib/fleetbar-session";
import { getSupabaseClient } from "@/lib/supabase";

export const dynamic = "force-dynamic";

function setCookie(res: NextResponse, value: string, maxAge: number) {
  res.cookies.set(FLEETBAR_COOKIE, value, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: FLEETBAR_COOKIE_PATH,
    maxAge,
  });
  return res;
}

/** Seconds until this JWT expires, capped at the cookie's max age; 0 when unreadable. */
function secondsLeft(token: string): number {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    const exp = typeof payload.exp === "number" ? payload.exp : 0;
    return Math.max(0, Math.min(FLEETBAR_COOKIE_MAX_AGE, exp - Math.floor(Date.now() / 1000)));
  } catch {
    return 0;
  }
}

/**
 * /fleet calls this with the session's Bearer token; it becomes an httpOnly
 * cookie sent only to /api/fleetbar, which is how the <fleet-bar> panel's
 * same-origin requests carry the session. Only a Bearer header is accepted
 * here, never the cookie itself, so it cannot extend its own life.
 */
export async function POST(request: Request) {
  const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "").trim();
  if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

  const { data, error } = await getSupabaseClient().auth.getUser(token);
  if (error || !data?.user) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

  const maxAge = secondsLeft(token) || FLEETBAR_COOKIE_MAX_AGE;
  return setCookie(NextResponse.json({ ok: true }), token, maxAge);
}

/** Drops the cookie (sign-out). */
export async function DELETE() {
  return setCookie(NextResponse.json({ ok: true }), "", 0);
}
