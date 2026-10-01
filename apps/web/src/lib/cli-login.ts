import "server-only";
import { createHash, randomInt, timingSafeEqual } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createSupabaseAuthClient } from "@/lib/supabase";

/**
 * `threatcrush login` by link: the CLI starts a request bound to a PKCE
 * challenge, the operator approves it in a signed-in browser, and the CLI
 * redeems it with the verifier. See supabase/migrations/*_cli_login_and_server_config.sql.
 */

/** How often the CLI should poll /api/auth/cli/token, in seconds. */
export const POLL_INTERVAL_SECONDS = 3;

const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
// RFC 7636: 43–128 characters from the unreserved set.
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// No 0/O, 1/I/L, 5/S, 2/Z: the code is read off one screen and checked on another.
const CODE_ALPHABET = "ABCDEFGHJKMNPQRTUVWXY346789";

export function isValidChallenge(value: unknown): value is string {
  return typeof value === "string" && CHALLENGE.test(value);
}

export function isValidVerifier(value: unknown): value is string {
  return typeof value === "string" && VERIFIER.test(value);
}

export function isRequestId(value: unknown): value is string {
  return typeof value === "string" && UUID.test(value);
}

/** base64url(SHA-256(verifier)), the S256 transform. */
export function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/** Does `verifier` hash to `challenge`? Constant-time. */
export function verifierMatches(verifier: string, challenge: string): boolean {
  const a = Buffer.from(s256(verifier));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** `ABCD-EFGH`. */
export function generateUserCode(): string {
  let code = "";
  for (let i = 0; i < 8; i++) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

/** A hostname-ish label for the approval page; never trusted for anything else. */
export function cleanDeviceName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value.replace(/[^\w.@ -]/g, "").trim().slice(0, 100);
  return cleaned || null;
}

export function isExpired(expiresAt: string, now = Date.now()): boolean {
  return Date.parse(expiresAt) <= now;
}

export interface MintedSession {
  user: { id: string; email?: string };
  session: { access_token: string; refresh_token: string; expires_at?: number };
}

/**
 * A fresh session for `email`, without a password and without sending mail.
 *
 * `generateLink` makes a magic-link token server-side (it emails nothing);
 * redeeming its hash with `verifyOtp` signs that user in. Each call is a new
 * session with its own refresh token, which is the point: machines must not
 * share one.
 */
export async function mintSession(
  admin: SupabaseClient,
  email: string,
): Promise<MintedSession | null> {
  const { data: link, error: linkError } = await admin.auth.admin.generateLink({
    type: "magiclink",
    email,
  });
  const tokenHash = link?.properties?.hashed_token;
  if (linkError || !tokenHash) return null;

  const { data, error } = await createSupabaseAuthClient().auth.verifyOtp({
    type: "magiclink",
    token_hash: tokenHash,
  });
  if (error || !data.session || !data.user) return null;

  return {
    user: { id: data.user.id, email: data.user.email },
    session: {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at,
    },
  };
}
