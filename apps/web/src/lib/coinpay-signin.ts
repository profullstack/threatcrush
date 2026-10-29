import "server-only";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  authorizeUrl,
  pkce,
  randomToken,
  SIGN_IN_SCOPES,
} from "@profullstack/coinpay-onboard/oauth";

/**
 * "Sign in with CoinPay" (and "Connect CoinPay" from /account).
 *
 * STANDING rule: a CoinPay login binds to the CoinPay `sub` (coinpay_identities),
 * never to an existing account whose email matches. CoinPay's email is unverified
 * contact information only: it is never the account's auth email, never marked
 * verified, never grants anything. A new CoinPay login gets a new account whose
 * auth email is a placeholder under `.invalid` (RFC 2606: it can receive no mail,
 * so no one can ever prove it). Linking needs a signed-in session.
 */

export const COINPAY_STATE_COOKIE = "tc_coinpay_oauth";
export const COINPAY_STATE_PATH = "/api/v1/coinpay/oauth";
const STATE_MAX_AGE_SECONDS = 10 * 60;
export const CALLBACK_PATH = "/api/v1/coinpay/oauth/callback";
const PLACEHOLDER_DOMAIN = "coinpay.threatcrush.invalid";

export interface CoinpayConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  appUrl: string;
}

/** Read per request through non-literal keys: Next inlines process.env.NAME at build. */
export function coinpayConfig(env: Record<string, string | undefined> = process.env): CoinpayConfig | null {
  const clientId = env["COINPAY_OAUTH_CLIENT_ID"];
  const clientSecret = env["COINPAY_OAUTH_CLIENT_SECRET"];
  if (!clientId || !clientSecret) return null;
  const appUrl = (env["NEXT_PUBLIC_APP_URL"] || "https://threatcrush.com").replace(/\/$/, "");
  return { clientId, clientSecret, appUrl, redirectUri: `${appUrl}${CALLBACK_PATH}` };
}

export type PendingSignIn = {
  mode: "login" | "link";
  state: string;
  nonce: string;
  verifier: string;
  next: string;
  /** The signed-in user who started a link; null for a login. */
  userId: string | null;
  exp: number;
};

function mac(secret: string, payload: string): string {
  return createHmac("sha256", `threatcrush-coinpay-state:${secret}`).update(payload).digest("base64url");
}

/** The pending request as a tamper-proof cookie value (HMAC under the client secret). */
export function sealPending(pending: PendingSignIn, secret: string): string {
  const payload = Buffer.from(JSON.stringify(pending)).toString("base64url");
  return `${payload}.${mac(secret, payload)}`;
}

export function openPending(value: string | null | undefined, secret: string, now = Date.now()): PendingSignIn | null {
  if (!value || value.length > 4000) return null;
  const [payload, sig] = value.split(".");
  if (!payload || !sig) return null;
  const want = Buffer.from(mac(secret, payload));
  const got = Buffer.from(sig);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
  try {
    const pending = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as PendingSignIn;
    if (typeof pending.exp !== "number" || pending.exp < now) return null;
    if (pending.mode !== "login" && pending.mode !== "link") return null;
    if (pending.mode === "link" && !pending.userId) return null;
    return pending;
  } catch {
    return null;
  }
}

/** Starts a sign-in or link: the CoinPay authorize URL and the cookie that must come back with it. */
export function beginCoinpay(
  config: CoinpayConfig,
  input: { mode: "login" | "link"; next: string; userId?: string | null },
  now = Date.now(),
): { url: string; cookie: string } {
  const { verifier, challenge } = pkce();
  const pending: PendingSignIn = {
    mode: input.mode,
    state: randomToken(),
    nonce: randomToken(),
    verifier,
    next: input.next,
    userId: input.mode === "link" ? input.userId ?? null : null,
    exp: now + STATE_MAX_AGE_SECONDS * 1000,
  };
  const url = authorizeUrl({
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    state: pending.state,
    nonce: pending.nonce,
    challenge,
    scopes: SIGN_IN_SCOPES,
  });
  return { url, cookie: sealPending(pending, config.clientSecret) };
}

export const stateCookieOptions = (secure: boolean, maxAge = STATE_MAX_AGE_SECONDS) => ({
  httpOnly: true,
  // lax: the cookie must ride the top-level redirect back from coinpayportal.com.
  sameSite: "lax" as const,
  secure,
  path: COINPAY_STATE_PATH,
  maxAge,
});

/** The auth email of an account created by a CoinPay sign-in. Never a real address. */
export function placeholderEmail(): string {
  return `cp-${randomBytes(12).toString("hex")}@${PLACEHOLDER_DOMAIN}`;
}

export function isPlaceholderEmail(email: string | null | undefined): boolean {
  return typeof email === "string" && email.toLowerCase().endsWith(`@${PLACEHOLDER_DOMAIN}`);
}

export interface CoinpayIdentity {
  sub: string;
  user_id: string;
  email: string | null;
  name: string | null;
}

export async function identityBySub(admin: SupabaseClient, sub: string): Promise<CoinpayIdentity | null> {
  const { data } = await admin
    .from("coinpay_identities")
    .select("sub, user_id, email, name")
    .eq("sub", sub)
    .maybeSingle();
  return (data as CoinpayIdentity | null) ?? null;
}

export async function identityForUser(admin: SupabaseClient, userId: string): Promise<CoinpayIdentity | null> {
  const { data } = await admin
    .from("coinpay_identities")
    .select("sub, user_id, email, name")
    .eq("user_id", userId)
    .maybeSingle();
  return (data as CoinpayIdentity | null) ?? null;
}

export type LinkOutcome = "linked" | "already_linked" | "sub_taken" | "user_has_other";

/** Binds `sub` to the signed-in `userId`. Never moves a sub from one account to another. */
export async function linkIdentity(
  admin: SupabaseClient,
  userId: string,
  who: { sub: string; email: string | null; name: string | null },
): Promise<LinkOutcome> {
  const bySub = await identityBySub(admin, who.sub);
  if (bySub) return bySub.user_id === userId ? "already_linked" : "sub_taken";
  const mine = await identityForUser(admin, userId);
  if (mine) return "user_has_other";
  const { error } = await admin.from("coinpay_identities").insert({
    sub: who.sub,
    user_id: userId,
    email: who.email,
    name: who.name,
  });
  if (error) return "sub_taken";
  return "linked";
}

/**
 * The account for a CoinPay login: the one bound to `sub`, else a brand-new one.
 * Never looks at the email to find an account.
 */
export async function accountForCoinpayLogin(
  admin: SupabaseClient,
  who: { sub: string; email: string | null; name: string | null },
  createProfile: (userId: string, authEmail: string, displayName: string | null) => Promise<void>,
): Promise<{ userId: string; authEmail: string; created: boolean } | null> {
  const existing = await identityBySub(admin, who.sub);
  if (existing) {
    const { data } = await admin.auth.admin.getUserById(existing.user_id);
    const authEmail = data?.user?.email;
    if (!authEmail) return null;
    await admin
      .from("coinpay_identities")
      .update({ email: who.email, name: who.name, last_login_at: new Date().toISOString() })
      .eq("sub", who.sub);
    return { userId: existing.user_id, authEmail, created: false };
  }

  const authEmail = placeholderEmail();
  const { data, error } = await admin.auth.admin.createUser({
    email: authEmail,
    email_confirm: true,
    app_metadata: { coinpay_signup: true },
  });
  const userId = data?.user?.id;
  if (error || !userId) return null;

  const { error: bindError } = await admin.from("coinpay_identities").insert({
    sub: who.sub,
    user_id: userId,
    email: who.email,
    name: who.name,
    last_login_at: new Date().toISOString(),
  });
  if (bindError) {
    // Lost a race with another first login for the same sub: use theirs.
    await admin.auth.admin.deleteUser(userId);
    const winner = await identityBySub(admin, who.sub);
    if (!winner) return null;
    const { data: w } = await admin.auth.admin.getUserById(winner.user_id);
    return w?.user?.email ? { userId: winner.user_id, authEmail: w.user.email, created: false } : null;
  }
  await createProfile(userId, authEmail, who.name);
  return { userId, authEmail, created: true };
}
