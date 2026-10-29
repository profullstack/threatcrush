import { randomInt } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { finishSignIn, sameState } from "@profullstack/coinpay-onboard/oauth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { mintSession } from "@/lib/cli-login";
import { clearInviteCookie, inviteCookie, onSignedIn } from "@/lib/credit-codes";
import {
  accountForCoinpayLogin,
  COINPAY_STATE_COOKIE,
  coinpayConfig,
  linkIdentity,
  openPending,
  stateCookieOptions,
} from "@/lib/coinpay-signin";

export const dynamic = "force-dynamic";

function referralCode(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let code = "";
  for (let i = 0; i < 8; i++) code += chars[randomInt(0, chars.length)];
  return code;
}

/**
 * GET /api/v1/coinpay/oauth/callback — CoinPay sends the browser back here.
 * The state must match the signed cookie this browser got at the start; the
 * id_token's nonce, issuer, audience and expiry are checked; the account is
 * found by CoinPay sub only (see lib/coinpay-signin.ts).
 */
export async function GET(request: NextRequest) {
  const config = coinpayConfig();
  const appUrl = config?.appUrl ?? (process.env["NEXT_PUBLIC_APP_URL"] || "https://threatcrush.com");
  const secure = appUrl.startsWith("https:");
  const done = (path: string) => {
    const response = NextResponse.redirect(`${appUrl}${path}`, 302);
    response.cookies.set(COINPAY_STATE_COOKIE, "", stateCookieOptions(secure, 0));
    return response;
  };
  if (!config) return done("/auth/login?error=coinpay_unavailable");

  const params = request.nextUrl.searchParams;
  const pending = openPending(request.cookies.get(COINPAY_STATE_COOKIE)?.value, config.clientSecret);
  if (!pending || !sameState(pending.state, params.get("state"))) {
    return done("/auth/login?error=coinpay_state");
  }
  const back = pending.mode === "link" ? "/account?coinpay=" : "/auth/login?error=coinpay_";
  if (params.get("error")) return done(`${back}denied`);
  const code = params.get("code");
  if (!code) return done(`${back}failed`);

  let who: { sub: string; email: string | null; name: string | null };
  try {
    const result = await finishSignIn({
      code,
      verifier: pending.verifier,
      nonce: pending.nonce,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
    });
    who = { sub: result.sub, email: result.email, name: result.name };
  } catch (err) {
    console.error("[coinpay] sign-in failed:", (err as Error).message);
    return done(`${back}failed`);
  }

  const admin = getSupabaseAdmin();

  if (pending.mode === "link") {
    const outcome = await linkIdentity(admin, pending.userId as string, who);
    return done(`/account?coinpay=${outcome}`);
  }

  const account = await accountForCoinpayLogin(admin, who, async (userId, authEmail, displayName) => {
    await admin.from("user_profiles").insert({
      id: userId,
      email: authEmail,
      display_name: displayName,
      email_verified: false,
      referral_code: referralCode(),
    });
  });
  if (!account) return done("/auth/login?error=coinpay_failed");

  const minted = await mintSession(admin, account.authEmail);
  if (!minted) return done("/auth/login?error=coinpay_failed");
  await onSignedIn(account.userId, inviteCookie(request));

  const hash = new URLSearchParams({
    access_token: minted.session.access_token,
    refresh_token: minted.session.refresh_token,
    type: "oauth",
  });
  const response = done(`${pending.next}#${hash.toString()}`);
  clearInviteCookie(request, response);
  return response;
}
