import { NextRequest, NextResponse } from "next/server";
import { safeRedirectPath } from "@/lib/safe-redirect";
import {
  beginCoinpay,
  COINPAY_STATE_COOKIE,
  coinpayConfig,
  stateCookieOptions,
} from "@/lib/coinpay-signin";

export const dynamic = "force-dynamic";

/**
 * GET /api/v1/coinpay/oauth/start?next=/path — "Sign in with CoinPay".
 * Sends the browser to CoinPay (auth code + PKCE S256 + state + nonce); the
 * pending request rides back in a signed httpOnly cookie.
 */
export async function GET(request: NextRequest) {
  const config = coinpayConfig();
  if (!config) {
    return NextResponse.json({ error: "Sign in with CoinPay is not configured" }, { status: 404 });
  }
  // The session rides back in the URL hash, so the path must not carry one.
  const next = safeRedirectPath(request.nextUrl.searchParams.get("next")).split("#")[0] || "/account";
  const { url, cookie } = beginCoinpay(config, { mode: "login", next });
  const response = NextResponse.redirect(url, 302);
  response.cookies.set(COINPAY_STATE_COOKIE, cookie, stateCookieOptions(config.appUrl.startsWith("https:")));
  return response;
}
