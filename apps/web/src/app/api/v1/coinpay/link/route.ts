import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  beginCoinpay,
  COINPAY_STATE_COOKIE,
  coinpayConfig,
  identityForUser,
  isPlaceholderEmail,
  stateCookieOptions,
} from "@/lib/coinpay-signin";

export const dynamic = "force-dynamic";

/** GET: is CoinPay connected to the signed-in account? */
export async function GET(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();
  const identity = await identityForUser(getSupabaseAdmin(), user.userId);
  return NextResponse.json({
    enabled: Boolean(coinpayConfig()),
    linked: Boolean(identity),
    // CoinPay's address, shown as-is: unverified contact information.
    email: identity?.email ?? null,
    name: identity?.name ?? null,
    // An account CoinPay created has no other way in.
    canDisconnect: Boolean(identity) && !isPlaceholderEmail(user.email),
  });
}

/**
 * POST: "Connect CoinPay" for the signed-in account (Bearer). Returns the CoinPay
 * URL to open; the signed cookie binds the request to this account, so the
 * callback links CoinPay only to the user who started it.
 */
export async function POST(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();
  const config = coinpayConfig();
  if (!config) return NextResponse.json({ error: "Sign in with CoinPay is not configured" }, { status: 404 });
  if (await identityForUser(getSupabaseAdmin(), user.userId)) {
    return NextResponse.json({ error: "CoinPay is already connected" }, { status: 409 });
  }
  const { url, cookie } = beginCoinpay(config, { mode: "link", next: "/account", userId: user.userId });
  const response = NextResponse.json({ url });
  response.cookies.set(COINPAY_STATE_COOKIE, cookie, stateCookieOptions(config.appUrl.startsWith("https:")));
  return response;
}

/** DELETE: disconnect, refused when CoinPay is the only way into the account. */
export async function DELETE(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();
  if (isPlaceholderEmail(user.email)) {
    return NextResponse.json(
      { error: "CoinPay is the only way into this account, so it cannot be disconnected." },
      { status: 409 },
    );
  }
  const { error } = await getSupabaseAdmin().from("coinpay_identities").delete().eq("user_id", user.userId);
  if (error) return NextResponse.json({ error: "Could not disconnect CoinPay" }, { status: 500 });
  return NextResponse.json({ ok: true });
}
