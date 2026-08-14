import { NextRequest, NextResponse } from "next/server";
import { createHmac, timingSafeEqual } from "node:crypto";

const TELNYX_API_KEY = process.env.TELNYX_API_KEY!;
const TELNYX_PHONE_NUMBER = process.env.TELNYX_PHONE_NUMBER!;

/**
 * TC-06: this endpoint took any {user:{phone},sms:{otp}} body and forwarded it
 * to Telnyx with no authentication and no rate limit, so anyone could bill the
 * operator for SMS to arbitrary numbers.
 *
 * Supabase signs auth-hook requests with the standard webhook scheme:
 * `webhook-signature: v1,<base64 hmac>` over `<id>.<timestamp>.<body>`, keyed
 * by the hook secret (`v1,whsec_<base64>`).
 */
function verifyHookSignature(request: NextRequest, rawBody: string): boolean {
  const secret = process.env.SUPABASE_SMS_HOOK_SECRET;
  if (!secret) {
    // Fail closed. An unauthenticated SMS sender is worse than a broken one.
    console.error("[Telnyx SMS] SUPABASE_SMS_HOOK_SECRET is not set — rejecting hook call");
    return false;
  }

  const id = request.headers.get("webhook-id");
  const timestamp = request.headers.get("webhook-timestamp");
  const signatureHeader = request.headers.get("webhook-signature");
  if (!id || !timestamp || !signatureHeader) return false;

  // Reject replays of an old signed request.
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > 300) return false;

  const key = Buffer.from(secret.replace(/^v1,whsec_/, "").replace(/^whsec_/, ""), "base64");
  const expected = createHmac("sha256", key)
    .update(`${id}.${timestamp}.${rawBody}`)
    .digest("base64");

  // The header may carry several space-separated versioned signatures.
  return signatureHeader.split(" ").some((part) => {
    const value = part.startsWith("v1,") ? part.slice(3) : part;
    const a = Buffer.from(value);
    const b = Buffer.from(expected);
    return a.length === b.length && timingSafeEqual(a, b);
  });
}

/**
 * Supabase Send SMS Hook
 * Called by Supabase Auth when it needs to send an OTP via SMS.
 * We forward the message to Telnyx instead of using a built-in provider.
 *
 * Supabase sends: { user: { phone: string }, sms: { otp: string } }
 * We must return: { success: true } or { error: { message: string } }
 */
export async function POST(request: NextRequest) {
  try {
    // Read the raw body: the signature covers the exact bytes sent.
    const rawBody = await request.text();

    if (!verifyHookSignature(request, rawBody)) {
      return NextResponse.json(
        { error: { message: "Invalid hook signature" } },
        { status: 401 },
      );
    }

    let body: { user?: { phone?: string }; sms?: { otp?: string } };
    try {
      body = JSON.parse(rawBody);
    } catch {
      return NextResponse.json(
        { error: { message: "Invalid JSON" } },
        { status: 400 },
      );
    }

    const phone = body.user?.phone;
    const otp = body.sms?.otp;

    if (!phone || !otp) {
      return NextResponse.json(
        { error: { message: "Missing phone or OTP" } },
        { status: 400 },
      );
    }

    const message = `Your ThreatCrush verification code is: ${otp}`;

    const res = await fetch("https://api.telnyx.com/v2/messages", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TELNYX_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: TELNYX_PHONE_NUMBER,
        to: phone,
        text: message,
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      console.error("[Telnyx SMS] Failed:", res.status, err);
      return NextResponse.json(
        { error: { message: `SMS delivery failed: ${res.status}` } },
        { status: 500 },
      );
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("[Telnyx SMS] Error:", err);
    return NextResponse.json(
      { error: { message: "SMS hook error" } },
      { status: 500 },
    );
  }
}
