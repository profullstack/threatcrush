import { NextRequest, NextResponse } from "next/server";

const TELNYX_API_KEY = process.env.TELNYX_API_KEY!;
const TELNYX_PHONE_NUMBER = process.env.TELNYX_PHONE_NUMBER!;

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
    const body = await request.json();
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
