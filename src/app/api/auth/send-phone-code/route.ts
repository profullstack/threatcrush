import { NextRequest, NextResponse } from "next/server";
import { createHash, randomInt } from "node:crypto";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";
import { sendTelnyxSms } from "@/lib/telnyx";

const CODE_TTL_SECONDS = 10 * 60; // 10 minutes
const RESEND_COOLDOWN_SECONDS = 30;

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function normalizePhone(raw: string): string {
  const digits = raw.replace(/[^\d+]/g, "");
  if (digits.startsWith("+")) return digits;
  if (digits.length === 10) return `+1${digits}`;
  return `+${digits}`;
}

export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get("authorization")?.replace("Bearer ", "");
    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const anon = getSupabaseClient();
    const { data: { user } } = await anon.auth.getUser(token);
    if (!user?.id) {
      return NextResponse.json({ error: "Invalid session" }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    const rawPhone: string | undefined = body.phone;
    if (!rawPhone) {
      return NextResponse.json({ error: "Phone is required" }, { status: 400 });
    }
    const phone = normalizePhone(rawPhone);
    if (!/^\+\d{10,15}$/.test(phone)) {
      return NextResponse.json({ error: "Invalid phone number format" }, { status: 400 });
    }

    const admin = getSupabaseAdmin();

    // Cooldown: reject if we sent a code to this user in the last 30s.
    const cutoff = new Date(Date.now() - RESEND_COOLDOWN_SECONDS * 1000).toISOString();
    const { data: recent } = await admin
      .from("phone_verification_codes")
      .select("created_at")
      .eq("user_id", user.id)
      .gt("created_at", cutoff)
      .limit(1)
      .maybeSingle();

    if (recent) {
      return NextResponse.json(
        { error: `Please wait ${RESEND_COOLDOWN_SECONDS}s before requesting another code` },
        { status: 429 },
      );
    }

    // Generate a uniformly-distributed 6-digit code.
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    const expiresAt = new Date(Date.now() + CODE_TTL_SECONDS * 1000).toISOString();

    // Invalidate any outstanding codes for this user and insert the new one.
    await admin.from("phone_verification_codes").delete().eq("user_id", user.id);
    const { error: insertError } = await admin.from("phone_verification_codes").insert({
      user_id: user.id,
      phone,
      code_hash: sha256(code),
      expires_at: expiresAt,
    });

    if (insertError) {
      console.error("phone_verification_codes insert failed:", insertError);
      return NextResponse.json({ error: "Could not store verification code" }, { status: 500 });
    }

    try {
      await sendTelnyxSms(
        phone,
        `Your ThreatCrush verification code is ${code}. It expires in 10 minutes.`,
      );
    } catch (err) {
      console.error("Telnyx send failed:", err);
      // Best-effort cleanup so we don't leave an unsent code dangling.
      await admin.from("phone_verification_codes").delete().eq("user_id", user.id);
      return NextResponse.json(
        { error: "Could not send SMS. Please try again in a moment." },
        { status: 502 },
      );
    }

    return NextResponse.json({ ok: true, expires_in: CODE_TTL_SECONDS });
  } catch (err) {
    console.error("send-phone-code error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
