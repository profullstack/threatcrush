import "server-only";
import { createHash, randomInt } from "node:crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { sendTelnyxSms } from "@/lib/telnyx";
import { verifySignupGrant } from "@/lib/signup-grant";

export const CODE_TTL_SECONDS = 10 * 60;
export const RESEND_COOLDOWN_SECONDS = 30;

export function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function normalizePhone(raw: string): string {
  const digits = raw.replace(/[^\d+]/g, "");
  if (digits.startsWith("+")) return digits;
  if (digits.length === 10) return `+1${digits}`;
  return `+${digits}`;
}

/**
 * Issue a fresh phone verification code for a user, persist its hash,
 * and send it via Telnyx. Throws on failure (caller decides whether
 * to surface the error or swallow it for best-effort flows like signup).
 */
export async function issuePhoneCode(opts: {
  userId: string;
  phone: string;
  /** When true, ignores the resend cooldown — used at signup time. */
  bypassCooldown?: boolean;
}): Promise<{ phone: string }> {
  const phone = normalizePhone(opts.phone);
  if (!/^\+\d{10,15}$/.test(phone)) {
    throw new Error("Invalid phone number format");
  }

  const admin = getSupabaseAdmin();

  if (!opts.bypassCooldown) {
    const cutoff = new Date(Date.now() - RESEND_COOLDOWN_SECONDS * 1000).toISOString();
    const { data: recent } = await admin
      .from("phone_verification_codes")
      .select("created_at")
      .eq("user_id", opts.userId)
      .gt("created_at", cutoff)
      .limit(1)
      .maybeSingle();
    if (recent) {
      const err = new Error(
        `Please wait ${RESEND_COOLDOWN_SECONDS}s before requesting another code`,
      );
      (err as Error & { status?: number }).status = 429;
      throw err;
    }
  }

  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  const expiresAt = new Date(Date.now() + CODE_TTL_SECONDS * 1000).toISOString();

  await admin.from("phone_verification_codes").delete().eq("user_id", opts.userId);
  const { error: insertError } = await admin.from("phone_verification_codes").insert({
    user_id: opts.userId,
    phone,
    code_hash: sha256(code),
    expires_at: expiresAt,
  });
  if (insertError) {
    console.error("[phone-verification] insert failed:", insertError);
    throw new Error("Could not store verification code");
  }

  try {
    await sendTelnyxSms(
      phone,
      `Your ThreatCrush verification code is ${code}. It expires in 10 minutes.`,
    );
  } catch (err) {
    console.error("[phone-verification] Telnyx send failed:", err);
    await admin.from("phone_verification_codes").delete().eq("user_id", opts.userId);
    throw new Error("Could not send SMS");
  }

  return { phone };
}

/**
 * Resolve a user_id from a Supabase auth Bearer token or, when the signup flow
 * has not produced a session yet, from a signed signup grant cookie.
 *
 * This used to fall back to a bare `email` parameter, which meant anyone who
 * knew an address could drive the phone-verification flow for that account
 * (TC-05). The grant carries the user id itself and is signed, so it cannot be
 * forged or pointed at another account.
 */
export async function resolveUserId(opts: {
  bearerToken?: string | null;
  grantToken?: string | null;
}): Promise<string | null> {
  const admin = getSupabaseAdmin();

  if (opts.bearerToken) {
    const { data: { user } } = await admin.auth.getUser(opts.bearerToken);
    if (user?.id) return user.id;
  }

  const grant = verifySignupGrant(opts.grantToken);
  if (grant) return grant.userId;

  return null;
}
