import "server-only";
import { createHash, randomInt } from "node:crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { sendTelnyxSms } from "@/lib/telnyx";
import { verifySignupGrant } from "@/lib/signup-grant";

export const CODE_TTL_SECONDS = 10 * 60;
export const RESEND_COOLDOWN_SECONDS = 30;

/**
 * Ceilings on SMS sent to one number, across every account and every send
 * path. A real person verifying a phone needs one code, maybe a resend or two
 * after a typo, so 3 an hour never gets in their way; 10 a day bounds what a
 * single number can cost us to a few cents even when an attacker cycles fresh
 * signups against it.
 */
export const SMS_SENDS_PER_HOUR = 3;
export const SMS_SENDS_PER_DAY = 10;

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

type StatusError = Error & { status?: number; retryAfterSeconds?: number };

/**
 * Record one SMS to `phone` (already normalized) against its hourly and daily
 * ceilings, or throw a 429 error without recording anything when either is
 * reached. Call it immediately before handing a message to Telnyx.
 *
 * The row is inserted first and the count taken afterwards, including it. Of
 * any set of concurrent reservations only those that saw at most the limit go
 * ahead, so parallel requests cannot all pass a count none of them had written
 * to yet. A refused reservation deletes its row so that retries against a
 * capped number do not keep pushing the window forward.
 */
export async function reservePhoneSmsSend(phone: string, userId: string | null): Promise<void> {
  const admin = getSupabaseAdmin();
  const now = Date.now();
  const dayAgo = new Date(now - DAY_MS).toISOString();

  // Nothing older than the widest window counts toward anything.
  await admin.from("phone_sms_sends").delete().eq("phone", phone).lt("created_at", dayAgo);

  const { data: reservation, error: insertError } = await admin
    .from("phone_sms_sends")
    .insert({ phone, user_id: userId, created_at: new Date(now).toISOString() })
    .select("id")
    .single();
  if (insertError || !reservation) {
    // Fail closed: an SMS we cannot count is an SMS we do not send.
    console.error("[phone-verification] send log insert failed:", insertError);
    throw new Error("Could not send SMS");
  }

  const { data: recent, error: selectError } = await admin
    .from("phone_sms_sends")
    .select("id, created_at")
    .eq("phone", phone)
    .gt("created_at", dayAgo)
    .order("created_at", { ascending: true });
  if (selectError || !recent) {
    console.error("[phone-verification] send log read failed:", selectError);
    await admin.from("phone_sms_sends").delete().eq("id", reservation.id);
    throw new Error("Could not send SMS");
  }

  const others = (recent as { id: string; created_at: string }[]).filter(
    (row) => row.id !== reservation.id,
  );
  const lastHour = others.filter((row) => Date.parse(row.created_at) > now - HOUR_MS);
  // With `rows` sorted oldest first and at least `limit` of them, the send that
  // has to age out before another fits is rows[rows.length - limit].
  const waitMs = Math.max(
    lastHour.length < SMS_SENDS_PER_HOUR
      ? 0
      : Date.parse(lastHour[lastHour.length - SMS_SENDS_PER_HOUR].created_at) + HOUR_MS - now,
    others.length < SMS_SENDS_PER_DAY
      ? 0
      : Date.parse(others[others.length - SMS_SENDS_PER_DAY].created_at) + DAY_MS - now,
  );
  if (waitMs <= 0) return;

  await admin.from("phone_sms_sends").delete().eq("id", reservation.id);
  const minutes = Math.max(1, Math.ceil(waitMs / 60_000));
  const err: StatusError = new Error(
    `Too many verification codes have been sent to this number. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
  );
  err.status = 429;
  err.retryAfterSeconds = Math.ceil(waitMs / 1000);
  throw err;
}

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
  /**
   * When true, ignores the per-account resend cooldown — used at signup time.
   * The per-number ceiling (reservePhoneSmsSend) applies regardless.
   */
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

  await reservePhoneSmsSend(phone, opts.userId);

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
