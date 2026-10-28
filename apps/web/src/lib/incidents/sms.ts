import "server-only";
import { isTelnyxConfigured, sendTelnyxSms } from "@/lib/telnyx";

export type SmsOutcome = { ok: true; provider: "smshub" | "telnyx" } | { ok: false; error: string };

const TIMEOUT_MS = 10_000;

/**
 * One incident text. smshub first (SMSHUB_API_KEY: POST /api/v1/messages/send
 * from the account's own number), then Telnyx directly (TELNYX_API_KEY +
 * TELNYX_PHONE_NUMBER, the verification-code sender) when smshub is not set up
 * or fails. Never throws.
 */
export async function sendIncidentSms(to: string, message: string, env: NodeJS.ProcessEnv = process.env): Promise<SmsOutcome> {
  const errors: string[] = [];
  const key = env.SMSHUB_API_KEY?.trim();
  if (key) {
    const base = (env.SMSHUB_URL?.trim() || "https://smshub.dev").replace(/\/$/, "");
    try {
      const res = await fetch(`${base}/api/v1/messages/send`, {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "User-Agent": "ThreatCrush-Incidents/1" },
        body: JSON.stringify({ to, message }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (res.ok) return { ok: true, provider: "smshub" };
      const text = await res.text().catch(() => "");
      errors.push(`smshub HTTP ${res.status}${text ? `: ${text.slice(0, 160)}` : ""}`);
    } catch (err) {
      errors.push(`smshub: ${(err as Error).message}`);
    }
  } else {
    errors.push("smshub not configured");
  }
  if (isTelnyxConfigured()) {
    try {
      await sendTelnyxSms(to, message);
      return { ok: true, provider: "telnyx" };
    } catch (err) {
      errors.push(`telnyx: ${(err as Error).message.slice(0, 200)}`);
    }
  } else {
    errors.push("telnyx not configured");
  }
  return { ok: false, error: errors.join("; ") };
}
