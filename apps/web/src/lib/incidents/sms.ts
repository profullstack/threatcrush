import "server-only";
import { isTelnyxConfigured, sendTelnyxSms } from "@/lib/telnyx";

export type SmsOutcome = { ok: true; provider: "smshub" | "telnyx"; detail?: string } | { ok: false; error: string };

const TIMEOUT_MS = 15_000;

/** smshub alert severity for an incident severity: critical/high always ring the phone. */
export function smshubSeverity(severity: string | undefined): "info" | "warning" | "critical" {
  const s = (severity ?? "").toLowerCase();
  if (s === "critical" || s === "high") return "critical";
  if (s === "info" || s === "low") return "info";
  return "warning";
}

/**
 * One incident page to a phone. smshub's alert API first (SMSHUB_API_KEY:
 * POST /api/v1/alerts), which texts when the account has a number that can
 * deliver SMS and otherwise, and always for critical, calls and reads the
 * message. Then Telnyx SMS directly (TELNYX_API_KEY + TELNYX_PHONE_NUMBER)
 * when smshub is not set up or fails. Never throws.
 */
export async function sendIncidentSms(
  to: string,
  message: string,
  env: NodeJS.ProcessEnv = process.env,
  severity?: string,
): Promise<SmsOutcome> {
  const errors: string[] = [];
  const key = env.SMSHUB_API_KEY?.trim();
  if (key) {
    const base = (env.SMSHUB_URL?.trim() || "https://smshub.dev").replace(/\/$/, "");
    try {
      const res = await fetch(`${base}/api/v1/alerts`, {
        method: "POST",
        headers: { "X-API-Key": key, "Content-Type": "application/json", "User-Agent": "ThreatCrush-Incidents/1" },
        body: JSON.stringify({ to, message, severity: smshubSeverity(severity) }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      const text = await res.text().catch(() => "");
      if (res.ok) {
        let channels: string[] = [];
        try {
          channels = (JSON.parse(text) as { alert?: { channels?: string[] } }).alert?.channels ?? [];
        } catch {
          // a 2xx without a JSON body still went out
        }
        if (channels.includes("call") && !channels.includes("sms") && isTelnyxConfigured()) {
          try {
            // SMSHub can successfully place a call when its sender line is not
            // registered for texting. Preserve that call, then deliver the
            // text from ThreatCrush's configured Telnyx line.
            await sendTelnyxSms(to, message);
            return { ok: true, provider: "smshub", detail: "smshub call; Telnyx SMS sent" };
          } catch (err) {
            return {
              ok: true,
              provider: "smshub",
              detail: `smshub call; Telnyx SMS failed: ${(err as Error).message.slice(0, 300)}`,
            };
          }
        }
        return { ok: true, provider: "smshub", detail: channels.length ? `smshub ${channels.join("+")}` : "smshub" };
      }
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
