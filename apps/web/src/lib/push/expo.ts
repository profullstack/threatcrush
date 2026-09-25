import "server-only";
import type { PushNotification, PushSendResult } from "./types";

export const EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";
/** Expo rejects requests with more than 100 messages. */
const CHUNK_SIZE = 100;

type ExpoTicket =
  | { status: "ok"; id: string }
  | { status: "error"; message?: string; details?: { error?: string } };

/**
 * Send `notification` to every Expo push token. Never throws. Tokens Expo
 * answers with `DeviceNotRegistered` (app uninstalled, token rotated) come back
 * in `dead`.
 *
 * EXPO_ACCESS_TOKEN is only required when "Enhanced push security" is turned
 * on for the Expo project.
 */
export async function sendExpoPush(
  tokens: string[],
  notification: PushNotification,
): Promise<PushSendResult> {
  const result: PushSendResult = { sent: 0, failures: [], dead: [] };
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  const accessToken = process.env.EXPO_ACCESS_TOKEN?.trim();
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  for (let start = 0; start < tokens.length; start += CHUNK_SIZE) {
    const chunk = tokens.slice(start, start + CHUNK_SIZE);
    const messages = chunk.map((to) => ({
      to,
      title: notification.title,
      body: notification.body,
      data: { url: notification.url, ...notification.data },
      sound: "default",
      priority: "high",
    }));

    let tickets: ExpoTicket[];
    try {
      const res = await fetch(EXPO_PUSH_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(messages),
        signal: AbortSignal.timeout(10_000),
      });
      const text = await res.text();
      if (!res.ok) {
        result.failures.push(`expo HTTP ${res.status}: ${text.slice(0, 200)}`);
        continue;
      }
      tickets = (JSON.parse(text) as { data?: ExpoTicket[] }).data ?? [];
    } catch (err) {
      result.failures.push(`expo request failed: ${(err as Error).message}`);
      continue;
    }

    // Tickets come back in message order.
    chunk.forEach((token, i) => {
      const ticket = tickets[i];
      if (ticket?.status === "ok") {
        result.sent++;
      } else if (ticket?.details?.error === "DeviceNotRegistered") {
        result.dead.push(token);
      } else {
        result.failures.push(`expo: ${ticket?.message ?? "no ticket returned"}`.slice(0, 300));
      }
    });
  }

  return result;
}
