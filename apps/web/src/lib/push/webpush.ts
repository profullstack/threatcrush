import "server-only";
import { sendNotification, WebPushError } from "web-push";
import type { PushNotification, PushSendResult } from "./types";

/**
 * Push services browsers actually hand out endpoints for. A subscription's
 * endpoint is a URL the server later POSTs to, so anything outside this list
 * is refused at registration and skipped at send time.
 *
 * - fcm.googleapis.com: Chrome, Chromium-based browsers (Brave, Opera, Samsung Internet), Android
 * - jmt17.google.com: Chromium builds without Google API keys (open-source Chromium, Playwright)
 * - updates.push.services.mozilla.com: Firefox
 * - *.push.apple.com: Safari (macOS 13+, iOS 16.4+ home-screen apps)
 * - *.notify.windows.com: Edge (WNS)
 */
const EXACT_HOSTS: Record<string, true> = {
  "fcm.googleapis.com": true,
  "jmt17.google.com": true,
  "updates.push.services.mozilla.com": true,
};
const HOST_SUFFIXES = [".push.apple.com", ".notify.windows.com"];

export function isAllowedWebPushEndpoint(endpoint: string): boolean {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.port !== "" || url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  return EXACT_HOSTS[host] === true || HOST_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

export interface WebPushTarget {
  endpoint: string;
  p256dh: string;
  auth: string;
}

/** The VAPID key pair, or the name of what is missing. */
export function webPushConfig():
  | { ok: true; subject: string; publicKey: string; privateKey: string }
  | { ok: false; error: string } {
  const publicKey = process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY?.trim();
  const privateKey = process.env.VAPID_PRIVATE_KEY?.trim();
  const subject = process.env.VAPID_SUBJECT?.trim() || "mailto:admin@threatcrush.com";
  const missing = [
    !publicKey && "NEXT_PUBLIC_VAPID_PUBLIC_KEY",
    !privateKey && "VAPID_PRIVATE_KEY",
  ].filter(Boolean);
  if (missing.length > 0 || !publicKey || !privateKey) {
    return { ok: false, error: `Web Push is not configured (${missing.join(", ")} not set)` };
  }
  return { ok: true, subject, publicKey, privateKey };
}

/**
 * Send one encrypted Web Push message to each subscription. Never throws.
 * Subscriptions the push service reports as gone (404/410) come back in
 * `dead` so the caller can delete them.
 */
export async function sendWebPush(
  targets: WebPushTarget[],
  notification: PushNotification,
): Promise<PushSendResult> {
  const result: PushSendResult = { sent: 0, failures: [], dead: [] };
  if (targets.length === 0) return result;

  const config = webPushConfig();
  if (!config.ok) {
    result.failures.push(config.error);
    return result;
  }

  // Exactly what public/sw.js reads in its `push` handler.
  const payload = JSON.stringify({
    title: notification.title,
    body: notification.body,
    url: notification.url,
    tag: notification.tag,
  });

  await Promise.all(
    targets.map(async (target) => {
      if (!isAllowedWebPushEndpoint(target.endpoint)) {
        result.failures.push("subscription endpoint is not a known push service");
        return;
      }
      try {
        await sendNotification(
          { endpoint: target.endpoint, keys: { p256dh: target.p256dh, auth: target.auth } },
          payload,
          {
            vapidDetails: {
              subject: config.subject,
              publicKey: config.publicKey,
              privateKey: config.privateKey,
            },
            TTL: 60 * 60,
            urgency: "high",
            timeout: 10_000,
          },
        );
        result.sent++;
      } catch (err) {
        if (err instanceof WebPushError && (err.statusCode === 404 || err.statusCode === 410)) {
          result.dead.push(target.endpoint);
          return;
        }
        const status = err instanceof WebPushError ? `HTTP ${err.statusCode}: ` : "";
        result.failures.push(`web push ${status}${(err as Error).message}`.slice(0, 300));
      }
    }),
  );

  return result;
}
