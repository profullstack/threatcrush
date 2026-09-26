import "server-only";
import { createHmac } from "node:crypto";
import { Resend } from "resend";
import { sendOrgPush } from "@/lib/push/org";
import { safeFetch } from "@/lib/ssrf-guard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { buildTestMessage } from "./message";
import type { AlertDestinationRow, AlertMessage, DeliveryOutcome, Severity } from "./types";

export const PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue";
const EMAIL_FROM = "ThreatCrush Alerts <alerts@threatcrush.com>";
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_EMAIL_RECIPIENTS = 10;
const EMAIL_PATTERN = /^[^\s@<>,]+@[^\s@<>,]+\.[^\s@<>,]+$/;

const DISCORD_COLOR: Record<Severity, number> = {
  critical: 0xa855f7,
  high: 0xef4444,
  medium: 0xeab308,
  low: 0x3b82f6,
  info: 0x22c55e,
};

const PAGERDUTY_SEVERITY: Record<Severity, "critical" | "error" | "warning" | "info"> = {
  critical: "critical",
  high: "error",
  medium: "warning",
  low: "info",
  info: "info",
};

function configString(destination: AlertDestinationRow, key: string): string | null {
  const value = destination.config?.[key];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/** Slack treats `<...>` as links/mentions; detection text must not ping `<!channel>`. */
function slackEscape(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function htmlEscape(text: string): string {
  return slackEscape(text).replace(/"/g, "&quot;");
}

/**
 * POST JSON (an object, or an already serialized string) to a customer-supplied
 * URL through the SSRF guard. Non-2xx and
 * guard refusals become failures, never exceptions.
 */
async function postJsonGuarded(
  url: string,
  payload: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<DeliveryOutcome> {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  try {
    const res = await safeFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "ThreatCrush-Alerts/1", ...extraHeaders },
      body,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.ok) return { ok: true };
    const text = await res.text().catch(() => "");
    return { ok: false, error: `HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ""}` };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

function webhookPayload(message: AlertMessage) {
  return {
    event: message.detection ? "detection.created" : "test",
    title: message.title,
    severity: message.severity,
    message: message.body,
    timestamp: message.timestamp,
    url: message.url,
    ...(message.detection && { detection: message.detection }),
  };
}

async function sendWebhook(destination: AlertDestinationRow, message: AlertMessage): Promise<DeliveryOutcome> {
  const url = configString(destination, "url");
  if (!url) return { ok: false, error: "Webhook URL not configured" };
  const body = JSON.stringify(webhookPayload(message));
  const secret = configString(destination, "secret");
  // Receivers verify with HMAC-SHA256(secret, raw body); the secret itself never travels.
  const headers: Record<string, string> = {};
  if (secret) {
    headers["X-ThreatCrush-Signature"] = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  }
  return postJsonGuarded(url, body, headers);
}

async function sendSlack(destination: AlertDestinationRow, message: AlertMessage): Promise<DeliveryOutcome> {
  const url = configString(destination, "webhook_url");
  if (!url) return { ok: false, error: "Slack webhook not configured" };
  const icon = message.detection ? ":rotating_light:" : ":white_check_mark:";
  return postJsonGuarded(url, {
    text: `${icon} *${slackEscape(message.title)}*\n${slackEscape(message.body)}\n<${message.url}|View in ThreatCrush>`,
  });
}

async function sendDiscord(destination: AlertDestinationRow, message: AlertMessage): Promise<DeliveryOutcome> {
  const url = configString(destination, "webhook_url");
  if (!url) return { ok: false, error: "Discord webhook not configured" };
  return postJsonGuarded(url, {
    username: "ThreatCrush",
    // Detection text comes from monitored hosts; it must never @everyone.
    allowed_mentions: { parse: [] },
    embeds: [
      {
        title: message.title.slice(0, 256),
        description: message.body.slice(0, 4000),
        url: message.url,
        color: DISCORD_COLOR[message.severity],
        timestamp: message.timestamp,
      },
    ],
  });
}

async function sendPagerDuty(destination: AlertDestinationRow, message: AlertMessage): Promise<DeliveryOutcome> {
  const routingKey = configString(destination, "routing_key");
  if (!routingKey) return { ok: false, error: "PagerDuty routing key not configured" };
  const detection = message.detection;
  try {
    const res = await fetch(PAGERDUTY_EVENTS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: "trigger",
        // One incident per detection; PagerDuty folds resends into it.
        ...(detection && { dedup_key: `threatcrush-${detection.id}` }),
        payload: {
          summary: message.title.slice(0, 1024),
          source: detection?.server_name ?? detection?.server_id ?? "threatcrush.com",
          severity: PAGERDUTY_SEVERITY[message.severity],
          timestamp: message.timestamp,
          component: detection?.rule_id ?? undefined,
          custom_details: detection
            ? {
                description: detection.description,
                source_ip: detection.source_ip,
                rule_id: detection.rule_id,
                server_id: detection.server_id,
                detection_id: detection.id,
              }
            : { message: message.body },
        },
        links: [{ href: message.url, text: "View in ThreatCrush" }],
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.ok) return { ok: true };
    const text = await res.text().catch(() => "");
    return { ok: false, error: `PagerDuty HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ""}` };
  } catch (err) {
    return { ok: false, error: `PagerDuty request failed: ${(err as Error).message}` };
  }
}

async function sendEmail(destination: AlertDestinationRow, message: AlertMessage): Promise<DeliveryOutcome> {
  const to = (configString(destination, "to") ?? "")
    .split(",")
    .map((address) => address.trim())
    .filter(Boolean);
  if (to.length === 0) return { ok: false, error: "Email recipient not configured" };
  if (to.length > MAX_EMAIL_RECIPIENTS || !to.every((address) => EMAIL_PATTERN.test(address))) {
    return { ok: false, error: `Email recipients must be up to ${MAX_EMAIL_RECIPIENTS} valid addresses` };
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return { ok: false, error: "Email delivery is not configured (RESEND_API_KEY not set)" };

  const html = `<h2>${htmlEscape(message.title)}</h2>
<p style="white-space:pre-line">${htmlEscape(message.body)}</p>
<p><a href="${htmlEscape(message.url)}">View in ThreatCrush</a></p>`;
  try {
    const { error } = await new Resend(apiKey).emails.send({
      from: EMAIL_FROM,
      to,
      subject: message.title.slice(0, 200),
      text: `${message.title}\n\n${message.body}\n\n${message.url}`,
      html,
    });
    return error ? { ok: false, error: `Resend: ${error.message}` } : { ok: true };
  } catch (err) {
    return { ok: false, error: `Resend request failed: ${(err as Error).message}` };
  }
}

async function sendPush(destination: AlertDestinationRow, message: AlertMessage): Promise<DeliveryOutcome> {
  const result = await sendOrgPush(destination.organization_id, {
    title: message.title,
    body: message.body,
    url: message.url,
    tag: message.tag,
    data: message.detection
      ? { detection_id: message.detection.id, organization_id: message.detection.organization_id }
      : {},
  });
  const failures = result.failures.join("; ").slice(0, 500);
  if (result.devices === 0) {
    return { ok: false, error: failures || "No devices are registered for push notifications in this org" };
  }
  if (result.sent > 0) {
    return { ok: true, detail: `sent to ${result.sent} of ${result.devices} devices${failures ? `; ${failures}` : ""}` };
  }
  if (!failures && result.dead.length > 0) {
    return { ok: false, error: `All ${result.dead.length} registered devices had expired and were removed` };
  }
  return { ok: false, error: failures || "No push notification was delivered" };
}

/** Deliver one alert to one destination. Never throws. */
export async function deliverAlert(
  destination: AlertDestinationRow,
  message: AlertMessage,
): Promise<DeliveryOutcome> {
  try {
    switch (destination.type) {
      case "webhook":
        return await sendWebhook(destination, message);
      case "slack":
        return await sendSlack(destination, message);
      case "discord":
        return await sendDiscord(destination, message);
      case "pagerduty":
        return await sendPagerDuty(destination, message);
      case "email":
        return await sendEmail(destination, message);
      case "push":
        return await sendPush(destination, message);
      default:
        return { ok: false, error: `Unsupported destination type: ${String(destination.type)}` };
    }
  } catch (err) {
    return { ok: false, error: `Delivery crashed: ${(err as Error).message}` };
  }
}

/** The destination's "Test" button: a canned message through the real sender. */
export async function sendTestAlert(destination: AlertDestinationRow): Promise<DeliveryOutcome> {
  const { data: org } = await getSupabaseAdmin()
    .from("organizations")
    .select("slug")
    .eq("id", destination.organization_id)
    .maybeSingle();
  return deliverAlert(destination, buildTestMessage((org as { slug?: string } | null)?.slug ?? null));
}
