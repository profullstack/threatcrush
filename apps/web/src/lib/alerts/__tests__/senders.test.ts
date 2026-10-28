import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery } from "@/__tests__/helpers/query-recorder";

vi.hoisted(() => {
  process.env.NEXT_PUBLIC_APP_URL = "https://threatcrush.com";
});

const safeFetch = vi.fn();
vi.mock("@/lib/ssrf-guard", () => ({ safeFetch: (...args: unknown[]) => safeFetch(...args) }));

const resendSend = vi.fn();
vi.mock("resend", () => ({
  Resend: class {
    emails = { send: (...args: unknown[]) => resendSend(...args) };
  },
}));

const subscriptions = { rows: [] as unknown[] };
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "push_subscriptions") return recordQuery({ data: subscriptions.rows, error: null });
      if (table === "organizations") return recordQuery({ data: { slug: "acme" }, error: null });
      throw new Error(`Unexpected table ${table}`);
    },
  }),
}));

const hub = {
  ensure: vi.fn(),
  queue: vi.fn(),
};
vi.mock("@/lib/webhooks/hub", () => ({
  ensureDestinationEndpoint: (...a: unknown[]) => hub.ensure(...a),
  queueToEndpoint: (...a: unknown[]) => hub.queue(...a),
  getHooks: () => ({ test: async () => ({ ok: true, status: 204, error: null }) }),
}));

import { buildDetectionMessage } from "../message";
import { deliverAlert, PAGERDUTY_EVENTS_URL } from "../senders";
import type { AlertDestinationRow, DestinationType } from "../types";

const fetchMock = vi.mocked(fetch);

const message = buildDetectionMessage(
  {
    id: "det-1",
    organization_id: "org-1",
    server_id: "srv-1",
    severity: "critical",
    title: "Root login <!channel> @everyone",
    description: "Login from unknown network",
    source_ip: "203.0.113.5",
    rule_id: "ssh-root-login",
    detected_at: "2026-09-25T10:00:00.000Z",
  },
  { orgSlug: "acme", serverName: "web-1" },
);

function dest(type: DestinationType, config: Record<string, unknown>): AlertDestinationRow {
  return { id: "dest-1", organization_id: "org-1", name: type, type, config, enabled: true };
}

function sentBody(mock: typeof safeFetch | typeof fetchMock) {
  const [, init] = mock.mock.calls[0] as [string, RequestInit];
  return JSON.parse(init.body as string);
}

beforeEach(() => {
  hub.ensure.mockReset();
  hub.queue.mockReset();
  safeFetch.mockReset().mockResolvedValue(new Response("ok", { status: 200 }));
  fetchMock.mockReset().mockResolvedValue(new Response('{"status":"success"}', { status: 202 }));
  resendSend.mockReset().mockResolvedValue({ data: { id: "email-1" }, error: null });
  subscriptions.rows = [];
  process.env.RESEND_API_KEY = "re_test";
});

describe("customer-URL senders go through the SSRF guard", () => {
  it("posts Slack text with mentions neutralised and a dashboard link", async () => {
    const outcome = await deliverAlert(dest("slack", { webhook_url: "https://hooks.slack.com/services/T/B/x" }), message);

    expect(outcome).toEqual({ ok: true });
    expect(safeFetch.mock.calls[0][0]).toBe("https://hooks.slack.com/services/T/B/x");
    const { text } = sentBody(safeFetch);
    expect(text).toContain("&lt;!channel&gt;");
    expect(text).not.toContain("<!channel>");
    expect(text).toContain("<https://threatcrush.com/org/acme/detections?detection=det-1|View in ThreatCrush>");
  });

  it("posts a Discord embed that cannot ping anyone", async () => {
    await deliverAlert(dest("discord", { webhook_url: "https://discord.com/api/webhooks/1/x" }), message);

    const body = sentBody(safeFetch);
    expect(body.allowed_mentions).toEqual({ parse: [] });
    expect(body.embeds[0]).toMatchObject({
      title: "[CRITICAL] Root login <!channel> @everyone",
      url: "https://threatcrush.com/org/acme/detections?detection=det-1",
      timestamp: "2026-09-25T10:00:00.000Z",
    });
  });

  it("queues webhooks in the hub for the destination's endpoint, with the old body as data", async () => {
    hub.ensure.mockResolvedValue({ endpointId: "wh_1", generatedSecret: null });
    hub.queue.mockResolvedValue({ ok: true, deliveryId: "dlv_1" });
    const outcome = await deliverAlert(dest("webhook", { url: "https://example.com/hook", hub_endpoint_id: "wh_1" }), message);

    expect(outcome).toEqual({ ok: true, detail: "queued", hubDeliveryId: "dlv_1" });
    expect(safeFetch).not.toHaveBeenCalled();
    const [owner, endpointId, alert] = hub.queue.mock.calls[0];
    expect(owner).toBe("org-1");
    expect(endpointId).toBe("wh_1");
    expect(alert).toMatchObject({
      type: "detection.created",
      subject: "detection:det-1",
      legacy: { event: "detection.created", severity: "critical", detection: { id: "det-1", server_name: "web-1", source_ip: "203.0.113.5" } },
    });
  });

  it("reports a webhook that cannot be queued as a failure", async () => {
    hub.ensure.mockRejectedValue(new Error("Webhook URL not configured"));
    const outcome = await deliverAlert(dest("webhook", {}), message);
    expect(outcome).toEqual({ ok: false, error: "Webhook URL not configured" });
    expect(hub.queue).not.toHaveBeenCalled();
  });

  it("records a non-2xx answer as a failure with the status", async () => {
    safeFetch.mockResolvedValue(new Response("invalid_token", { status: 403 }));
    const outcome = await deliverAlert(dest("slack", { webhook_url: "https://hooks.slack.com/x" }), message);
    expect(outcome).toEqual({ ok: false, error: "HTTP 403: invalid_token" });
  });

  it("records a guard refusal as a failure instead of throwing", async () => {
    safeFetch.mockRejectedValue(new Error("Requests to internal addresses are not allowed"));
    const outcome = await deliverAlert(dest("slack", { webhook_url: "http://169.254.169.254/" }), message);
    expect(outcome).toEqual({ ok: false, error: "Requests to internal addresses are not allowed" });
  });

  it("fails fast when the URL is not configured", async () => {
    const outcome = await deliverAlert(dest("discord", {}), message);
    expect(outcome.ok).toBe(false);
    expect(safeFetch).not.toHaveBeenCalled();
  });
});

describe("PagerDuty", () => {
  it("triggers an Events API v2 incident deduplicated per detection", async () => {
    const outcome = await deliverAlert(dest("pagerduty", { routing_key: "R0UTING" }), message);

    expect(outcome).toEqual({ ok: true });
    expect(fetchMock.mock.calls[0][0]).toBe(PAGERDUTY_EVENTS_URL);
    expect(sentBody(fetchMock)).toMatchObject({
      routing_key: "R0UTING",
      event_action: "trigger",
      dedup_key: "threatcrush-det-1",
      payload: { summary: "[CRITICAL] Root login <!channel> @everyone", source: "web-1", severity: "critical" },
      links: [{ href: "https://threatcrush.com/org/acme/detections?detection=det-1" }],
    });
  });

  it("maps high to PagerDuty's error severity", async () => {
    await deliverAlert(dest("pagerduty", { routing_key: "R" }), { ...message, severity: "high" });
    expect(sentBody(fetchMock).payload.severity).toBe("error");
  });

  it("records a rejected routing key", async () => {
    fetchMock.mockResolvedValue(new Response('{"status":"invalid event"}', { status: 400 }));
    const outcome = await deliverAlert(dest("pagerduty", { routing_key: "bad" }), message);
    expect(outcome).toEqual({ ok: false, error: 'PagerDuty HTTP 400: {"status":"invalid event"}' });
  });
});

describe("email", () => {
  it("sends through Resend to every configured recipient", async () => {
    const outcome = await deliverAlert(dest("email", { to: "a@example.com, b@example.com" }), message);

    expect(outcome).toEqual({ ok: true });
    expect(resendSend.mock.calls[0][0]).toMatchObject({
      to: ["a@example.com", "b@example.com"],
      subject: "[CRITICAL] Root login <!channel> @everyone",
    });
    expect(resendSend.mock.calls[0][0].html).toContain("&lt;!channel&gt;");
  });

  it("fails clearly without RESEND_API_KEY", async () => {
    delete process.env.RESEND_API_KEY;
    const outcome = await deliverAlert(dest("email", { to: "a@example.com" }), message);
    expect(outcome).toEqual({ ok: false, error: "Email delivery is not configured (RESEND_API_KEY not set)" });
    expect(resendSend).not.toHaveBeenCalled();
  });

  it("refuses malformed recipients", async () => {
    const outcome = await deliverAlert(dest("email", { to: "not-an-address" }), message);
    expect(outcome.ok).toBe(false);
    expect(resendSend).not.toHaveBeenCalled();
  });

  it("records a provider error", async () => {
    resendSend.mockResolvedValue({ data: null, error: { message: "domain not verified" } });
    const outcome = await deliverAlert(dest("email", { to: "a@example.com" }), message);
    expect(outcome).toEqual({ ok: false, error: "Resend: domain not verified" });
  });
});

describe("push", () => {
  it("fails when the org has no registered devices", async () => {
    const outcome = await deliverAlert(dest("push", {}), message);
    expect(outcome).toEqual({ ok: false, error: "No devices are registered for push notifications in this org" });
  });
});
