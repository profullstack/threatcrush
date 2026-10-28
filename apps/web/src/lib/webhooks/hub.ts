import "server-only";
import { randomBytes } from "node:crypto";
import {
  Webhooks,
  createEvent,
  matchesEvent,
  sha256Header,
  type Delivery,
  type WebhookStore,
  type WebhooksOptions,
} from "@profullstack/webhooks";
import { safeFetch } from "@/lib/ssrf-guard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { countDeliveriesSince, supabaseStore, type SupabaseLike } from "./supabase-store";

/**
 * Customer webhooks for ThreatCrush, on @profullstack/webhooks.
 *
 * One hub endpoint (hub_webhook_endpoints, owner = the organization id) per
 * webhook. Two kinds:
 *  - the "Webhook" alert destination (Settings -> Alerts). Its row in
 *    alert_destinations keeps `config.hub_endpoint_id`; alert rules decide
 *    what reaches it (min severity, server scope, hourly rate limit) exactly
 *    as before, and each rule hit is queued to that one endpoint;
 *  - an endpoint made through /api/v1/webhooks (or the CLI / MCP) that no
 *    destination points at. It gets every event its patterns match, capped at
 *    UNROUTED_LIMIT_PER_HOUR, like a rule's default limit.
 *
 * Deliveries are durable: queued in hub_webhook_deliveries, sent by the
 * drainer started at boot (src/instrumentation.ts), retried with backoff for
 * about three days, logged.
 *
 * Receivers built against the old sender keep working unchanged:
 *  - `X-ThreatCrush-Signature: sha256=<hex HMAC-SHA256 of the raw body>`,
 *    keyed with the secret the customer typed (see `storedSecret`);
 *  - `content-type: application/json`, `user-agent: ThreatCrush-Alerts/1`;
 *  - the body still has the old fields at the top level (`event`, `title`,
 *    `severity`, `message`, `timestamp`, `url`, `detection` / `findings`),
 *    next to the CloudEvents attributes (`specversion`, `id`, `type`,
 *    `source`, `time`, `data`, where `data` holds the same alert).
 * New receivers verify the Standard Webhooks `webhook-signature` header.
 */

export const WEBHOOK_SOURCE = "https://threatcrush.com";

/** What ThreatCrush emits: the alert kinds an alert destination receives. */
export const WEBHOOK_EVENT_TYPES = ["detection.created", "findings.raised", "reputation.changed"] as const;
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

/** The alert kinds a migrated or newly added webhook destination subscribes to. */
export const ALERT_DESTINATION_EVENTS: string[] = [...WEBHOOK_EVENT_TYPES];

/** For endpoints no alert rule governs: the default rate_limit_per_hour of a rule. */
export const UNROUTED_LIMIT_PER_HOUR = 60;

const HOUR_MS = 60 * 60 * 1000;
const SECRET_PREFIX = "whsec_";

/**
 * The hub secret for a signing secret a customer typed. The package keys a
 * `whsec_` secret with the base64 after the prefix and anything else with its
 * UTF-8 bytes; the old sender always used the UTF-8 bytes of the whole string.
 * So a typed `whsec_...` is re-wrapped as `whsec_` + base64(its bytes): same
 * key, and both the old and the new signature header verify with what the
 * customer already has. Everything else is stored as typed.
 */
export function storedSecret(typed: string): string {
  return typed.startsWith(SECRET_PREFIX) ? `${SECRET_PREFIX}${Buffer.from(typed, "utf8").toString("base64")}` : typed;
}

/** The headers the old sender put on every delivery, next to the Standard Webhooks ones. */
export const legacyHeaders: NonNullable<WebhooksOptions["extraHeaders"]> = (input) => ({
  "content-type": "application/json",
  "user-agent": "ThreatCrush-Alerts/1",
  ...sha256Header("X-ThreatCrush-Signature")(input),
});

/**
 * Pins the socket to the address the SSRF guard checked (the package checks the
 * URL, then fetch would resolve it again). The package already refuses
 * redirects (`redirect: "manual"`), which safeFetch honours.
 */
const guardedFetch: typeof fetch = (input, init) =>
  safeFetch(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, init);

/** Keep the alert_deliveries row of a rule-routed webhook in step with the hub. */
async function syncAlertDelivery({ delivery, ok }: { delivery: { id: string; status: string; attempts: number; last_error: string | null }; ok: boolean }) {
  const status = ok ? "sent" : delivery.status === "failed" ? "failed" : "queued";
  const error = ok
    ? null
    : status === "failed"
      ? (delivery.last_error ?? "delivery failed").slice(0, 1000)
      : `attempt ${delivery.attempts} failed (${delivery.last_error ?? "error"}); retrying`.slice(0, 1000);
  const { error: dbError } = await getSupabaseAdmin()
    .from("alert_deliveries")
    .update({ status, error })
    .eq("hub_delivery_id", delivery.id);
  if (dbError) console.error("[webhooks] could not update alert delivery:", dbError.message);
}

export function createHooks(store: WebhookStore, options: Partial<WebhooksOptions> = {}): Webhooks {
  return new Webhooks({
    store,
    source: WEBHOOK_SOURCE,
    eventTypes: [...WEBHOOK_EVENT_TYPES],
    maxEndpoints: 25,
    extraHeaders: legacyHeaders,
    fetchImpl: guardedFetch,
    guard: process.env.NODE_ENV === "production" ? {} : { allowHttp: true },
    onDelivery: syncAlertDelivery,
    log: (m) => console.warn(`[webhooks] ${m}`),
    ...options,
  });
}

interface Hub {
  hooks: Webhooks;
  store: WebhookStore;
  client: SupabaseLike;
}

const KEY = Symbol.for("threatcrush.webhooks.hub");
type HubGlobal = typeof globalThis & { [KEY]?: Hub };

/**
 * The process-wide hub. On globalThis because Next bundles route handlers and
 * instrumentation separately: a module-level singleton would give each its
 * own instance, and only the one that called start() would drain.
 */
export function getHub(): Hub {
  const g = globalThis as HubGlobal;
  if (!g[KEY]) {
    const client = getSupabaseAdmin() as unknown as SupabaseLike;
    const store = supabaseStore(client);
    g[KEY] = { hooks: createHooks(store), store, client };
  }
  return g[KEY]!;
}

/** Tests swap in a hub on a fake store. */
export function setHubForTests(hub: Hub | undefined): void {
  (globalThis as HubGlobal)[KEY] = hub;
}

export function getHooks(): Webhooks {
  return getHub().hooks;
}

/** Start the background drainer once per server process. */
export function startWebhooks(): void {
  getHooks().start();
}

/** One alert, as it is queued: the CloudEvents type plus the old body's fields. */
export interface WebhookAlert {
  type: WebhookEventType;
  /** The old webhook body (`event`, `title`, `severity`, ...): CloudEvents `data`, and mirrored at the top level. */
  legacy: Record<string, unknown>;
  subject?: string;
}

function deliveryFor(owner: string, endpointId: string, alert: WebhookAlert, at: number): Delivery {
  const event = createEvent(alert.type, alert.legacy, {
    source: WEBHOOK_SOURCE,
    ...(alert.subject ? { subject: alert.subject } : {}),
  });
  return {
    id: `dlv_${randomBytes(12).toString("base64url")}`,
    endpointId,
    owner,
    eventId: event.id,
    eventType: alert.type,
    // CloudEvents attributes first; the old top-level fields cannot collide with them.
    payload: JSON.stringify({ ...event, ...alert.legacy }),
    status: "pending",
    attempts: 0,
    nextAt: at,
    lastStatus: null,
    lastError: null,
    createdAt: at,
    updatedAt: at,
  };
}

function kick(hooks: Webhooks) {
  void hooks.drain().catch((err: Error) => console.error("[webhooks] drain failed:", err.message));
}

export type QueueOutcome = { ok: true; deliveryId: string } | { ok: false; error: string };

/**
 * Queue one alert to one endpoint (an alert destination's), after its rule
 * matched. The endpoint's own event patterns and on/off switch still apply.
 */
export async function queueToEndpoint(owner: string, endpointId: string, alert: WebhookAlert): Promise<QueueOutcome> {
  const { hooks, store } = getHub();
  const endpoint = await store.getEndpoint(endpointId);
  if (!endpoint || endpoint.owner !== owner) return { ok: false, error: "Webhook endpoint was deleted; remove and re-add this destination" };
  if (!endpoint.enabled) {
    return { ok: false, error: `Webhook endpoint is switched off${endpoint.disabledReason ? `: ${endpoint.disabledReason}` : ""}` };
  }
  if (!matchesEvent(endpoint.events, alert.type)) return { ok: false, error: `Webhook endpoint does not subscribe to ${alert.type}` };
  const delivery = deliveryFor(owner, endpointId, alert, Date.now());
  await store.insertDeliveries([delivery]);
  kick(hooks);
  return { ok: true, deliveryId: delivery.id };
}

/**
 * Queue alerts to the org's endpoints that no alert destination owns (made via
 * /api/v1/webhooks, the CLI or MCP), by their event patterns, at most
 * UNROUTED_LIMIT_PER_HOUR each. `build` may be a function, called only when
 * the org has an endpoint at all. Never throws: alert dispatch runs after the
 * response.
 */
export async function emitToOrg(
  orgId: string,
  build: WebhookAlert[] | (() => Promise<WebhookAlert[]>),
): Promise<number> {
  try {
    const { hooks, store, client } = getHub();
    const endpoints = (await store.listEndpoints(orgId)).filter((e) => e.enabled);
    if (!endpoints.length) return 0;
    // Built only when the org has an endpoint: most have none, and building can cost queries.
    const alerts = typeof build === "function" ? await build() : build;
    if (!alerts.length) return 0;

    const { data, error } = await getSupabaseAdmin()
      .from("alert_destinations")
      .select("config")
      .eq("organization_id", orgId)
      .eq("type", "webhook");
    if (error) throw new Error(error.message);
    const linked = new Set(
      ((data ?? []) as { config: Record<string, unknown> | null }[])
        .map((d) => d.config?.hub_endpoint_id)
        .filter((id): id is string => typeof id === "string"),
    );

    const now = Date.now();
    const rows: Delivery[] = [];
    for (const endpoint of endpoints) {
      if (linked.has(endpoint.id)) continue;
      const wanted = alerts.filter((a) => matchesEvent(endpoint.events, a.type));
      if (!wanted.length) continue;
      const room = UNROUTED_LIMIT_PER_HOUR - (await countDeliveriesSince(client, endpoint.id, now - HOUR_MS));
      if (room <= 0) continue;
      for (const alert of wanted.slice(0, room)) rows.push(deliveryFor(orgId, endpoint.id, alert, now));
    }
    if (!rows.length) return 0;
    await store.insertDeliveries(rows);
    kick(hooks);
    return rows.length;
  } catch (err) {
    console.error(`[webhooks] org ${orgId}: could not queue webhooks:`, (err as Error).message);
    return 0;
  }
}

/**
 * The hub endpoint behind a webhook alert destination, made on first use for
 * a destination saved before the hub existed (or between the migration and
 * this deploy). Keeps the destination's own secret; returns the endpoint id
 * and, when ThreatCrush had to generate the secret, that secret (shown once).
 */
export async function ensureDestinationEndpoint(destination: {
  id: string;
  organization_id: string;
  name: string;
  enabled: boolean;
  config: Record<string, unknown> | null;
}): Promise<{ endpointId: string; generatedSecret: string | null }> {
  const config = destination.config ?? {};
  if (typeof config.hub_endpoint_id === "string" && config.hub_endpoint_id) {
    return { endpointId: config.hub_endpoint_id, generatedSecret: null };
  }
  const url = typeof config.url === "string" ? config.url.trim() : "";
  if (!url) throw new Error("Webhook URL not configured");
  const { hooks, store } = getHub();
  const { endpoint, secret } = await hooks.createEndpoint(destination.organization_id, {
    url,
    events: ALERT_DESTINATION_EVENTS,
    description: String(destination.name ?? "").slice(0, 200),
  });
  const typed = typeof config.secret === "string" ? config.secret.trim() : "";
  if (typed) await store.updateEndpoint(endpoint.id, { secret: storedSecret(typed), updatedAt: Date.now() });
  if (!destination.enabled) await store.updateEndpoint(endpoint.id, { enabled: false, updatedAt: Date.now() });

  const { secret: _dropped, ...rest } = config;
  const { error } = await getSupabaseAdmin()
    .from("alert_destinations")
    .update({ config: { ...rest, hub_endpoint_id: endpoint.id } })
    .eq("id", destination.id);
  if (error) {
    await store.deleteEndpoint(endpoint.id).catch(() => {});
    throw new Error(`Could not link the webhook endpoint: ${error.message}`);
  }
  destination.config = { ...rest, hub_endpoint_id: endpoint.id };
  return { endpointId: endpoint.id, generatedSecret: typed ? null : secret };
}
