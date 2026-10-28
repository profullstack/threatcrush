import { createHmac } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { verifySignature } from "@profullstack/webhooks";
import { fakeSupabase } from "./fake-supabase";

// alert_destinations / alert_deliveries live in the app's tables; the hub's own in the fake.
const appTables: Record<string, Array<Record<string, unknown>>> = { alert_destinations: [], alert_deliveries: [] };
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      let rows = appTables[table] ?? [];
      const q: Record<string, unknown> = {};
      let patch: Record<string, unknown> | null = null;
      Object.assign(q, {
        select: () => q,
        update: (p: Record<string, unknown>) => ((patch = p), q),
        eq: (c: string, v: unknown) => {
          rows = rows.filter((r) => r[c] === v);
          return q;
        },
        then: (resolve: (v: unknown) => void) => {
          if (patch) for (const r of rows) Object.assign(r, patch);
          resolve({ data: rows, error: null });
        },
      });
      return q;
    },
  }),
}));
vi.mock("@/lib/ssrf-guard", () => ({ safeFetch: vi.fn() }));

import {
  createHooks,
  emitToOrg,
  queueToEndpoint,
  setHubForTests,
  storedSecret,
  UNROUTED_LIMIT_PER_HOUR,
  type WebhookAlert,
} from "../hub";
import { supabaseStore } from "../supabase-store";

const ORG = "org-1";
// Fixture keys, assembled so no scanner mistakes them for credentials.
const PLAIN_KEY = ["old", "receiver", "key"].join("-");
const WHSEC_TYPED = ["whsec", "typed-by-a-customer"].join("_");

interface Sent {
  url: string;
  headers: Record<string, string>;
  body: string;
}
let sent: Sent[];
let answer: number;

function setup() {
  const db = fakeSupabase();
  const store = supabaseStore(db);
  const fetchImpl = (async (url: string, init: RequestInit) => {
    sent.push({ url: String(url), headers: init.headers as Record<string, string>, body: String(init.body) });
    return new Response(null, { status: answer });
  }) as unknown as typeof fetch;
  const hooks = createHooks(store, { fetchImpl, guard: { lookup: async () => ["93.184.216.34"] } });
  setHubForTests({ hooks, store, client: db });
  return { db, store, hooks };
}

async function endpoint(store: ReturnType<typeof setup>["store"], id: string, over: Record<string, unknown> = {}) {
  await store.insertEndpoint({
    id,
    owner: ORG,
    url: `https://hooks.example.com/${id}`,
    secret: storedSecret(PLAIN_KEY),
    events: ["*"],
    description: "",
    enabled: true,
    failures: 0,
    disabledReason: null,
    createdAt: 1,
    updatedAt: 1,
    ...over,
  });
}

const alert: WebhookAlert = {
  type: "detection.created",
  subject: "detection:det-1",
  legacy: { event: "detection.created", title: "[HIGH] SSH brute force", severity: "high", message: "x", timestamp: "2026-10-28T00:00:00.000Z", url: "https://threatcrush.com/org/acme/detections", detection: { id: "det-1" } },
};

beforeEach(() => {
  sent = [];
  answer = 204;
  appTables.alert_destinations = [];
  appTables.alert_deliveries = [];
});

describe("storedSecret", () => {
  it("keeps a plain secret as typed and re-wraps a typed whsec_ so the key bytes stay the same", () => {
    expect(storedSecret(PLAIN_KEY)).toBe(PLAIN_KEY);
    const wrapped = storedSecret(WHSEC_TYPED);
    expect(wrapped.startsWith("whsec_")).toBe(true);
    expect(Buffer.from(wrapped.slice(6), "base64").toString("utf8")).toBe(WHSEC_TYPED);
  });
});

describe("an old-style receiver", () => {
  for (const [label, typed] of [["a plain secret", PLAIN_KEY], ["a typed whsec_ secret", WHSEC_TYPED]] as const) {
    it(`still verifies X-ThreatCrush-Signature and reads the old body (${label})`, async () => {
      const { store, hooks } = setup();
      await endpoint(store, "wh_a", { secret: storedSecret(typed) });

      const queued = await queueToEndpoint(ORG, "wh_a", alert);
      expect(queued.ok).toBe(true);
      await hooks.drain();

      expect(sent).toHaveLength(1);
      const { headers, body } = sent[0];
      // Exactly what the old sender did: HMAC-SHA256 keyed with the typed string, over the raw body.
      expect(headers["X-ThreatCrush-Signature"]).toBe(`sha256=${createHmac("sha256", typed).update(body).digest("hex")}`);
      expect(headers["content-type"]).toBe("application/json");
      expect(headers["user-agent"]).toBe("ThreatCrush-Alerts/1");
      const parsed = JSON.parse(body);
      expect(parsed).toMatchObject({ event: "detection.created", severity: "high", detection: { id: "det-1" } });
      // ...and it is a CloudEvent with the same alert as data, signed per Standard Webhooks.
      expect(parsed).toMatchObject({ specversion: "1.0", type: "detection.created", subject: "detection:det-1", data: alert.legacy });
      expect(verifySignature({ headers, body, secret: storedSecret(typed) }).ok).toBe(true);
    });
  }

  it("moves the alert_deliveries row from queued to sent, and keeps it queued with the error while retrying", async () => {
    const { store, hooks, db } = setup();
    await endpoint(store, "wh_a");
    const queued = await queueToEndpoint(ORG, "wh_a", alert);
    if (!queued.ok) throw new Error(queued.error);
    appTables.alert_deliveries.push({ id: "ad-1", status: "queued", hub_delivery_id: queued.deliveryId, error: null });
    await hooks.drain();
    expect(appTables.alert_deliveries[0]).toMatchObject({ status: "sent", error: null });

    answer = 500;
    const again = await queueToEndpoint(ORG, "wh_a", alert);
    if (!again.ok) throw new Error(again.error);
    appTables.alert_deliveries.push({ id: "ad-2", status: "queued", hub_delivery_id: again.deliveryId, error: null });
    await hooks.drain();
    expect(appTables.alert_deliveries[1].status).toBe("queued");
    expect(String(appTables.alert_deliveries[1].error)).toContain("retrying");
    expect(db.rows("hub_webhook_deliveries").find((r) => r.id === again.deliveryId)).toMatchObject({ status: "pending", attempts: 1 });
  });
});

describe("queueToEndpoint", () => {
  it("refuses another org's, a switched-off or a non-subscribed endpoint", async () => {
    const { store } = setup();
    await endpoint(store, "wh_off", { enabled: false, disabledReason: "20 failed deliveries in a row" });
    await endpoint(store, "wh_findings", { events: ["findings.*"] });
    expect(await queueToEndpoint("org-2", "wh_off", alert)).toMatchObject({ ok: false });
    expect(await queueToEndpoint(ORG, "wh_off", alert)).toEqual({ ok: false, error: "Webhook endpoint is switched off: 20 failed deliveries in a row" });
    expect(await queueToEndpoint(ORG, "wh_findings", alert)).toMatchObject({ ok: false, error: expect.stringContaining("does not subscribe") });
    expect(await queueToEndpoint(ORG, "wh_gone", alert)).toMatchObject({ ok: false, error: expect.stringContaining("deleted") });
  });
});

describe("emitToOrg", () => {
  it("skips endpoints behind an alert destination (rules route those) and honours event patterns", async () => {
    const { store, db } = setup();
    await endpoint(store, "wh_rule");
    await endpoint(store, "wh_api");
    await endpoint(store, "wh_rep", { events: ["reputation.changed"] });
    appTables.alert_destinations.push({ organization_id: ORG, type: "webhook", config: { hub_endpoint_id: "wh_rule" } });

    expect(await emitToOrg(ORG, [alert])).toBe(1);
    expect(db.rows("hub_webhook_deliveries").map((r) => r.endpoint_id)).toEqual(["wh_api"]);
  });

  it("does not build alerts for an org with no endpoints", async () => {
    setup();
    const build = vi.fn(async () => [alert]);
    expect(await emitToOrg(ORG, build)).toBe(0);
    expect(build).not.toHaveBeenCalled();
  });

  it(`caps an unrouted endpoint at ${UNROUTED_LIMIT_PER_HOUR} an hour`, async () => {
    const { store, db } = setup();
    await endpoint(store, "wh_api");
    expect(await emitToOrg(ORG, Array.from({ length: UNROUTED_LIMIT_PER_HOUR - 1 }, () => alert))).toBe(UNROUTED_LIMIT_PER_HOUR - 1);
    expect(await emitToOrg(ORG, [alert, alert, alert])).toBe(1);
    expect(await emitToOrg(ORG, [alert])).toBe(0);
    expect(db.rows("hub_webhook_deliveries")).toHaveLength(UNROUTED_LIMIT_PER_HOUR);
  });
});
