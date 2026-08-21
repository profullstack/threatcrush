import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createHmac } from "node:crypto";

const originalEnv = { ...process.env };

const SECRET = "test-marketplace-secret";

/**
 * In-memory stand-in for the two tables. `state` is reset per test so the
 * dedupe and out-of-order cases can set up their own starting point.
 */
const state = {
  existingPurchase: null as { id: string; effective_date: string | null } | null,
  eventInsertReturns: [{ id: "event-1" }] as { id: string }[],
  upsertedPurchases: [] as Record<string, unknown>[],
  eventUpdates: [] as Record<string, unknown>[],
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "github_marketplace_events") {
        return {
          upsert: () => ({
            select: async () => ({ data: state.eventInsertReturns, error: null }),
          }),
          update: (patch: Record<string, unknown>) => {
            state.eventUpdates.push(patch);
            return { eq: async () => ({ error: null }) };
          },
        };
      }
      // github_marketplace_purchases
      return {
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({ data: state.existingPurchase, error: null }),
          }),
        }),
        upsert: async (row: Record<string, unknown>) => {
          state.upsertedPurchases.push(row);
          return { error: null };
        },
      };
    },
  }),
}));

import { POST, GET } from "@/app/api/webhooks/github/marketplace/route";

const PAYLOAD = {
  action: "purchased",
  effective_date: "2026-08-21T00:00:00+00:00",
  sender: { login: "octocat" },
  marketplace_purchase: {
    account: { type: "Organization", id: 18404712, login: "acme-corp" },
    billing_cycle: "monthly",
    unit_count: 1,
    on_free_trial: false,
    next_billing_date: "2026-09-21T00:00:00+00:00",
    plan: { id: 435, name: "Pro Plan", monthly_price_in_cents: 999 },
  },
};

function makeRequest(
  body: string,
  {
    signature,
    event = "marketplace_purchase",
    delivery = "delivery-1",
    contentType = "application/json",
  }: {
    signature?: string | null;
    event?: string;
    delivery?: string | null;
    contentType?: string;
  } = {},
) {
  const headers: Record<string, string> = { "Content-Type": contentType };
  const sig =
    signature === undefined
      ? `sha256=${createHmac("sha256", SECRET).update(body, "utf8").digest("hex")}`
      : signature;
  if (sig) headers["X-Hub-Signature-256"] = sig;
  if (event) headers["X-GitHub-Event"] = event;
  if (delivery) headers["X-GitHub-Delivery"] = delivery;

  return new Request("http://localhost/api/webhooks/github/marketplace", {
    method: "POST",
    headers,
    body,
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/webhooks/github/marketplace", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    state.existingPurchase = null;
    state.eventInsertReturns = [{ id: "event-1" }];
    state.upsertedPurchases = [];
    state.eventUpdates = [];
    process.env.GITHUB_MARKETPLACE_WEBHOOK_SECRET = SECRET;
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
    process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service-key";
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("accepts and applies a correctly signed purchase", async () => {
    const body = JSON.stringify(PAYLOAD);
    const res = await POST(makeRequest(body));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ received: true, applied: true });
    expect(state.upsertedPurchases).toHaveLength(1);
    expect(state.upsertedPurchases[0]).toMatchObject({
      github_account_id: 18404712,
      plan_name: "Pro Plan",
      status: "active",
    });
  });

  it("rejects an unsigned delivery with 401 and writes nothing", async () => {
    const res = await POST(makeRequest(JSON.stringify(PAYLOAD), { signature: null }));
    expect(res.status).toBe(401);
    expect(state.upsertedPurchases).toHaveLength(0);
  });

  it("rejects a delivery signed with the wrong secret", async () => {
    const body = JSON.stringify(PAYLOAD);
    const wrong = `sha256=${createHmac("sha256", "not-the-secret").update(body).digest("hex")}`;
    const res = await POST(makeRequest(body, { signature: wrong }));
    expect(res.status).toBe(401);
    expect(state.upsertedPurchases).toHaveLength(0);
  });

  it("rejects a body altered after signing", async () => {
    const body = JSON.stringify(PAYLOAD);
    const signature = `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`;
    const tampered = JSON.stringify({ ...PAYLOAD, action: "cancelled" });
    const res = await POST(makeRequest(tampered, { signature }));
    expect(res.status).toBe(401);
    expect(state.upsertedPurchases).toHaveLength(0);
  });

  it("refuses with 503 when no secret is configured, rather than accepting", async () => {
    delete process.env.GITHUB_MARKETPLACE_WEBHOOK_SECRET;
    const res = await POST(makeRequest(JSON.stringify(PAYLOAD)));
    expect(res.status).toBe(503);
    expect(state.upsertedPurchases).toHaveLength(0);
  });

  it("answers the ping GitHub sends when the hook is saved", async () => {
    const body = JSON.stringify({ zen: "Keep it logically awesome." });
    const res = await POST(makeRequest(body, { event: "ping" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ pong: true });
  });

  it("ignores a signed event that is not marketplace_purchase", async () => {
    const body = JSON.stringify(PAYLOAD);
    const res = await POST(makeRequest(body, { event: "installation" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ignored: "installation" });
    expect(state.upsertedPurchases).toHaveLength(0);
  });

  it("treats a repeated delivery id as a duplicate and does not re-apply it", async () => {
    // ignoreDuplicates means the upsert returns no row for a delivery we
    // have already seen.
    state.eventInsertReturns = [];
    const res = await POST(makeRequest(JSON.stringify(PAYLOAD)));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ duplicate: true });
    expect(state.upsertedPurchases).toHaveLength(0);
  });

  it("does not let an older event overwrite newer state", async () => {
    state.existingPurchase = { id: "p1", effective_date: "2026-09-01T00:00:00.000Z" };
    const stale = { ...PAYLOAD, effective_date: "2026-08-01T00:00:00+00:00" };
    const res = await POST(makeRequest(JSON.stringify(stale)));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ stale: true, applied: false });
    expect(state.upsertedPurchases).toHaveLength(0);
    expect(state.eventUpdates[0]).toMatchObject({ applied: false });
  });

  it("accepts the urlencoded content type as well", async () => {
    const body = `payload=${encodeURIComponent(JSON.stringify(PAYLOAD))}`;
    const res = await POST(
      makeRequest(body, { contentType: "application/x-www-form-urlencoded" }),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ applied: true });
  });

  it("ignores an unknown action without failing the delivery", async () => {
    const body = JSON.stringify({ ...PAYLOAD, action: "exploded" });
    const res = await POST(makeRequest(body));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ignored: "exploded" });
    expect(state.upsertedPurchases).toHaveLength(0);
  });
});

describe("GET /api/webhooks/github/marketplace", () => {
  it("reports configuration without leaking the secret", async () => {
    process.env.GITHUB_MARKETPLACE_WEBHOOK_SECRET = SECRET;
    const res = await GET();
    const body = await res.json();
    expect(body.configured).toBe(true);
    expect(JSON.stringify(body)).not.toContain(SECRET);
  });
});
