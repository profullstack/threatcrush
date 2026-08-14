import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHmac } from "node:crypto";

// ─── Mock setup ───
// The coinpay route creates its own supabase client via createClient directly.
// Chain patterns used:
//   .from("funding_payments").select("id").eq("coinpay_payment_id", paymentId).maybeSingle()
//   .from("funding_payments").update({...}).eq("coinpay_payment_id", paymentId)  ← awaited
//   .from("waitlist").select("id, email, paid").eq("payment_id", paymentId).maybeSingle()
//   .from("waitlist").update({...}).eq("id", entry.id)       ← awaited directly
//   .from("waitlist").select("referred_by").eq("id", entry.id).single()
//   .from("waitlist").update({amount_usd:399}).eq("referral_code",...).eq("paid",false)  ← awaited

const mockFundingMaybeSingle = vi.fn();
const mockLicenseMaybeSingle = vi.fn();
const mockCreditMaybeSingle = vi.fn();
const mockWaitlistMaybeSingle = vi.fn();
const mockWaitlistSingle = vi.fn();

// Build a chainable mock for a specific table
function buildTableMock(table: string) {
  if (table === "funding_payments") {
    const chainableEq = () => ({
      eq: vi.fn().mockImplementation(() => chainableEq()),
      maybeSingle: mockFundingMaybeSingle,
      then: (resolve: (v: unknown) => void) => resolve({ error: null }),
    });
    return {
      select: vi.fn().mockImplementation(() => chainableEq()),
      update: vi.fn().mockImplementation(() => chainableEq()),
    };
  }
  if (table === "license_purchases") {
    const chainableEq = () => ({
      eq: vi.fn().mockImplementation(() => chainableEq()),
      maybeSingle: mockLicenseMaybeSingle,
      then: (resolve: (v: unknown) => void) => resolve({ error: null }),
    });
    return {
      select: vi.fn().mockImplementation(() => chainableEq()),
      update: vi.fn().mockImplementation(() => chainableEq()),
    };
  }
  if (table === "credit_deposits") {
    const chainableEq = () => ({
      eq: vi.fn().mockImplementation(() => chainableEq()),
      maybeSingle: mockCreditMaybeSingle,
      then: (resolve: (v: unknown) => void) => resolve({ error: null }),
    });
    return {
      select: vi.fn().mockImplementation(() => chainableEq()),
      update: vi.fn().mockImplementation(() => chainableEq()),
    };
  }
  // waitlist table
  const chainableEq = () => ({
    eq: vi.fn().mockImplementation(() => chainableEq()),
    maybeSingle: mockWaitlistMaybeSingle,
    single: mockWaitlistSingle,
    then: (resolve: (v: unknown) => void) => resolve({ error: null }),
  });
  return {
    select: vi.fn().mockImplementation(() => chainableEq()),
    update: vi.fn().mockImplementation(() => chainableEq()),
  };
}

function resetMocks(overrides: {
  findEntryResult?: { data: unknown; error: unknown };
  referralResult?: { data: unknown; error: unknown };
} = {}) {
  const findEntryResult = overrides.findEntryResult ?? {
    data: { id: "wl-001", email: "user@example.com", paid: false },
    error: null,
  };
  const referralResult = overrides.referralResult ?? {
    data: { referred_by: "REF123" },
    error: null,
  };

  mockFundingMaybeSingle.mockResolvedValue({ data: null, error: null });
  mockLicenseMaybeSingle.mockResolvedValue({ data: null, error: null });
  mockCreditMaybeSingle.mockResolvedValue({ data: null, error: null });
  mockWaitlistMaybeSingle.mockResolvedValue(findEntryResult);
  mockWaitlistSingle.mockResolvedValue(referralResult);
}

vi.mock("@supabase/supabase-js", () => ({
  createClient: () => ({
    from: (table: string) => buildTableMock(table),
  }),
}));

import { POST } from "@/app/api/webhooks/coinpay/route";

const WEBHOOK_SECRET = "test-webhook-secret";

/**
 * Real signature, not a mocked verifier: TC-09 was specifically about a branch
 * that skipped this check, so the tests should exercise the genuine one.
 */
function signBody(rawBody: string): string {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const sig = createHmac("sha256", WEBHOOK_SECRET)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");
  return `t=${timestamp},v1=${sig}`;
}

function makeRequest(body: unknown, opts: { signed?: boolean } = {}) {
  const rawBody = JSON.stringify(body);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.signed !== false) headers["x-coinpay-signature"] = signBody(rawBody);

  return new Request("http://localhost/api/webhooks/coinpay", {
    method: "POST",
    headers,
    body: rawBody,
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/webhooks/coinpay", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.COINPAY_WEBHOOK_SECRET = WEBHOOK_SECRET;
    resetMocks();
  });

  it("handles payment.confirmed event", async () => {
    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.email).toBe("user@example.com");
  });

  // TC-09: the waitlist branch used to be reachable with no signature at all,
  // so anyone who knew a payment id could mark a waitlist row paid.
  it("rejects an unsigned waitlist callback", async () => {
    const req = makeRequest(
      { type: "payment.confirmed", data: { payment_id: "pay-001", status: "confirmed" } },
      { signed: false },
    );
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Invalid signature");
  });

  it("rejects a waitlist callback with a forged signature", async () => {
    const rawBody = JSON.stringify({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const req = new Request("http://localhost/api/webhooks/coinpay", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-coinpay-signature": `t=${Math.floor(Date.now() / 1000)},v1=${"00".repeat(32)}`,
      },
      body: rawBody,
    }) as unknown as import("next/server").NextRequest;

    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it("rejects missing payment_id", async () => {
    const req = makeRequest({ type: "payment.confirmed", data: {} });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Missing payment_id");
  });

  it("ignores non-confirmed events", async () => {
    const req = makeRequest({
      type: "payment.pending",
      data: { payment_id: "pay-001", status: "pending" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.email).toBeUndefined();
  });

  it("skips already-paid entries", async () => {
    resetMocks({
      findEntryResult: {
        data: { id: "wl-001", email: "user@example.com", paid: true },
        error: null,
      },
    });

    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
  });

  it("handles missing waitlist entry gracefully", async () => {
    resetMocks({
      findEntryResult: { data: null, error: null },
    });

    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-999", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
  });

  it("processes forwarded status", async () => {
    const req = makeRequest({
      type: "payment.forwarded",
      data: { payment_id: "pay-001", status: "forwarded" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.email).toBe("user@example.com");
  });

  it("response shape matches contract", async () => {
    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(body).toEqual(
      expect.objectContaining({
        ok: true,
      })
    );
  });
});
