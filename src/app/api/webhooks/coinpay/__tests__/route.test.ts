import { describe, it, expect, vi, beforeEach } from "vitest";

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
const mockWaitlistMaybeSingle = vi.fn();
const mockWaitlistSingle = vi.fn();

// Build a chainable mock for a specific table
function buildTableMock(table: string) {
  if (table === "funding_payments") {
    const chainableEq = () => ({
      eq: vi.fn().mockImplementation(() => chainableEq()),
      maybeSingle: mockFundingMaybeSingle,
      // When update().eq() is awaited directly (no terminal), it resolves
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
    // When update().eq() is awaited directly (no terminal), it resolves
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

  // funding_payments returns null so route falls through to waitlist
  mockFundingMaybeSingle.mockResolvedValue({ data: null, error: null });
  mockWaitlistMaybeSingle.mockResolvedValue(findEntryResult);
  mockWaitlistSingle.mockResolvedValue(referralResult);
}

vi.mock("@supabase/supabase-js", () => ({
  createClient: () => ({
    from: (table: string) => buildTableMock(table),
  }),
}));

import { POST } from "@/app/api/webhooks/coinpay/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/webhooks/coinpay", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/webhooks/coinpay", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
