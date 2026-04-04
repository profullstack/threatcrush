import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock chain ───

const mockSelect = vi.fn();
const mockUpdate = vi.fn();
const mockEq = vi.fn();
const mockMaybeSingle = vi.fn();
const mockSingle = vi.fn();
const mockUpdateEq = vi.fn();

function resetMocks(overrides: {
  waitlistResult?: { data: unknown; error: unknown };
  referralResult?: { data: unknown; error: unknown };
} = {}) {
  const waitlistResult = overrides.waitlistResult ?? {
    data: { id: "wl-001", email: "user@example.com", paid: false },
    error: null,
  };
  const referralResult = overrides.referralResult ?? {
    data: { referred_by: "REF123" },
    error: null,
  };

  mockMaybeSingle.mockResolvedValue(waitlistResult);
  mockSingle.mockResolvedValue(referralResult);
  mockEq.mockReturnValue({ maybeSingle: mockMaybeSingle, eq: mockEq, single: mockSingle });
  mockSelect.mockReturnValue({ eq: mockEq });
  mockUpdateEq.mockResolvedValue({ error: null });
  mockUpdate.mockReturnValue({ eq: mockUpdateEq });
}

// Mock createClient from @supabase/supabase-js (used directly in this route)
vi.mock("@supabase/supabase-js", () => ({
  createClient: () => ({
    from: () => ({
      select: mockSelect,
      update: mockUpdate,
    }),
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
    expect(mockUpdate).toHaveBeenCalled();
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
      waitlistResult: {
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
      waitlistResult: { data: null, error: null },
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

  it("updates referral pricing when referred_by exists", async () => {
    resetMocks({
      referralResult: { data: { referred_by: "REF123" }, error: null },
    });

    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const res = await POST(req);

    expect(res.status).toBe(200);
    // update is called for marking paid AND for referral pricing
    expect(mockUpdate).toHaveBeenCalled();
  });

  it("response shape matches contract (ok event)", async () => {
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
