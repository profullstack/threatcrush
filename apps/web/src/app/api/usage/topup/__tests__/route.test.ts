import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { NextRequest } from "next/server";

// ─── Mocks ───

// vi.mock factories are hoisted above the imports, so anything they close over
// must be hoisted with them.
const { mockGetUser, mockInsert, mockCreatePayment } = vi.hoisted(() => ({
  mockGetUser: vi.fn(),
  mockInsert: vi.fn(),
  mockCreatePayment: vi.fn(),
}));

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: { getUser: mockGetUser },
  }),
  getSupabaseAdmin: () => ({
    from: () => ({ insert: mockInsert }),
  }),
}));

vi.mock("@/lib/coinpay-client", () => ({
  createCoinpayPayment: mockCreatePayment,
}));

import { POST } from "@/app/api/usage/topup/route";

function makeRequest(body: unknown, headers: Record<string, string> = { Authorization: "Bearer tok-abc" }) {
  return new Request("http://localhost/api/usage/topup", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  }) as unknown as NextRequest;
}

describe("POST /api/usage/topup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue({
      data: { user: { id: "user-123", email: "test@example.com" } },
      error: null,
    });
    mockCreatePayment.mockResolvedValue({
      payment: { id: "cp-1", payment_address: "0xabc", amount_crypto: 50 },
      checkout_url: "https://pay/cp-1",
    });
    mockInsert.mockResolvedValue({ error: null });
    // Top-ups are paused unless the owner turns them on; the validation tests
    // below describe the enabled route.
    vi.stubEnv("USAGE_TOPUPS_ENABLED", "true");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("while top-ups are paused", () => {
    it("refuses with 403 JSON by default, before auth, CoinPay or the deposit row", async () => {
      vi.stubEnv("USAGE_TOPUPS_ENABLED", undefined);

      const res = await POST(makeRequest({ amount_usd: 10, currency: "usdc_sol" }));

      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: expect.any(String) });
      expect(mockGetUser).not.toHaveBeenCalled();
      expect(mockCreatePayment).not.toHaveBeenCalled();
      expect(mockInsert).not.toHaveBeenCalled();
    });

    it("only the exact value \"true\" re-enables them", async () => {
      for (const value of ["", "false", "1", "TRUE", "yes"]) {
        vi.stubEnv("USAGE_TOPUPS_ENABLED", value);
        expect((await POST(makeRequest({ amount_usd: 10, currency: "usdc_sol" }))).status).toBe(403);
      }
      expect(mockCreatePayment).not.toHaveBeenCalled();
      expect(mockInsert).not.toHaveBeenCalled();
    });
  });

  it("returns 401 without an auth token and never creates a payment", async () => {
    const res = await POST(makeRequest({ amount_usd: 10 }, {}));
    expect(res.status).toBe(401);
    expect(mockCreatePayment).not.toHaveBeenCalled();
    expect(mockInsert).not.toHaveBeenCalled();
  });

  it("rejects a missing amount_usd without creating a payment", async () => {
    const res = await POST(makeRequest({ currency: "usdc_sol" }));
    expect(res.status).toBe(400);
    expect(mockCreatePayment).not.toHaveBeenCalled();
    expect(mockInsert).not.toHaveBeenCalled();
  });

  it("rejects a non-numeric amount_usd instead of forwarding a garbage amount", async () => {
    const res = await POST(makeRequest({ amount_usd: "abc", currency: "usdc_sol" }));
    expect(res.status).toBe(400);
    expect(mockCreatePayment).not.toHaveBeenCalled();
    expect(mockInsert).not.toHaveBeenCalled();
  });

  it("rejects out-of-range amounts at both bounds", async () => {
    for (const amount_usd of [0, 0.99, 10000.01, 20000]) {
      expect((await POST(makeRequest({ amount_usd, currency: "usdc_sol" }))).status).toBe(400);
    }
    expect(mockCreatePayment).not.toHaveBeenCalled();
    expect(mockInsert).not.toHaveBeenCalled();
  });

  it("accepts the inclusive bounds $1 and $10,000", async () => {
    for (const amount_usd of [1, 10000]) {
      expect((await POST(makeRequest({ amount_usd, currency: "usdc_sol" }))).status).toBe(200);
    }
    expect(mockCreatePayment).toHaveBeenCalledTimes(2);
  });

  it("rejects an unsupported currency without creating a payment", async () => {
    const res = await POST(makeRequest({ amount_usd: 10, currency: "card" }));
    expect(res.status).toBe(400);
    expect(mockCreatePayment).not.toHaveBeenCalled();
  });

  it("accepts a valid amount and passes a NUMBER to CoinPay and the deposit row", async () => {
    const res = await POST(makeRequest({ amount_usd: 50, currency: "usdc_sol" }));
    expect(res.status).toBe(200);
    expect(mockCreatePayment).toHaveBeenCalledWith(expect.objectContaining({ amount_usd: 50 }));
    expect(mockInsert).toHaveBeenCalledWith(expect.objectContaining({ amount_usd: 50 }));
  });

  it("coerces a numeric string to a number", async () => {
    const res = await POST(makeRequest({ amount_usd: "50", currency: "usdc_sol" }));
    expect(res.status).toBe(200);
    expect(mockCreatePayment).toHaveBeenCalledWith(expect.objectContaining({ amount_usd: 50 }));
    expect(mockInsert).toHaveBeenCalledWith(expect.objectContaining({ amount_usd: 50 }));
  });
});
