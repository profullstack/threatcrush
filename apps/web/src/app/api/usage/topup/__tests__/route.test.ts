import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mocks ───

const mockGetUser = vi.fn();
const mockInsert = vi.fn();
const mockCreatePayment = vi.fn();

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

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/usage/topup", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer tok-abc" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
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
  });

  it("rejects a non-numeric amount_usd instead of forwarding a garbage amount", async () => {
    const res = await POST(makeRequest({ amount_usd: "abc", currency: "usdc_sol" }));
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.error).toContain("between $1 and $10,000");
    expect(mockCreatePayment).not.toHaveBeenCalled();
    expect(mockInsert).not.toHaveBeenCalled();
  });

  it("rejects out-of-range amounts", async () => {
    expect((await POST(makeRequest({ amount_usd: 0, currency: "usdc_sol" }))).status).toBe(400);
    expect((await POST(makeRequest({ amount_usd: 20000, currency: "usdc_sol" }))).status).toBe(400);
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
  });
});
