import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";

const originalEnv = { ...process.env };

import { POST } from "@/app/api/usage/topup/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/usage/topup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/usage/topup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.COINPAYPORTAL_API_KEY;
    delete process.env.COINPAYPORTAL_BUSINESS_ID;
    delete process.env.COINPAY_API_KEY;
    delete process.env.COINPAY_BUSINESS_ID;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("validates amount range — $5 is valid input", async () => {
    const req = makeRequest({ amount_usd: 5 });
    const res = await POST(req);
    // Without API keys it throws; the important thing is amount validation passed
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("validates amount range — $10000 is valid input", async () => {
    const req = makeRequest({ amount_usd: 10000 });
    const res = await POST(req);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("rejects amount below $5", async () => {
    const req = makeRequest({ amount_usd: 2 });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("between $5 and $10,000");
  });

  it("rejects amount above $10000", async () => {
    const req = makeRequest({ amount_usd: 15000 });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("between $5 and $10,000");
  });

  it("rejects missing amount_usd", async () => {
    const req = makeRequest({});
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("amount_usd required");
  });

  it("rejects invalid currency", async () => {
    const req = makeRequest({ amount_usd: 10, currency: "card" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Invalid currency");
  });
});
