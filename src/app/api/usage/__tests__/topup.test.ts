import { describe, it, expect, vi, beforeEach } from "vitest";

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
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("validates amount range — $5 is valid input", async () => {
    // Returns 503 because API keys aren't set, but the amount validation passed
    const req = makeRequest({ email: "user@example.com", amount_usd: 5 });
    const res = await POST(req);

    expect(res.status).toBe(503);
  });

  it("validates amount range — $1000 is valid input", async () => {
    const req = makeRequest({ email: "user@example.com", amount_usd: 1000 });
    const res = await POST(req);

    expect(res.status).toBe(503);
  });

  it("rejects amount below $5", async () => {
    const req = makeRequest({ email: "user@example.com", amount_usd: 2 });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("between $5 and $1,000");
  });

  it("rejects amount above $1000", async () => {
    const req = makeRequest({ email: "user@example.com", amount_usd: 1500 });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("between $5 and $1,000");
  });

  it("rejects missing email", async () => {
    const req = makeRequest({ amount_usd: 10 });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("email and amount_usd required");
  });

  it("rejects missing amount_usd", async () => {
    const req = makeRequest({ email: "user@example.com" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("email and amount_usd required");
  });

  it("returns 503 when no API key configured", async () => {
    const req = makeRequest({ email: "user@example.com", amount_usd: 25 });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(503);
    expect(body.error).toContain("not available");
  });
});
