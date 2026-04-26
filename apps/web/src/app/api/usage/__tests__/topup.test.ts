import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";

const originalEnv = { ...process.env };

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: vi.fn(async () => ({
        data: { user: { id: "user-1", email: "u@example.com" } },
        error: null,
      })),
    },
  }),
  getSupabaseAdmin: () => ({
    from: () => ({
      insert: vi.fn(async () => ({ error: null })),
    }),
  }),
}));

import { POST } from "@/app/api/usage/topup/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/usage/topup", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer valid-token",
    },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/usage/topup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "test-anon-key";
    process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service-key";
    delete process.env.COINPAYPORTAL_API_KEY;
    delete process.env.COINPAYPORTAL_BUSINESS_ID;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("returns 401 without auth token", async () => {
    const req = new Request("http://localhost/api/usage/topup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ amount_usd: 10 }),
    }) as unknown as import("next/server").NextRequest;
    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it("rejects amount below $1", async () => {
    const res = await POST(makeRequest({ amount_usd: 0.5 }));
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.error).toContain("between $1 and $10,000");
  });

  it("rejects amount above $10000", async () => {
    const res = await POST(makeRequest({ amount_usd: 15000 }));
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.error).toContain("between $1 and $10,000");
  });

  it("rejects missing amount_usd", async () => {
    const res = await POST(makeRequest({}));
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.error).toContain("amount_usd required");
  });

  it("rejects invalid currency", async () => {
    const res = await POST(makeRequest({ amount_usd: 10, currency: "card" }));
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.error).toContain("Invalid currency");
  });
});
