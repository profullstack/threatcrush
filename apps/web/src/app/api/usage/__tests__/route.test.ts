import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";

const originalEnv = { ...process.env };

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: vi.fn(async () => ({ data: { user: null }, error: { message: "no token" } })),
    },
  }),
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({
        eq: () => ({
          in: () => Promise.resolve({ data: [], error: null }),
          gte: () => ({
            order: () => ({ limit: () => Promise.resolve({ data: [], error: null }) }),
          }),
          order: () => ({ limit: () => Promise.resolve({ data: [], error: null }) }),
        }),
      }),
    }),
  }),
}));

import { GET } from "@/app/api/usage/route";

function makeRequest(opts: { token?: string } = {}) {
  const url = "http://localhost/api/usage";
  const headers: Record<string, string> = {};
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const req = new Request(url, { headers });
  (req as unknown as Record<string, unknown>).nextUrl = new URL(url);
  return req as unknown as import("next/server").NextRequest;
}

describe("GET /api/usage", () => {
  beforeEach(() => {
    vi.resetModules();
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "test-anon-key";
    process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service-key";
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("returns 401 when no auth token provided", async () => {
    const res = await GET(makeRequest());
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toContain("Not authenticated");
  });

  it("returns 401 when token is invalid", async () => {
    const res = await GET(makeRequest({ token: "bogus-token" }));
    expect(res.status).toBe(401);
  });
});
