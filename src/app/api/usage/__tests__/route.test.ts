import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";

const originalEnv = { ...process.env };

vi.mock("@/lib/supabase", () => ({}));

import { GET } from "@/app/api/usage/route";

function makeRequest(email?: string) {
  const url = email
    ? `http://localhost/api/usage?email=${encodeURIComponent(email)}`
    : "http://localhost/api/usage";
  const req = new Request(url);
  const parsedUrl = new URL(url);
  (req as unknown as Record<string, unknown>).nextUrl = parsedUrl;
  return req as unknown as import("next/server").NextRequest;
}

describe("GET /api/usage", () => {
  beforeEach(() => {
    vi.resetModules();
    delete process.env.COINPAYPORTAL_API_KEY;
    delete process.env.COINPAYPORTAL_BUSINESS_ID;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("returns 503 when no API key configured", async () => {
    const { GET: freshGet } = await import("@/app/api/usage/route");
    const req = makeRequest("test@example.com");
    const res = await freshGet(req);

    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toContain("not configured");
  });

  it("returns 400 when email missing", async () => {
    const { GET: freshGet } = await import("@/app/api/usage/route");
    const req = makeRequest();
    const res = await freshGet(req);

    expect(res.status).toBe(400);
  });
});
