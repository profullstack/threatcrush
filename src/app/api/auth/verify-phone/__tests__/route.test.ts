import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock chain ───

const mockUpdate = vi.fn();
const mockUpdateEq = vi.fn();

function resetMocks(overrides: {
  updateResult?: { error: unknown };
} = {}) {
  const updateResult = overrides.updateResult ?? { error: null };
  mockUpdateEq.mockResolvedValue(updateResult);
  mockUpdate.mockReturnValue({ eq: mockUpdateEq });
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      update: mockUpdate,
    }),
  }),
}));

import { POST } from "@/app/api/auth/verify-phone/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/auth/verify-phone", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/auth/verify-phone", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetMocks();
  });

  it("accepts valid 6-digit code", async () => {
    const req = makeRequest({ phone: "+1234567890", code: "123456", user_id: "user-123" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.verified).toBe(true);
    expect(mockUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ phone_verified: true })
    );
  });

  it("rejects non-6-digit code", async () => {
    const req = makeRequest({ phone: "+1234567890", code: "12345", user_id: "user-123" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("6 digits");
  });

  it("rejects missing phone", async () => {
    const req = makeRequest({ code: "123456", user_id: "user-123" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBeDefined();
  });

  it("rejects missing code", async () => {
    const req = makeRequest({ phone: "+1234567890", user_id: "user-123" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBeDefined();
  });

  it("rejects missing user_id", async () => {
    const req = makeRequest({ phone: "+1234567890", code: "123456" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBeDefined();
  });

  it("handles database error", async () => {
    resetMocks({ updateResult: { error: { message: "DB error" } } });

    const req = makeRequest({ phone: "+1234567890", code: "123456", user_id: "user-123" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(500);
    expect(body.error).toContain("Failed to verify phone");
  });

  it("response shape matches contract", async () => {
    const req = makeRequest({ phone: "+1234567890", code: "123456", user_id: "user-123" });
    const res = await POST(req);
    const body = await res.json();

    expect(body).toEqual({ verified: true });
  });
});
