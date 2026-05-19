import { describe, it, expect, vi, beforeEach } from "vitest";

const mockGetUser = vi.fn();
const mockSync = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: { getUser: mockGetUser },
  }),
}));

vi.mock("@/lib/auth-sync", () => ({
  syncEmailVerifiedIfConfirmed: (...args: unknown[]) => mockSync(...args),
}));

import { POST } from "@/app/api/auth/sync-verified/route";

function makeRequest(token?: string) {
  const headers: Record<string, string> = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  return new Request("http://localhost/api/auth/sync-verified", {
    method: "POST",
    headers,
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/auth/sync-verified", () => {
  beforeEach(() => {
    mockGetUser.mockReset();
    mockSync.mockReset();
  });

  it("returns 401 without a bearer token", async () => {
    const res = await POST(makeRequest());
    expect(res.status).toBe(401);
  });

  it("returns 401 when the token doesn't resolve to a user", async () => {
    mockGetUser.mockResolvedValue({ data: { user: null }, error: null });
    const res = await POST(makeRequest("bad"));
    expect(res.status).toBe(401);
  });

  it("syncs and returns email_verified=true when confirmed", async () => {
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-abc" } }, error: null });
    mockSync.mockResolvedValue(true);

    const res = await POST(makeRequest("good"));
    const body = await res.json();

    expect(mockSync).toHaveBeenCalledWith("user-abc");
    expect(res.status).toBe(200);
    expect(body.email_verified).toBe(true);
  });

  it("returns email_verified=false when auth user isn't confirmed yet", async () => {
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-abc" } }, error: null });
    mockSync.mockResolvedValue(false);

    const res = await POST(makeRequest("good"));
    const body = await res.json();

    expect(body.email_verified).toBe(false);
  });
});
