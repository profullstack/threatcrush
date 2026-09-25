import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mockRefresh = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({ auth: { refreshSession: mockRefresh } }),
}));

import { POST } from "@/app/api/auth/refresh/route";

function request(body: unknown) {
  return new Request("http://localhost/api/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  }) as unknown as NextRequest;
}

describe("POST /api/auth/refresh", () => {
  beforeEach(() => {
    mockRefresh.mockReset();
  });

  it("returns the rotated session for a valid refresh token", async () => {
    mockRefresh.mockResolvedValue({
      data: {
        session: {
          access_token: "access-2",
          refresh_token: "refresh-2",
          expires_at: 1_900_000_000,
          user: { id: "user-1", email: "a@example.com" },
        },
      },
      error: null,
    });

    const res = await POST(request({ refresh_token: "refresh-1" }));

    expect(res.status).toBe(200);
    expect(mockRefresh).toHaveBeenCalledWith({ refresh_token: "refresh-1" });
    expect(await res.json()).toEqual({
      session: { access_token: "access-2", refresh_token: "refresh-2", expires_at: 1_900_000_000 },
      user: { id: "user-1", email: "a@example.com" },
    });
  });

  it("answers 401 when Supabase rejects the refresh token", async () => {
    mockRefresh.mockResolvedValue({
      data: { session: null },
      error: { message: "Invalid Refresh Token: Already Used" },
    });

    const res = await POST(request({ refresh_token: "reused" }));
    expect(res.status).toBe(401);
  });

  it.each([
    ["no refresh_token", {}],
    ["an empty refresh_token", { refresh_token: "" }],
    ["a non-string refresh_token", { refresh_token: 42 }],
    ["an array body", "[]"],
    ["malformed JSON", "{"],
  ])("rejects %s with 400 without calling Supabase", async (_label, body) => {
    const res = await POST(request(body));
    expect(res.status).toBe(400);
    expect(mockRefresh).not.toHaveBeenCalled();
  });
});
