import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockUpdatePassword, mockSignOut } = vi.hoisted(() => ({
  mockUpdatePassword: vi.fn(),
  mockSignOut: vi.fn(),
}));

vi.mock("@/lib/supabase", () => ({
  updatePasswordWithAccessToken: mockUpdatePassword,
  getSupabaseClient: () => ({ auth: { admin: { signOut: mockSignOut } } }),
}));

import { POST } from "@/app/api/auth/reset-password/route";

const STRONG = "N3w-passw0rd";

function request(body: unknown, token: string | null = "recovery-token") {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token !== null) headers.Authorization = `Bearer ${token}`;
  return new Request("http://localhost/api/auth/reset-password", {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  }) as unknown as NextRequest;
}

describe("POST /api/auth/reset-password", () => {
  beforeEach(() => {
    mockUpdatePassword.mockReset().mockResolvedValue({ error: null });
    mockSignOut.mockReset().mockResolvedValue({ data: null, error: null });
  });

  it("sets the password as the recovery session's user, then ends all of their sessions", async () => {
    const res = await POST(request({ password: STRONG, confirm_password: STRONG }));

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(mockUpdatePassword).toHaveBeenCalledWith("recovery-token", STRONG);
    expect(mockSignOut).toHaveBeenCalledWith("recovery-token", "global");
  });

  it("still reports success when revoking sessions fails after the password changed", async () => {
    mockSignOut.mockRejectedValue(new Error("network down"));

    const res = await POST(request({ password: STRONG, confirm_password: STRONG }));
    expect(res.status).toBe(200);
  });

  it("answers 401 without a bearer token", async () => {
    const res = await POST(request({ password: STRONG, confirm_password: STRONG }, null));

    expect(res.status).toBe(401);
    expect(mockUpdatePassword).not.toHaveBeenCalled();
  });

  it.each([
    ["an expired or garbage token", 403, "bad_jwt"],
    ["a token whose session was already used up", 403, "session_not_found"],
    ["a token GoTrue refuses outright", 401, "no_authorization"],
  ])("answers 401 for %s", async (_label, status, code) => {
    mockUpdatePassword.mockResolvedValue({ error: { status, code, message: "invalid JWT" } });

    const res = await POST(request({ password: STRONG, confirm_password: STRONG }));

    expect(res.status).toBe(401);
    expect((await res.json()).error).toMatch(/expired/);
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it("rejects a password shorter than the signup minimum with 400 without calling GoTrue", async () => {
    const res = await POST(request({ password: "short12", confirm_password: "short12" }));

    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/at least 8/);
    expect(mockUpdatePassword).not.toHaveBeenCalled();
  });

  it("passes GoTrue's own password-policy rejection back as 400", async () => {
    mockUpdatePassword.mockResolvedValue({
      error: {
        status: 422,
        code: "same_password",
        message: "New password should be different from the old password.",
      },
    });

    const res = await POST(request({ password: STRONG, confirm_password: STRONG }));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "New password should be different from the old password.",
    });
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it("answers 502 when GoTrue fails for another reason", async () => {
    mockUpdatePassword.mockResolvedValue({ error: { status: 500, code: null, message: "boom" } });

    const res = await POST(request({ password: STRONG, confirm_password: STRONG }));
    expect(res.status).toBe(502);
  });

  it.each([
    ["mismatched passwords", { password: STRONG, confirm_password: `${STRONG}x` }],
    ["no confirm_password", { password: STRONG }],
    ["no password", { confirm_password: STRONG }],
    ["a non-string password", { password: 12345678, confirm_password: 12345678 }],
    ["an array body", "[]"],
    ["malformed JSON", "{"],
  ])("rejects %s with 400 without calling GoTrue", async (_label, body) => {
    const res = await POST(request(body));

    expect(res.status).toBe(400);
    expect(mockUpdatePassword).not.toHaveBeenCalled();
  });
});
