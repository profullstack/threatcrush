import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock chain ───

const mockSignIn = vi.fn();
const mockProfileSingle = vi.fn();
const mockProfileEq = vi.fn();
const mockProfileSelect = vi.fn();

function resetMocks(overrides: {
  signInResult?: { data: unknown; error: unknown };
  profileResult?: { data: unknown; error: unknown };
} = {}) {
  const signInResult = overrides.signInResult ?? {
    data: {
      user: { id: "user-123", email: "test@example.com" },
      session: { access_token: "tok-abc" },
    },
    error: null,
  };
  const profileResult = overrides.profileResult ?? {
    data: { email_verified: true, phone_verified: false },
    error: null,
  };

  mockSignIn.mockResolvedValue(signInResult);
  mockProfileSingle.mockResolvedValue(profileResult);
  mockProfileEq.mockReturnValue({ single: mockProfileSingle });
  mockProfileSelect.mockReturnValue({ eq: mockProfileEq });
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      signInWithPassword: mockSignIn,
    },
  }),
  getSupabaseAdmin: () => ({
    from: () => ({
      select: mockProfileSelect,
    }),
  }),
}));

import { POST } from "@/app/api/auth/login/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/auth/login", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetMocks();
  });

  it("logs in with valid credentials", async () => {
    const req = makeRequest({ email: "test@example.com", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.user).toBeDefined();
    expect(body.user.id).toBe("user-123");
    expect(body.session).toBeDefined();
    expect(body.session.access_token).toBe("tok-abc");
    expect(body.verified).toEqual({ email: true, phone: false });
  });

  it("rejects wrong password (401)", async () => {
    resetMocks({
      signInResult: {
        data: { user: null, session: null },
        error: { message: "Invalid login credentials" },
      },
    });

    const req = makeRequest({ email: "test@example.com", password: "wrongpass" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Invalid login credentials");
  });

  it("rejects missing email", async () => {
    const req = makeRequest({ password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Email and password are required");
  });

  it("rejects missing password", async () => {
    const req = makeRequest({ email: "test@example.com" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Email and password are required");
  });

  it("response shape matches contract", async () => {
    const req = makeRequest({ email: "test@example.com", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(body).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({ id: expect.any(String) }),
        session: expect.objectContaining({ access_token: expect.any(String) }),
        verified: expect.objectContaining({
          email: expect.any(Boolean),
          phone: expect.any(Boolean),
        }),
      })
    );
  });
});
