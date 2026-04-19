import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock chain ───

const mockGetUser = vi.fn();
const mockGetSession = vi.fn();
const mockAdminSelect = vi.fn();
const mockAdminEq = vi.fn();
const mockAdminSingle = vi.fn();

function resetMocks(overrides: {
  getUserResult?: { data: { user: unknown }; error?: unknown };
  getSessionResult?: { data: { session: unknown }; error?: unknown };
  profileResult?: { data: unknown; error: unknown };
} = {}) {
  const getUserResult = overrides.getUserResult ?? {
    data: { user: { id: "user-123" } },
  };
  const getSessionResult = overrides.getSessionResult ?? {
    data: { session: null },
  };
  const profileResult = overrides.profileResult ?? {
    data: { email_verified: true, phone_verified: true, license_status: "active" },
    error: null,
  };

  mockGetUser.mockResolvedValue(getUserResult);
  mockGetSession.mockResolvedValue(getSessionResult);
  mockAdminSingle.mockResolvedValue(profileResult);
  mockAdminEq.mockReturnValue({ single: mockAdminSingle });
  mockAdminSelect.mockReturnValue({ eq: mockAdminEq });
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: mockGetUser,
      getSession: mockGetSession,
    },
  }),
  getSupabaseAdmin: () => ({
    from: () => ({
      select: mockAdminSelect,
    }),
  }),
}));

import { GET } from "@/app/api/auth/check/route";

function makeRequest(token?: string, searchParams?: Record<string, string>) {
  const headers: Record<string, string> = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  const params = new URLSearchParams(searchParams).toString();
  const url = params
    ? `http://localhost/api/auth/check?${params}`
    : "http://localhost/api/auth/check";
  const req = new Request(url, { headers }) as unknown as import("next/server").NextRequest;
  // Next.js adds nextUrl from the URL
  (req as unknown as Record<string, unknown>).nextUrl = new URL(url);
  return req;
}

describe("GET /api/auth/check", () => {
  beforeEach(() => {
    resetMocks();
  });

  it("returns verification status", async () => {
    const req = makeRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.email_verified).toBe(true);
    expect(body.phone_verified).toBe(true);
    expect(body.license_status).toBe("active");
  });

  it("returns can_proceed_to_payment = true when both verified", async () => {
    resetMocks({
      profileResult: {
        data: { email_verified: true, phone_verified: true, license_status: "active" },
        error: null,
      },
    });

    const req = makeRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(body.can_proceed_to_payment).toBe(true);
  });

  it("returns can_proceed_to_payment = false when email not verified", async () => {
    resetMocks({
      profileResult: {
        data: { email_verified: false, phone_verified: true, license_status: null },
        error: null,
      },
    });

    const req = makeRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(body.can_proceed_to_payment).toBe(false);
    expect(body.email_verified).toBe(false);
  });

  it("returns can_proceed_to_payment = false when phone not verified", async () => {
    resetMocks({
      profileResult: {
        data: { email_verified: true, phone_verified: false, license_status: null },
        error: null,
      },
    });

    const req = makeRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(body.can_proceed_to_payment).toBe(false);
    expect(body.phone_verified).toBe(false);
  });

  it("returns 401 without auth", async () => {
    resetMocks({
      getUserResult: { data: { user: null } },
      getSessionResult: { data: { session: null } },
    });

    const req = makeRequest();
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Not authenticated");
  });

  it("response shape matches contract", async () => {
    const req = makeRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(body).toEqual(
      expect.objectContaining({
        email_verified: expect.any(Boolean),
        phone_verified: expect.any(Boolean),
        can_proceed_to_payment: expect.any(Boolean),
      })
    );
  });
});
