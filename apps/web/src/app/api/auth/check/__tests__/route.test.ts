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
    data: {
      id: "user-123",
      email_verified: true,
      phone_verified: true,
      license_status: "active",
    },
    error: null,
  };

  mockGetUser.mockResolvedValue(getUserResult);
  mockGetSession.mockResolvedValue(getSessionResult);
  mockAdminSingle.mockResolvedValue(profileResult);
  mockAdminEq.mockReturnValue({ single: mockAdminSingle, eq: mockAdminEq });
  mockAdminSelect.mockReturnValue({ eq: mockAdminEq });
}

const mockSyncEmailVerified = vi.fn();

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

vi.mock("@/lib/auth-sync", () => ({
  syncEmailVerifiedIfConfirmed: (...args: unknown[]) => mockSyncEmailVerified(...args),
}));

import { NextRequest } from "next/server";
import { GET } from "@/app/api/auth/check/route";
import { issueSignupGrant, SIGNUP_GRANT_COOKIE } from "@/lib/signup-grant";

function makeRequest(
  token?: string,
  opts: { searchParams?: Record<string, string>; grantCookie?: string } = {},
) {
  const headers: Record<string, string> = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  if (opts.grantCookie) headers["cookie"] = `${SIGNUP_GRANT_COOKIE}=${opts.grantCookie}`;
  const params = new URLSearchParams(opts.searchParams).toString();
  const url = params
    ? `http://localhost/api/auth/check?${params}`
    : "http://localhost/api/auth/check";
  // A real NextRequest, not a cast Request: the route reads req.cookies.
  return new NextRequest(url, { headers });
}

describe("GET /api/auth/check", () => {
  beforeEach(() => {
    resetMocks();
    mockSyncEmailVerified.mockReset();
    mockSyncEmailVerified.mockResolvedValue(false);
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
        data: {
          id: "user-123",
          email_verified: false,
          phone_verified: true,
          license_status: null,
        },
        error: null,
      },
    });

    const req = makeRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(body.can_proceed_to_payment).toBe(false);
    expect(body.email_verified).toBe(false);
  });

  it("self-heals email_verified when auth.users is confirmed but profile lags", async () => {
    resetMocks({
      profileResult: {
        data: {
          id: "user-123",
          email_verified: false,
          phone_verified: true,
          license_status: null,
        },
        error: null,
      },
    });
    mockSyncEmailVerified.mockResolvedValueOnce(true);

    const req = makeRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(mockSyncEmailVerified).toHaveBeenCalledWith("user-123");
    expect(body.email_verified).toBe(true);
    expect(body.can_proceed_to_payment).toBe(true);
  });

  it("does not call self-heal when email_verified is already true", async () => {
    const req = makeRequest("valid-token");
    await GET(req);
    expect(mockSyncEmailVerified).not.toHaveBeenCalled();
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

  // TC-02: ?email= used to be accepted as identity, turning this endpoint into
  // an unauthenticated profile dump and account-existence oracle.
  it("ignores ?email= and returns 401 without a session or grant", async () => {
    resetMocks({
      getUserResult: { data: { user: null } },
      getSessionResult: { data: { session: null } },
    });

    mockAdminSelect.mockClear();

    const req = makeRequest(undefined, { searchParams: { email: "victim@example.com" } });
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Not authenticated");
    expect(mockAdminSelect).not.toHaveBeenCalled();
  });

  it("accepts a valid signup grant cookie when there is no session", async () => {
    process.env.SIGNUP_GRANT_SECRET = "test-secret";
    resetMocks({
      getUserResult: { data: { user: null } },
      getSessionResult: { data: { session: null } },
    });

    const grantCookie = issueSignupGrant({ userId: "user-123", email: "user@example.com" });
    const res = await GET(makeRequest(undefined, { grantCookie }));

    expect(res.status).toBe(200);
    expect(mockAdminEq).toHaveBeenCalledWith("id", "user-123");
    delete process.env.SIGNUP_GRANT_SECRET;
  });

  it("rejects a forged signup grant cookie", async () => {
    process.env.SIGNUP_GRANT_SECRET = "test-secret";
    resetMocks({
      getUserResult: { data: { user: null } },
      getSessionResult: { data: { session: null } },
    });

    const res = await GET(makeRequest(undefined, { grantCookie: "v1.deadbeef.deadbeef" }));

    expect(res.status).toBe(401);
    delete process.env.SIGNUP_GRANT_SECRET;
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
