import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock chain ───

const mockGetUser = vi.fn();
const mockGetSession = vi.fn();
const mockAdminSelect = vi.fn();
const mockAdminUpdate = vi.fn();
const mockAdminEq = vi.fn();
const mockAdminSingle = vi.fn();
const mockUpdateSelect = vi.fn();
const mockUpdateEq = vi.fn();
const mockUpdateSingle = vi.fn();

const TEST_PROFILE = {
  id: "user-123",
  email: "test@example.com",
  display_name: "Test User",
  license_status: "active",
  referral_code: "REF12345",
  notification_email: true,
  notification_sms: false,
  notification_webhook_url: null,
  wallet_address: null,
  phone: "+1234567890",
  phone_verified: true,
  email_verified: true,
};

function resetMocks(overrides: {
  getUserResult?: { data: { user: unknown }; error?: unknown };
  getSessionResult?: { data: { session: unknown }; error?: unknown };
  profileResult?: { data: unknown; error: unknown };
  updateResult?: { data: unknown; error: unknown };
} = {}) {
  const getUserResult = overrides.getUserResult ?? {
    data: { user: { id: "user-123" } },
  };
  const getSessionResult = overrides.getSessionResult ?? {
    data: { session: null },
  };
  const profileResult = overrides.profileResult ?? {
    data: TEST_PROFILE,
    error: null,
  };
  const updateResult = overrides.updateResult ?? {
    data: { ...TEST_PROFILE, display_name: "Updated" },
    error: null,
  };

  mockGetUser.mockResolvedValue(getUserResult);
  mockGetSession.mockResolvedValue(getSessionResult);
  mockAdminSingle.mockResolvedValue(profileResult);
  mockAdminEq.mockReturnValue({ single: mockAdminSingle });
  mockAdminSelect.mockReturnValue({ eq: mockAdminEq });

  mockUpdateSingle.mockResolvedValue(updateResult);
  mockUpdateEq.mockReturnValue({ select: mockUpdateSelect });
  mockUpdateSelect.mockReturnValue({ single: mockUpdateSingle });
  mockAdminUpdate.mockReturnValue({ eq: mockUpdateEq });
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
      update: mockAdminUpdate,
    }),
  }),
}));

import { GET, PATCH } from "@/app/api/auth/me/route";

function makeGetRequest(token?: string) {
  const headers: Record<string, string> = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  return new Request("http://localhost/api/auth/me", { headers }) as unknown as import("next/server").NextRequest;
}

function makePatchRequest(body: unknown, token?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["authorization"] = `Bearer ${token}`;
  return new Request("http://localhost/api/auth/me", {
    method: "PATCH",
    headers,
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("GET /api/auth/me", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetMocks();
  });

  it("returns user profile", async () => {
    const req = makeGetRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.profile).toBeDefined();
    expect(body.profile.id).toBe("user-123");
    expect(body.profile.email).toBe("test@example.com");
    expect(body.profile.display_name).toBe("Test User");
  });

  it("returns 401 without auth", async () => {
    resetMocks({
      getUserResult: { data: { user: null } },
      getSessionResult: { data: { session: null } },
    });

    const req = makeGetRequest();
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Not authenticated");
  });

  it("response shape matches contract", async () => {
    const req = makeGetRequest("valid-token");
    const res = await GET(req);
    const body = await res.json();

    expect(body).toEqual(
      expect.objectContaining({
        profile: expect.objectContaining({
          id: expect.any(String),
          email: expect.any(String),
          display_name: expect.any(String),
          license_status: expect.any(String),
          referral_code: expect.any(String),
          notification_email: expect.any(Boolean),
          notification_sms: expect.any(Boolean),
        }),
      })
    );
  });
});

describe("PATCH /api/auth/me", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetMocks();
  });

  it("updates display_name", async () => {
    const req = makePatchRequest({ display_name: "New Name" }, "valid-token");
    const res = await PATCH(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.profile).toBeDefined();
    expect(mockAdminUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ display_name: "New Name" })
    );
  });

  it("updates wallet_address", async () => {
    const req = makePatchRequest({ wallet_address: "0xABC123" }, "valid-token");
    const res = await PATCH(req);

    expect(res.status).toBe(200);
    expect(mockAdminUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ wallet_address: "0xABC123" })
    );
  });

  it("updates notification preferences", async () => {
    const req = makePatchRequest(
      { notification_email: false, notification_sms: true, notification_webhook_url: "https://hook.example.com" },
      "valid-token"
    );
    const res = await PATCH(req);

    expect(res.status).toBe(200);
    expect(mockAdminUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        notification_email: false,
        notification_sms: true,
        notification_webhook_url: "https://hook.example.com",
      })
    );
  });

  it("returns 401 without auth", async () => {
    resetMocks({
      getUserResult: { data: { user: null } },
      getSessionResult: { data: { session: null } },
    });

    const req = makePatchRequest({ display_name: "New Name" });
    const res = await PATCH(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Not authenticated");
  });

  it("handles update failure", async () => {
    resetMocks({
      updateResult: { data: null, error: { message: "DB error" } },
    });

    const req = makePatchRequest({ display_name: "New Name" }, "valid-token");
    const res = await PATCH(req);
    const body = await res.json();

    expect(res.status).toBe(500);
    expect(body.error).toContain("Failed to update profile");
  });
});
