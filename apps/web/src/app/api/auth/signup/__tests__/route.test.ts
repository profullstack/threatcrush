import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock chain for supabase ───

const mockFromSelect = vi.fn();
const mockFromInsert = vi.fn();
const mockFromEq = vi.fn();
const mockSingle = vi.fn();
const mockCreateUser = vi.fn();
const mockDeleteUser = vi.fn();

function resetMocks(overrides: {
  createUserResult?: { data: unknown; error: unknown };
  profileSelectResult?: { data: unknown; error: unknown };
  profileInsertResult?: { data: unknown; error: unknown };
} = {}) {
  const createUserResult = overrides.createUserResult ?? {
    data: { user: { id: "user-123" } },
    error: null,
  };
  const profileSelectResult = overrides.profileSelectResult ?? { data: null, error: null };
  const profileInsertResult = overrides.profileInsertResult ?? { data: null, error: null };

  mockCreateUser.mockResolvedValue(createUserResult);
  mockDeleteUser.mockResolvedValue({ error: null });
  mockSingle.mockResolvedValue(profileSelectResult);
  mockFromEq.mockReturnValue({ single: mockSingle });
  mockFromSelect.mockReturnValue({ eq: mockFromEq });
  mockFromInsert.mockResolvedValue(profileInsertResult);
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: {
      admin: {
        createUser: mockCreateUser,
        deleteUser: mockDeleteUser,
      },
    },
    from: (table: string) => {
      if (table === "user_profiles") {
        return {
          select: mockFromSelect,
          insert: mockFromInsert,
        };
      }
      if (table === "phone_verification_codes") {
        return {
          delete: vi.fn().mockReturnValue({ eq: vi.fn().mockResolvedValue({}) }),
          insert: vi.fn().mockReturnValue({ insert: vi.fn().mockResolvedValue({ error: null }) }),
        };
      }
      return { select: vi.fn(), insert: vi.fn(), delete: vi.fn().mockReturnValue({ eq: vi.fn().mockResolvedValue({}) }) };
    },
  }),
  getSupabaseClient: () => ({
    auth: {
      signUp: mockCreateUser,
      admin: {
        createUser: mockCreateUser,
        deleteUser: mockDeleteUser,
      },
    },
  }),
}));

import { POST } from "@/app/api/auth/signup/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/auth/signup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetMocks();
  });

  it("creates user with valid email + phone + password", async () => {
    const req = makeRequest({ email: "test@example.com", phone: "+1234567890", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.user).toBeDefined();
    expect(body.user.id).toBe("user-123");
    expect(body.user.email).toBe("test@example.com");
    expect(body.needs_email_verification).toBe(true);
    expect(body.needs_phone_verification).toBe(true);
    expect(mockCreateUser).toHaveBeenCalledWith({
      email: "test@example.com",
      password: "securePass1!",
      options: {
        emailRedirectTo: "http://localhost/auth/verify",
      },
    });
  });

  it("returns referral_code in response", async () => {
    const req = makeRequest({ email: "test@example.com", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.referral_code).toBeDefined();
    expect(typeof body.referral_code).toBe("string");
    expect(body.referral_code.length).toBe(8);
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

  it("rejects invalid email format (via Supabase)", async () => {
    resetMocks({
      createUserResult: {
        data: { user: null },
        error: { message: "Unable to validate email address: invalid format" },
      },
    });

    const req = makeRequest({ email: "not-an-email", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("invalid format");
  });

  it("handles duplicate email (via Supabase error)", async () => {
    resetMocks({
      createUserResult: {
        data: { user: null },
        error: { message: "User already registered" },
      },
    });

    const req = makeRequest({ email: "existing@example.com", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("already registered");
  });

  it("accepts optional referral_code (referred_by)", async () => {
    const req = makeRequest({
      email: "test@example.com",
      password: "securePass1!",
      referral_code: "ABC12345",
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.user.id).toBe("user-123");
    // Verify insert was called with referred_by
    expect(mockFromInsert).toHaveBeenCalledWith(
      expect.objectContaining({ referred_by: "ABC12345" })
    );
  });

  it("sets needs_phone_verification=false when no phone provided", async () => {
    const req = makeRequest({ email: "test@example.com", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.needs_phone_verification).toBe(false);
  });

  it("response shape matches contract", async () => {
    const req = makeRequest({ email: "test@example.com", phone: "+1234567890", password: "securePass1!" });
    const res = await POST(req);
    const body = await res.json();

    expect(body).toEqual(
      expect.objectContaining({
        user: expect.objectContaining({
          id: expect.any(String),
          email: expect.any(String),
        }),
        referral_code: expect.any(String),
        needs_email_verification: expect.any(Boolean),
        needs_phone_verification: expect.any(Boolean),
      })
    );
  });
});
