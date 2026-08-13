import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  clientKey: "",
  clientOptions: undefined as Record<string, unknown> | undefined,
  exchangeCodeForSession: vi.fn(),
  profileSingle: vi.fn(),
  profileInsert: vi.fn(),
}));

vi.mock("next/server", () => {
  class MockResponse {
    headers = new Headers();
    status: number;
    cookies = {
      set: (cookie: Record<string, unknown>) => {
        const parts = [`${cookie.name}=${cookie.value}`];
        if (cookie.maxAge !== undefined) parts.push(`Max-Age=${cookie.maxAge}`);
        if (cookie.httpOnly) parts.push("HttpOnly");
        if (cookie.secure) parts.push("Secure");
        if (cookie.sameSite) parts.push(`SameSite=${cookie.sameSite}`);
        this.headers.set("set-cookie", parts.join("; "));
      },
    };

    constructor(status = 200) {
      this.status = status;
    }

    static redirect(url: string | URL) {
      const response = new MockResponse(307);
      response.headers.set("location", url.toString());
      return response;
    }
  }

  return { NextRequest: class {}, NextResponse: MockResponse };
});

vi.mock("@supabase/supabase-js", () => ({
  createClient: (_url: string, key: string, options: Record<string, unknown>) => {
    mocks.clientKey = key;
    mocks.clientOptions = options;
    return {
      auth: {
        exchangeCodeForSession: mocks.exchangeCodeForSession,
      },
    };
  },
}));

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({
        eq: () => ({ single: mocks.profileSingle }),
      }),
      insert: mocks.profileInsert,
    }),
  }),
}));

import { GET } from "@/app/api/auth/callback/route";

function makeRequest(url: string, cookies: Record<string, string> = {}) {
  return {
    url,
    cookies: {
      get: (name: string) => (cookies[name] ? { value: cookies[name] } : undefined),
    },
  } as unknown as import("next/server").NextRequest;
}

describe("GET /api/auth/callback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.clientKey = "";
    mocks.clientOptions = undefined;
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://project.supabase.co";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon-key";
    process.env.SUPABASE_SERVICE_ROLE_KEY = "service-key";
    process.env.NEXT_PUBLIC_APP_URL = "https://threatcrush.com";
    mocks.profileSingle.mockResolvedValue({ data: null, error: null });
    mocks.profileInsert.mockResolvedValue({ data: null, error: null });
  });

  it("exchanges the code with the verifier and clears its cookie", async () => {
    mocks.exchangeCodeForSession.mockImplementation(async () => {
      const auth = mocks.clientOptions?.auth as {
        storage: {
          getItem(key: string): string | null;
          removeItem(key: string): void;
        };
      };
      expect(auth.storage.getItem("sb-project-auth-token-code-verifier")).toBe("pkce-verifier");
      auth.storage.removeItem("sb-project-auth-token-code-verifier");
      return {
        data: {
          user: {
            id: "user-123",
            email: "dev@example.com",
            user_metadata: { user_name: "developer", avatar_url: "https://example.com/a.png" },
          },
          session: { access_token: "access-token", refresh_token: "refresh-token" },
        },
        error: null,
      };
    });

    const request = makeRequest(
      "https://threatcrush.com/api/auth/callback?code=oauth-code&ref=friend&next=%2Fstore",
      { "sb-project-auth-token-code-verifier": "pkce-verifier" }
    );
    const response = await GET(request);
    const authOptions = mocks.clientOptions?.auth as Record<string, unknown>;

    expect(mocks.clientKey).toBe("anon-key");
    expect(authOptions).toMatchObject({ flowType: "pkce", persistSession: true });
    expect(mocks.exchangeCodeForSession).toHaveBeenCalledWith("oauth-code");
    expect(mocks.profileInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "user-123",
        email: "dev@example.com",
        display_name: "developer",
        referred_by: "friend",
      })
    );
    expect(response.headers.get("location")).toBe(
      "https://threatcrush.com/store#access_token=access-token&refresh_token=refresh-token&type=oauth"
    );
    expect(response.headers.get("set-cookie")).toContain(
      "sb-project-auth-token-code-verifier="
    );
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("keeps the no-code error redirect safe", async () => {
    const response = await GET(
      makeRequest(
        "https://threatcrush.com/api/auth/callback?next=https://attacker.example"
      )
    );

    expect(response.headers.get("location")).toBe(
      "https://threatcrush.com/auth/login?error=no_code"
    );
    expect(mocks.exchangeCodeForSession).not.toHaveBeenCalled();
  });
});
