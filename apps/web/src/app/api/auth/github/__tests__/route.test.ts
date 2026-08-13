import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  clientOptions: undefined as Record<string, unknown> | undefined,
  signInWithOAuth: vi.fn(),
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

    static json(_body: unknown, init?: { status?: number }) {
      return new MockResponse(init?.status);
    }
  }

  return { NextRequest: class {}, NextResponse: MockResponse };
});

vi.mock("@supabase/supabase-js", () => ({
  createClient: (_url: string, _key: string, options: Record<string, unknown>) => {
    mocks.clientOptions = options;
    return {
      auth: {
        signInWithOAuth: mocks.signInWithOAuth,
      },
    };
  },
}));

import { GET } from "@/app/api/auth/github/route";

function makeRequest(url: string) {
  return {
    url,
    cookies: { get: () => undefined },
  } as unknown as import("next/server").NextRequest;
}

describe("GET /api/auth/github", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.clientOptions = undefined;
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://project.supabase.co";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon-key";
    process.env.NEXT_PUBLIC_APP_URL = "https://threatcrush.com";
  });

  it("starts a PKCE flow and stores the verifier in a secure cookie", async () => {
    mocks.signInWithOAuth.mockImplementation(async () => {
      const auth = mocks.clientOptions?.auth as {
        storage: { setItem(key: string, value: string): void };
      };
      auth.storage.setItem("sb-project-auth-token-code-verifier", "pkce-verifier");
      return { data: { url: "https://github.com/login/oauth/authorize" }, error: null };
    });

    const request = makeRequest(
      "https://threatcrush.com/api/auth/github?ref=friend&next=%2Fstore%3Ftab%3Downed"
    );
    const response = await GET(request);
    const authOptions = mocks.clientOptions?.auth as Record<string, unknown>;

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://github.com/login/oauth/authorize");
    expect(authOptions).toMatchObject({
      flowType: "pkce",
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    });
    expect(response.headers.get("set-cookie")).toContain(
      "sb-project-auth-token-code-verifier=pkce-verifier"
    );
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");
    expect(response.headers.get("set-cookie")).toContain("SameSite=lax");
    expect(response.headers.get("set-cookie")).toContain("Secure");
    expect(mocks.signInWithOAuth).toHaveBeenCalledWith({
      provider: "github",
      options: {
        redirectTo:
          "https://threatcrush.com/api/auth/callback?ref=friend&next=%2Fstore%3Ftab%3Downed",
        scopes: "user:email",
      },
    });
  });

  it("replaces an unsafe post-login redirect", async () => {
    mocks.signInWithOAuth.mockResolvedValue({
      data: { url: "https://github.com/login/oauth/authorize" },
      error: null,
    });

    await GET(
      makeRequest("https://threatcrush.com/api/auth/github?next=https://attacker.example")
    );

    expect(mocks.signInWithOAuth).toHaveBeenCalledWith(
      expect.objectContaining({
        options: expect.objectContaining({
          redirectTo: "https://threatcrush.com/api/auth/callback?ref=&next=%2Faccount",
        }),
      })
    );
  });
});
