import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";
import { POST as login } from "@/app/api/auth/login/route";
import { POST as refresh } from "@/app/api/auth/refresh/route";
import { GET as getMe, PATCH as patchMe } from "@/app/api/auth/me/route";
import { GET as check } from "@/app/api/auth/check/route";

// Real supabase-js clients against a fake Supabase (GoTrue + PostgREST) behind
// the global fetch stub, so the routes' shared clients behave exactly as in
// production: whatever session one request leaves on them, the next sees.

const USER_A = {
  id: "user-a",
  aud: "authenticated",
  role: "authenticated",
  email: "a@example.com",
  app_metadata: { provider: "email", providers: ["email"] },
  user_metadata: {},
  created_at: "2026-01-01T00:00:00Z",
};

const PROFILE_A = {
  id: "user-a",
  email: "a@example.com",
  phone: "+15555550100",
  email_verified: true,
  phone_verified: true,
  license_status: "active",
  wallet_address: "0xVICTIM",
};

const profileWrites: unknown[] = [];

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sessionFor(user: typeof USER_A) {
  return {
    access_token: "token-a",
    refresh_token: "refresh-a-2",
    token_type: "bearer",
    expires_in: 3600,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    user,
  };
}

async function fakeSupabase(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
  const method = (init?.method ?? "GET").toUpperCase();
  const auth = new Headers(init?.headers).get("authorization");

  if (url.pathname === "/auth/v1/token") {
    const grant = url.searchParams.get("grant_type");
    const body = JSON.parse(String(init?.body ?? "{}"));
    if (grant === "password" && body.email === USER_A.email && body.password === "correct horse") {
      return json(sessionFor(USER_A));
    }
    if (grant === "refresh_token" && body.refresh_token === "refresh-a-1") {
      return json(sessionFor(USER_A));
    }
    return json({ error: "invalid_grant", error_description: "Invalid login credentials" }, 400);
  }

  if (url.pathname === "/auth/v1/user") {
    if (auth === "Bearer token-a") return json(USER_A);
    return json({ code: 401, msg: "invalid JWT" }, 401);
  }

  if (url.pathname === "/rest/v1/user_profiles") {
    if (url.searchParams.get("id") !== `eq.${USER_A.id}`) {
      return json({ code: "PGRST116", message: "0 rows" }, 406);
    }
    if (method === "PATCH") {
      const patch = JSON.parse(String(init?.body ?? "{}"));
      profileWrites.push(patch);
      return json({ ...PROFILE_A, ...patch });
    }
    return json(PROFILE_A);
  }

  return json({ message: `unexpected ${method} ${url.pathname}` }, 500);
}

function request(url: string, init: { method?: string; body?: unknown; token?: string } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  const req = new Request(`http://localhost${url}`, {
    method: init.method ?? "GET",
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  // The routes read cookies through NextRequest's API.
  return Object.assign(req, {
    cookies: { get: () => undefined },
  }) as unknown as NextRequest;
}

const sessionCreators: [string, () => Promise<Response>][] = [
  [
    "login",
    () =>
      login(request("/api/auth/login", {
        method: "POST",
        body: { email: USER_A.email, password: "correct horse" },
      })),
  ],
  [
    "refresh",
    () =>
      refresh(request("/api/auth/refresh", {
        method: "POST",
        body: { refresh_token: "refresh-a-1" },
      })),
  ],
];

describe.each(sessionCreators)("after user A signs in via %s", (_name, signIn) => {
  beforeEach(async () => {
    vi.mocked(fetch).mockReset();
    vi.mocked(fetch).mockImplementation(fakeSupabase);
    profileWrites.length = 0;
    const res = await signIn();
    expect(res.status).toBe(200);
  });

  it("GET /api/auth/me without a token is 401 and returns no profile", async () => {
    const res = await getMe(request("/api/auth/me"));
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.profile).toBeUndefined();
  });

  it("PATCH /api/auth/me without a token is 401 and writes nothing", async () => {
    const res = await patchMe(
      request("/api/auth/me", { method: "PATCH", body: { wallet_address: "0xATTACKER" } }),
    );

    expect(res.status).toBe(401);
    expect(profileWrites).toEqual([]);
  });

  it("GET /api/auth/check without a token is 401 and discloses nothing", async () => {
    const res = await check(request("/api/auth/check"));
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.email).toBeUndefined();
    expect(body.phone).toBeUndefined();
  });

  it("still answers user A's own bearer token", async () => {
    const res = await getMe(request("/api/auth/me", { token: "token-a" }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.profile.id).toBe(USER_A.id);
  });
});
