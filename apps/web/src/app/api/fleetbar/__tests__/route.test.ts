import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Users the fake GoTrue knows, by access token.
const USERS: Record<string, { id: string; email: string; email_confirmed_at: string | null }> = {
  "tok-verified": { id: "u1", email: "anthony@example.com", email_confirmed_at: "2026-01-01T00:00:00Z" },
  "tok-unverified": { id: "u2", email: "new@example.com", email_confirmed_at: null },
};
const PROFILES: Record<string, { email_verified: boolean }> = {
  u1: { email_verified: true },
  u2: { email_verified: false },
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: async (token: string) =>
        USERS[token] ? { data: { user: USERS[token] }, error: null } : { data: { user: null }, error: new Error("bad jwt") },
    },
  }),
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({
        eq: (_col: string, id: string) => ({
          maybeSingle: async () => ({ data: PROFILES[id] ?? null, error: null }),
        }),
      }),
    }),
  }),
}));

import { GET, POST } from "@/app/api/fleetbar/[...path]/route";
import { POST as startSession, DELETE as endSession } from "@/app/api/fleet-session/route";

const ORIGIN = "https://threatcrush.com";

function req(path: string, init: RequestInit & { cookie?: string; bearer?: string } = {}) {
  const headers = new Headers(init.headers);
  if (init.cookie) headers.set("cookie", init.cookie);
  if (init.bearer) headers.set("authorization", `Bearer ${init.bearer}`);
  return new Request(ORIGIN + path, { ...init, headers });
}

const fetchMock = vi.fn();

beforeEach(() => {
  process.env.CRAWLPROOF_UPTIME_TOKEN = "cpu_test_partner_token";
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  delete process.env.CRAWLPROOF_UPTIME_TOKEN;
});

describe("/api/fleetbar", () => {
  it("401s with no session and never calls crawlproof", async () => {
    const res = await GET(req("/api/fleetbar/monitors"));
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("unauthorized");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("401s on a token GoTrue rejects", async () => {
    const res = await GET(req("/api/fleetbar/monitors", { cookie: "tc_fleetbar=forged" }));
    expect(res.status).toBe(401);
  });

  it("403s when the email is not verified", async () => {
    const res = await GET(req("/api/fleetbar/monitors", { cookie: "tc_fleetbar=tok-unverified" }));
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("email_unverified");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("proxies to crawlproof with the partner token and the verified email (cookie session)", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ monitors: [{ id: "m1", name: "SSH root@dev2", type: "ssh" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const res = await GET(req("/api/fleetbar/monitors?x=1", { cookie: "a=b; tc_fleetbar=tok-verified" }));
    expect(res.status).toBe(200);
    expect((await res.json()).monitors[0].name).toBe("SSH root@dev2");

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("https://crawlproof.com/api/uptime/v1/monitors");
    const headers = new Headers(init.headers);
    expect(headers.get("authorization")).toBe("Bearer cpu_test_partner_token");
    expect(headers.get("x-fleet-user-email")).toBe("anthony@example.com");
    expect(headers.get("cookie")).toBeNull();
  });

  it("accepts a Bearer session too", async () => {
    fetchMock.mockResolvedValue(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    const res = await GET(req("/api/fleetbar/settings", { bearer: "tok-verified" }));
    expect(res.status).toBe(200);
  });

  it("503s when the partner token is not configured, read at request time", async () => {
    delete process.env.CRAWLPROOF_UPTIME_TOKEN;
    const res = await GET(req("/api/fleetbar/monitors", { cookie: "tc_fleetbar=tok-verified" }));
    expect(res.status).toBe(503);
  });

  it("refuses a cross-site write", async () => {
    const res = await POST(
      req("/api/fleetbar/monitors", {
        method: "POST",
        cookie: "tc_fleetbar=tok-verified",
        headers: { origin: "https://evil.example", "content-type": "application/json" },
        body: "{}",
      }),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("/api/fleet-session", () => {
  it("401s without a Bearer token", async () => {
    const res = await startSession(req("/api/fleet-session", { method: "POST", cookie: "tc_fleetbar=tok-verified" }));
    expect(res.status).toBe(401);
  });

  it("sets an httpOnly, strict cookie scoped to /api/fleetbar", async () => {
    const res = await startSession(req("/api/fleet-session", { method: "POST", bearer: "tok-verified" }));
    expect(res.status).toBe(200);
    const cookie = res.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/^tc_fleetbar=tok-verified;/);
    expect(cookie).toMatch(/Path=\/api\/fleetbar/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=strict/i);
  });

  it("DELETE expires it", async () => {
    const res = await endSession();
    expect(res.headers.get("set-cookie") ?? "").toMatch(/Max-Age=0/);
  });
});
