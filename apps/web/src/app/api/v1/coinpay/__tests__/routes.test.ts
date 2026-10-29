import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const mocks = vi.hoisted(() => ({
  finishSignIn: vi.fn(),
  mintSession: vi.fn(),
  user: null as null | { userId: string; email: string | null; githubLogin: null },
  admin: null as unknown,
}));

vi.mock("@profullstack/coinpay-onboard/oauth", async (orig) => ({
  ...(await orig<typeof import("@profullstack/coinpay-onboard/oauth")>()),
  finishSignIn: mocks.finishSignIn,
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => mocks.admin }));
vi.mock("@/lib/cli-login", () => ({ mintSession: mocks.mintSession }));
vi.mock("@/lib/credit-codes", () => ({
  onSignedIn: vi.fn(async () => {}),
  inviteCookie: () => "",
  clearInviteCookie: () => {},
}));
vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: async () => mocks.user,
  unauthorized: () => Response.json({ error: "Not authenticated" }, { status: 401 }),
}));

import { fakeAdmin } from "@/__tests__/helpers/coinpay-fake-admin";
import { GET as start } from "../oauth/start/route";
import { GET as callback } from "../oauth/callback/route";
import { POST as link, DELETE as unlink } from "../link/route";

const BASE = "https://threatcrush.com";

function cookieFrom(res: Response): string {
  const raw = res.headers.get("set-cookie") ?? "";
  return /tc_coinpay_oauth=([^;]+)/.exec(raw)?.[1] ?? "";
}

async function started(next = "/account") {
  const res = await start(new NextRequest(`${BASE}/api/v1/coinpay/oauth/start?next=${encodeURIComponent(next)}`));
  const location = new URL(res.headers.get("location")!);
  return { res, location, cookie: cookieFrom(res), state: location.searchParams.get("state")!, nonce: location.searchParams.get("nonce")! };
}

describe("CoinPay routes", () => {
  beforeEach(() => {
    process.env.COINPAY_OAUTH_CLIENT_ID = "cp_tc";
    process.env.COINPAY_OAUTH_CLIENT_SECRET = "secret";
    process.env.NEXT_PUBLIC_APP_URL = BASE;
    mocks.finishSignIn.mockReset();
    mocks.mintSession.mockReset();
    mocks.user = null;
    mocks.admin = fakeAdmin({ users: [{ id: "victim", email: "victim@example.com" }] });
  });

  it("start 302s to CoinPay with S256 and state, and sets the pending cookie", async () => {
    const { res, location, cookie } = await started();
    expect(res.status).toBe(302);
    expect(location.origin).toBe("https://coinpayportal.com");
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.get("state")).toBeTruthy();
    expect(cookie).toBeTruthy();
  });

  it("callback rejects a state that does not match this browser's cookie", async () => {
    const { cookie } = await started();
    const res = await callback(new NextRequest(`${BASE}/api/v1/coinpay/oauth/callback?code=c&state=forged`, { headers: { cookie: `tc_coinpay_oauth=${cookie}` } }));
    expect(res.headers.get("location")).toBe(`${BASE}/auth/login?error=coinpay_state`);
    expect(mocks.finishSignIn).not.toHaveBeenCalled();
  });

  it("callback rejects a state with no cookie at all", async () => {
    const { state } = await started();
    const res = await callback(new NextRequest(`${BASE}/api/v1/coinpay/oauth/callback?code=c&state=${state}`));
    expect(res.headers.get("location")).toBe(`${BASE}/auth/login?error=coinpay_state`);
  });

  it("callback passes the nonce through and refuses when the id_token nonce is wrong", async () => {
    const { cookie, state, nonce } = await started();
    mocks.finishSignIn.mockRejectedValue(new Error("id_token nonce mismatch"));
    const res = await callback(new NextRequest(`${BASE}/api/v1/coinpay/oauth/callback?code=c&state=${state}`, { headers: { cookie: `tc_coinpay_oauth=${cookie}` } }));
    expect(mocks.finishSignIn.mock.calls[0][0].nonce).toBe(nonce);
    expect(res.headers.get("location")).toBe(`${BASE}/auth/login?error=coinpay_failed`);
    expect(mocks.mintSession).not.toHaveBeenCalled();
  });

  it("a login whose CoinPay email matches an existing user never mints that user's session", async () => {
    const { cookie, state } = await started("/cli/login?request=r1");
    mocks.finishSignIn.mockResolvedValue({ sub: "cp_eve", email: "victim@example.com", name: "Eve" });
    mocks.mintSession.mockResolvedValue({ user: { id: "x" }, session: { access_token: "at", refresh_token: "rt" } });
    const res = await callback(new NextRequest(`${BASE}/api/v1/coinpay/oauth/callback?code=c&state=${state}`, { headers: { cookie: `tc_coinpay_oauth=${cookie}` } }));
    const minted = mocks.mintSession.mock.calls[0][1] as string;
    expect(minted).not.toBe("victim@example.com");
    expect(minted).toMatch(/@coinpay\.threatcrush\.invalid$/);
    expect(res.headers.get("location")).toBe(`${BASE}/cli/login?request=r1#access_token=at&refresh_token=rt&type=oauth`);
  });

  it("Connect CoinPay needs a signed-in session", async () => {
    const res = await link(new NextRequest(`${BASE}/api/v1/coinpay/link`, { method: "POST" }));
    expect(res.status).toBe(401);
  });

  it("a signed-in link binds the sub to that user and does not sign anyone in", async () => {
    mocks.user = { userId: "victim", email: "victim@example.com", githubLogin: null };
    const res = await link(new NextRequest(`${BASE}/api/v1/coinpay/link`, { method: "POST" }));
    const { url } = await res.json();
    const state = new URL(url).searchParams.get("state");
    mocks.finishSignIn.mockResolvedValue({ sub: "cp_v", email: null, name: null });
    const back = await callback(new NextRequest(`${BASE}/api/v1/coinpay/oauth/callback?code=c&state=${state}`, { headers: { cookie: `tc_coinpay_oauth=${cookieFrom(res)}` } }));
    expect(back.headers.get("location")).toBe(`${BASE}/account?coinpay=linked`);
    expect((mocks.admin as ReturnType<typeof fakeAdmin>).identities[0]).toMatchObject({ sub: "cp_v", user_id: "victim" });
    expect(mocks.mintSession).not.toHaveBeenCalled();
  });

  it("disconnect is refused when CoinPay is the only way in", async () => {
    mocks.user = { userId: "u1", email: "cp-abc@coinpay.threatcrush.invalid", githubLogin: null };
    const res = await unlink(new NextRequest(`${BASE}/api/v1/coinpay/link`, { method: "DELETE" }));
    expect(res.status).toBe(409);
  });
});
