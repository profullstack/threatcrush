import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const rpc = vi.fn();
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

const { GET } = await import("../route");

const TOKEN = "t".repeat(40);
const get = (qs = "", token: string | null = TOKEN) =>
  GET(
    new NextRequest(`https://threatcrush.com/api/v1/ban-candidates${qs}`, {
      headers: token ? { authorization: `Bearer ${token}` } : {},
    }),
  );

describe("GET /api/v1/ban-candidates", () => {
  beforeEach(() => {
    vi.stubEnv("TRAFFIC_FEED_TOKEN", TOKEN);
    rpc.mockReset();
  });
  afterEach(() => vi.unstubAllEnvs());

  it("refuses without the token, with a wrong one, and when the token is unset", async () => {
    expect((await get("", null)).status).toBe(401);
    expect((await get("", "x".repeat(40))).status).toBe(401);
    vi.stubEnv("TRAFFIC_FEED_TOKEN", "");
    expect((await get("", "")).status).toBe(401);
    expect(rpc).not.toHaveBeenCalled();
  });

  it("pages by address and returns a cursor only on a full page", async () => {
    rpc.mockResolvedValueOnce({ data: [{ ip: "1.1.1.1" }, { ip: "2.2.2.2" }], error: null });
    const res = await get("?limit=2&cursor=1.0.0.1");
    expect(res.status).toBe(200);
    expect(rpc).toHaveBeenCalledWith("ban_candidates", { p_after: "1.0.0.1", p_limit: 2 });
    const body = await res.json();
    expect(body.next_cursor).toBe("2.2.2.2");

    rpc.mockResolvedValueOnce({ data: [{ ip: "3.3.3.3" }], error: null });
    expect((await (await get("?limit=2&cursor=2.2.2.2")).json()).next_cursor).toBeNull();
  });

  it("rejects a cursor that is not an address", async () => {
    expect((await get("?cursor=1;drop")).status).toBe(400);
  });
});
