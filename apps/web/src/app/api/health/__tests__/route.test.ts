import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery } from "@/__tests__/helpers/query-recorder";

const state = {
  mode: "up" as "up" | "error" | "hang" | "throw",
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => {
    if (state.mode === "throw") throw new Error("Missing required env var: SUPABASE_SERVICE_ROLE_KEY");
    return {
      from: () => {
        if (state.mode === "hang") {
          const never = Promise.withResolvers<never>().promise;
          const builder: Record<string, unknown> = { then: never.then.bind(never) };
          for (const m of ["select", "limit", "abortSignal"]) builder[m] = () => builder;
          return builder;
        }
        return recordQuery(
          state.mode === "up"
            ? { data: null, error: null }
            : { data: null, error: { message: 'relation "user_profiles" does not exist' } },
        );
      },
    };
  },
}));

import { GET } from "@/app/api/health/route";

describe("GET /api/health", () => {
  beforeEach(() => {
    state.mode = "up";
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("reports ok with the database reachable", async () => {
    const res = await GET();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ status: "ok", db: "ok" });
    expect(body.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(typeof body.uptime).toBe("number");
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("returns 503 without the database error text when the query fails", async () => {
    state.mode = "error";
    const res = await GET();
    expect(res.status).toBe(503);
    const text = await res.text();
    expect(JSON.parse(text)).toMatchObject({ status: "error", db: "error" });
    expect(text).not.toContain("user_profiles");
  });

  it("returns 503 when the database client cannot be built", async () => {
    state.mode = "throw";
    const res = await GET();
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain("SUPABASE_SERVICE_ROLE_KEY");
  });

  it("gives up on a hung database after two seconds", async () => {
    vi.useFakeTimers();
    state.mode = "hang";
    const pending = GET();
    await vi.advanceTimersByTimeAsync(2000);
    const res = await pending;
    expect(res.status).toBe(503);
  });
});
