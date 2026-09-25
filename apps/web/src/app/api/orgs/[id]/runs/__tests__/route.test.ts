import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall } from "@/__tests__/helpers/query-recorder";

const state = {
  user: { id: "user-1", email: "a@example.com" } as { id: string; email: string } | null,
  membership: { role: "member" } as { role: string } | null,
  runs: { data: [] as unknown[], error: null as unknown, count: 0 },
  runCalls: [] as QueryCall[],
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: async (token: string) =>
        token === "good-token" && state.user
          ? { data: { user: state.user }, error: null }
          : { data: { user: null }, error: { message: "bad jwt" } },
    },
  }),
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "organization_members") {
        return recordQuery({ data: state.membership, error: null }, []);
      }
      if (table === "property_runs") return recordQuery(state.runs, state.runCalls);
      throw new Error(`Unexpected table ${table}`);
    },
  }),
}));

import { GET } from "@/app/api/orgs/[id]/runs/route";

function get(query = "", token: string | null = "good-token") {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const req = new Request(`http://localhost/api/orgs/org-1/runs${query}`, { headers });
  return GET(req as unknown as NextRequest, {
    params: Promise.resolve({ id: "org-1" }),
  });
}

describe("GET /api/orgs/:id/runs", () => {
  beforeEach(() => {
    state.user = { id: "user-1", email: "a@example.com" };
    state.membership = { role: "member" };
    state.runs = { data: [], error: null, count: 0 };
    state.runCalls = [];
  });

  it("rejects a missing or invalid bearer token", async () => {
    expect((await get("", null)).status).toBe(401);
    expect((await get("", "forged")).status).toBe(401);
  });

  it("refuses users who are not members of the org", async () => {
    state.membership = null;
    const res = await get();
    expect(res.status).toBe(403);
    expect(state.runCalls).toEqual([]);
  });

  it("only reads runs belonging to the requested org, newest first", async () => {
    await get();
    expect(state.runCalls).toContainEqual(["eq", "org_id", "org-1"]);
    expect(state.runCalls).toContainEqual(["order", "queued_at", { ascending: false }]);
  });

  it("returns each run with its property and the total count", async () => {
    state.runs = {
      data: [
        {
          id: "run-1",
          status: "succeeded",
          findings_count: 3,
          properties: { name: "Marketing site", kind: "url", target: "https://example.com" },
        },
      ],
      error: null,
      count: 41,
    };

    const res = await get();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      runs: [
        {
          id: "run-1",
          status: "succeeded",
          findings_count: 3,
          property: { name: "Marketing site", kind: "url", target: "https://example.com" },
        },
      ],
      total: 41,
    });
  });

  it("clamps limit to 1..100 and pages with offset", async () => {
    await get("?limit=500&offset=50");
    expect(state.runCalls).toContainEqual(["range", 50, 149]);

    state.runCalls = [];
    await get("?limit=0");
    expect(state.runCalls).toContainEqual(["range", 0, 0]);

    state.runCalls = [];
    await get("?limit=abc");
    expect(state.runCalls).toContainEqual(["range", 0, 24]);
  });

  it("filters by a known status and rejects unknown ones", async () => {
    await get("?status=failed");
    expect(state.runCalls).toContainEqual(["eq", "status", "failed"]);

    const res = await get("?status=exploded");
    expect(res.status).toBe(400);
  });

  it("reports a database failure as 500", async () => {
    state.runs = { data: null as unknown as unknown[], error: { message: "boom" }, count: 0 };
    expect((await get()).status).toBe(500);
  });
});
