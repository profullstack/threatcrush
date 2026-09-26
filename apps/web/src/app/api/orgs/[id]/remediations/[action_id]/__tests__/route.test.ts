import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall } from "@/__tests__/helpers/query-recorder";

type Row = { id: string; status: string; metadata: Record<string, unknown> | null } | null;

const state = {
  membership: { role: "member" } as { role: string } | null,
  // Each from("remediation_actions") takes the next result: the read, then the
  // guarded update.
  actionResults: [] as Array<{ data: unknown; error: unknown }>,
  actionCalls: [] as QueryCall[][],
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: async (token: string) =>
        token === "good-token"
          ? { data: { user: { id: "user-1", email: "a@example.com", user_metadata: {} } }, error: null }
          : { data: { user: null }, error: { message: "bad jwt" } },
    },
  }),
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "organization_members") return recordQuery({ data: state.membership, error: null });
      if (table === "remediation_actions") {
        const calls: QueryCall[] = [];
        state.actionCalls.push(calls);
        return recordQuery(state.actionResults.shift() ?? { data: null, error: null }, calls);
      }
      throw new Error(`Unexpected table ${table}`);
    },
  }),
}));

import { PATCH } from "@/app/api/orgs/[id]/remediations/[action_id]/route";

function patch(body: unknown, token: string | null = "good-token") {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const req = new Request("http://localhost/api/orgs/org-1/remediations/act-1", {
    method: "PATCH",
    headers,
    body: JSON.stringify(body),
  });
  return PATCH(req as unknown as NextRequest, {
    params: Promise.resolve({ id: "org-1", action_id: "act-1" }),
  });
}

function stored(row: Row) {
  state.actionResults.push({ data: row, error: null });
}

function updateCall(): unknown {
  return state.actionCalls[1]?.find(([m]) => m === "update")?.[1];
}

describe("PATCH /api/orgs/:id/remediations/:action_id", () => {
  beforeEach(() => {
    state.membership = { role: "member" };
    state.actionResults = [];
    state.actionCalls = [];
  });

  it("rejects a missing or invalid bearer token", async () => {
    expect((await patch({ status: "executed" }, null)).status).toBe(401);
    expect((await patch({ status: "executed" }, "forged")).status).toBe(401);
  });

  it("refuses callers who are not members of the org", async () => {
    state.membership = null;
    expect((await patch({ status: "executed" })).status).toBe(403);
    expect(state.actionCalls).toEqual([]);
  });

  it("only accepts executed or failed as the outcome", async () => {
    for (const status of ["pending", "executing", "reversed", undefined]) {
      expect((await patch({ status })).status).toBe(400);
    }
    expect((await patch({ status: "executed", dry_run: "yes" })).status).toBe(400);
    expect((await patch({ status: "executed", executed_at: "soonish" })).status).toBe(400);
    expect(state.actionCalls).toEqual([]);
  });

  it("returns 404 for an action outside the org", async () => {
    stored(null);
    expect((await patch({ status: "executed" })).status).toBe(404);
  });

  it.each(["pending", "executed", "failed", "expired", "reversed"])(
    "returns 409 when the action is %s instead of executing",
    async (status) => {
      stored({ id: "act-1", status, metadata: {} });
      expect((await patch({ status: "executed" })).status).toBe(409);
      expect(updateCall()).toBeUndefined();
    },
  );

  it("completes an executing action and keeps its claim metadata", async () => {
    stored({ id: "act-1", status: "executing", metadata: { claimed_at: "2026-09-25T10:00:00Z" } });
    state.actionResults.push({ data: { id: "act-1", status: "executed" }, error: null });

    const res = await patch({ status: "executed", dry_run: true, executed_at: "2026-09-25T10:00:30Z" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ action: { id: "act-1", status: "executed" } });
    expect(updateCall()).toEqual({
      status: "executed",
      executed_at: "2026-09-25T10:00:30.000Z",
      metadata: { claimed_at: "2026-09-25T10:00:00Z", dry_run: true },
    });
    // The write is guarded on the status it was read in.
    expect(state.actionCalls[1]).toContainEqual(["eq", "status", "executing"]);
  });

  it("records the failure reason", async () => {
    stored({ id: "act-1", status: "executing", metadata: {} });
    state.actionResults.push({ data: { id: "act-1", status: "failed" }, error: null });

    await patch({ status: "failed", error: "203.0.113.9 is allowlisted" });
    expect(updateCall()).toMatchObject({
      status: "failed",
      metadata: { error: "203.0.113.9 is allowlisted" },
    });
  });

  it("returns 409 when the action stopped executing between read and write", async () => {
    stored({ id: "act-1", status: "executing", metadata: {} });
    state.actionResults.push({ data: null, error: null });
    expect((await patch({ status: "executed" })).status).toBe(409);
  });
});
