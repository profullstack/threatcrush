import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall, type QueryResult } from "@/__tests__/helpers/query-recorder";

const TOKEN = "ExponentPushToken[abcDEF123_-xyz]";

const state = {
  membership: { role: "member" } as { role: string } | null,
  write: { data: { id: "sub-1", organization_id: "org-1" }, error: null } as QueryResult,
  subCalls: [] as QueryCall[],
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: async (token: string) =>
        token === "good-token"
          ? { data: { user: { id: "user-1", email: "a@example.com" } }, error: null }
          : { data: { user: null }, error: { message: "bad jwt" } },
    },
  }),
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "organization_members") {
        return recordQuery({ data: state.membership, error: null });
      }
      if (table === "push_subscriptions") return recordQuery(state.write, state.subCalls);
      throw new Error(`Unexpected table ${table}`);
    },
  }),
}));

import { DELETE, POST } from "@/app/api/orgs/[id]/push-subscriptions/route";

function request(method: string, body: unknown, token: string | null = "good-token") {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  return new Request("http://localhost/api/orgs/org-1/push-subscriptions", {
    method,
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  }) as unknown as NextRequest;
}

const ctx = () => ({ params: Promise.resolve({ id: "org-1" }) });

describe("POST /api/orgs/:id/push-subscriptions", () => {
  beforeEach(() => {
    state.membership = { role: "member" };
    state.write = { data: { id: "sub-1", organization_id: "org-1" }, error: null };
    state.subCalls = [];
  });

  it("requires a valid bearer token", async () => {
    const res = await POST(request("POST", { token: TOKEN, platform: "ios" }, null), ctx());
    expect(res.status).toBe(401);
    expect(state.subCalls).toEqual([]);
  });

  it("refuses non-members so a device cannot subscribe to another org's alerts", async () => {
    state.membership = null;
    const res = await POST(request("POST", { token: TOKEN, platform: "ios" }), ctx());
    expect(res.status).toBe(403);
    expect(state.subCalls).toEqual([]);
  });

  it.each([
    ["a URL instead of an Expo token", { token: "https://evil.example/hook", platform: "ios" }],
    ["a missing token", { platform: "android" }],
    ["an unknown platform", { token: TOKEN, platform: "windows" }],
    ["a non-object body", "[1,2]"],
    ["malformed JSON", "{"],
  ])("rejects %s with 400", async (_label, body) => {
    const res = await POST(request("POST", body), ctx());
    expect(res.status).toBe(400);
    expect(state.subCalls).toEqual([]);
  });

  it("upserts one row per (caller, token) bound to the org", async () => {
    const res = await POST(request("POST", { token: TOKEN, platform: "android" }), ctx());
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ subscription: { id: "sub-1", organization_id: "org-1" } });

    const upsert = state.subCalls.find(([m]) => m === "upsert");
    expect(upsert).toEqual([
      "upsert",
      {
        user_id: "user-1",
        organization_id: "org-1",
        endpoint: TOKEN,
        keys: { provider: "expo", platform: "android" },
      },
      { onConflict: "user_id,endpoint" },
    ]);
  });

  it("accepts the legacy ExpoPushToken prefix", async () => {
    const res = await POST(request("POST", { token: "ExpoPushToken[abc]", platform: "ios" }), ctx());
    expect(res.status).toBe(200);
  });

  it("reports a failed write as 500", async () => {
    state.write = { data: null, error: { message: "fk violation" } };
    const res = await POST(request("POST", { token: TOKEN, platform: "ios" }), ctx());
    expect(res.status).toBe(500);
  });
});

describe("DELETE /api/orgs/:id/push-subscriptions", () => {
  beforeEach(() => {
    state.membership = { role: "member" };
    state.write = { data: null, error: null };
    state.subCalls = [];
  });

  it("requires a valid bearer token", async () => {
    const res = await DELETE(request("DELETE", { token: TOKEN }, "forged"));
    expect(res.status).toBe(401);
    expect(state.subCalls).toEqual([]);
  });

  it("deletes only the caller's row for that token", async () => {
    const res = await DELETE(request("DELETE", { token: TOKEN }));
    expect(res.status).toBe(200);
    expect(state.subCalls).toContainEqual(["delete"]);
    expect(state.subCalls).toContainEqual(["eq", "user_id", "user-1"]);
    expect(state.subCalls).toContainEqual(["eq", "endpoint", TOKEN]);
  });

  it("still works after the caller has left the org", async () => {
    state.membership = null;
    const res = await DELETE(request("DELETE", { token: TOKEN }));
    expect(res.status).toBe(200);
  });

  it("rejects a token that is not an Expo push token", async () => {
    const res = await DELETE(request("DELETE", { token: "*" }));
    expect(res.status).toBe(400);
    expect(state.subCalls).toEqual([]);
  });
});
