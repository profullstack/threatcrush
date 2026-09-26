import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery } from "@/__tests__/helpers/query-recorder";

const state = {
  membership: { role: "member" } as { role: string } | null,
  server: { id: "srv-1" } as { id: string } | null,
  rpc: vi.fn(),
  rpcResult: { data: [] as unknown[], error: null as unknown },
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
      if (table === "servers") return recordQuery({ data: state.server, error: null });
      throw new Error(`Unexpected table ${table}`);
    },
    rpc: (name: string, args: unknown) => {
      state.rpc(name, args);
      return Promise.resolve(state.rpcResult);
    },
  }),
}));

import { POST } from "@/app/api/orgs/[id]/servers/[server_id]/remediations/claim/route";

function claim(token: string | null = "good-token") {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const req = new Request("http://localhost/api/orgs/org-1/servers/srv-1/remediations/claim", {
    method: "POST",
    headers,
  });
  return POST(req as unknown as NextRequest, {
    params: Promise.resolve({ id: "org-1", server_id: "srv-1" }),
  });
}

describe("POST /api/orgs/:id/servers/:server_id/remediations/claim", () => {
  beforeEach(() => {
    state.membership = { role: "member" };
    state.server = { id: "srv-1" };
    state.rpc = vi.fn();
    state.rpcResult = { data: [], error: null };
  });

  it("rejects a missing or invalid bearer token", async () => {
    expect((await claim(null)).status).toBe(401);
    expect((await claim("forged")).status).toBe(401);
    expect(state.rpc).not.toHaveBeenCalled();
  });

  it("refuses callers who are not members of the org", async () => {
    state.membership = null;
    expect((await claim()).status).toBe(403);
    expect(state.rpc).not.toHaveBeenCalled();
  });

  it("refuses a server that isn't in the org, so nothing is claimed", async () => {
    state.server = null;
    expect((await claim()).status).toBe(404);
    expect(state.rpc).not.toHaveBeenCalled();
  });

  it("returns claimed actions oldest first in the contract shape", async () => {
    state.rpcResult = {
      data: [
        {
          id: "a-2", organization_id: "org-1", server_id: "srv-1", action_type: "unblock",
          target_value: "203.0.113.9", status: "executing", expires_at: null,
          metadata: { claimed_at: "2026-09-25T10:00:00Z" }, created_at: "2026-09-25T09:59:00Z",
        },
        {
          id: "a-1", organization_id: "org-1", server_id: "srv-1", action_type: "block",
          target_value: "203.0.113.9", status: "executing", expires_at: "2026-09-25T11:00:00Z",
          metadata: null, created_at: "2026-09-25T09:58:00Z",
        },
      ],
      error: null,
    };
    const res = await claim();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      actions: [
        {
          id: "a-1", action_type: "block", target_value: "203.0.113.9",
          expires_at: "2026-09-25T11:00:00Z", metadata: {}, created_at: "2026-09-25T09:58:00Z",
        },
        {
          id: "a-2", action_type: "unblock", target_value: "203.0.113.9", expires_at: null,
          metadata: { claimed_at: "2026-09-25T10:00:00Z" }, created_at: "2026-09-25T09:59:00Z",
        },
      ],
    });
  });

  it("reports a database failure as 500", async () => {
    state.rpcResult = { data: null as unknown as unknown[], error: { message: "boom" } };
    expect((await claim()).status).toBe(500);
  });
});
