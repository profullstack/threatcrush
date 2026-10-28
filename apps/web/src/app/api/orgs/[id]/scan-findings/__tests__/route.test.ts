import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

let role: string | null = "write";
let principal: unknown = { kind: "user", userId: "u1", email: null };
const updates: Array<{ patch: Record<string, unknown>; ids: unknown[] }> = [];

vi.mock("@/lib/access", () => ({
  getPrincipal: async () => principal,
  findingsRoleOf: async () => role,
  atLeast: (r: string | null, min: string) => !!r && ["read", "write", "admin"].indexOf(r) >= ["read", "write", "admin"].indexOf(min),
}));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      update: (patch: Record<string, unknown>) => {
        const q = {
          eq: () => q,
          in: (_k: string, ids: unknown[]) => { updates.push({ patch, ids }); return q; },
          select: async () => ({ data: updates.at(-1)!.ids.map((id) => ({ id, status: patch.status, note: patch.note })), error: null }),
        };
        return q;
      },
    }),
  }),
}));


import { PATCH } from "@/app/api/orgs/[id]/scan-findings/route";
import { POST as report } from "@/app/api/orgs/[id]/scan-findings/report/route";

const ID = "0b9c3f2e-6a1d-4c55-9f3e-2d4b8a7c1e90";
const req = (body: unknown) =>
  new Request("http://x/api/orgs/o1/scan-findings", { method: "PATCH", body: typeof body === "string" ? body : JSON.stringify(body) }) as never;
const ctx = { params: Promise.resolve({ id: "o1" }) };

describe("PATCH /api/orgs/[id]/scan-findings", () => {
  beforeEach(() => { role = "write"; principal = { kind: "user", userId: "u1", email: null }; updates.length = 0; });

  it("needs a principal and write", async () => {
    principal = null;
    expect((await PATCH(req({ ids: [ID], status: "fixed" }), ctx)).status).toBe(401);
    principal = { kind: "user", userId: "u1", email: null };
    role = "read";
    expect((await PATCH(req({ ids: [ID], status: "fixed" }), ctx)).status).toBe(403);
    expect(updates).toHaveLength(0);
  });

  it("validates ids, status and note", async () => {
    expect((await PATCH(req({ ids: ["not-a-uuid"], status: "fixed" }), ctx)).status).toBe(400);
    expect((await PATCH(req({ ids: [ID], status: "deleted" }), ctx)).status).toBe(400);
    expect((await PATCH(req({ ids: [ID], note: 5 }), ctx)).status).toBe(400);
    expect((await PATCH(req({ ids: [ID] }), ctx)).status).toBe(400);
  });

  it("records who triaged it, and resolves only closing statuses", async () => {
    expect((await PATCH(req({ ids: [ID], status: "false_positive", note: "test fixture" }), ctx)).status).toBe(200);
    expect(updates[0].patch).toMatchObject({ status: "false_positive", status_changed_by: "u1", status_source: "user", note: "test fixture" });
    expect(updates[0].patch.resolved_at).toBeTruthy();
    await PATCH(req({ ids: [ID], status: "acknowledged" }), ctx);
    expect(updates[1].patch.resolved_at).toBeNull();
  });

  it("an agent key's triage is marked as the agent's", async () => {
    principal = { kind: "agent", keyId: "k", orgId: "o1", teamId: "t", role: "write", name: "ci" };
    await PATCH(req({ ids: [ID], status: "ignored" }), ctx);
    expect(updates[0].patch).toMatchObject({ status_changed_by: null, status_source: "agent" });
  });
});

describe("POST /api/orgs/[id]/scan-findings/report", () => {
  beforeEach(() => { role = "write"; principal = { kind: "user", userId: "u1", email: null }; });
  const post = (body: unknown) => report(new Request("http://x", { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) }) as never, ctx);

  it("needs write and a valid source + target", async () => {
    role = "read";
    expect((await post({ source: "scan", target: "x" })).status).toBe(403);
    role = "write";
    expect((await post("{nope")).status).toBe(400);
    expect((await post({ source: "deploy", target: "x" })).status).toBe(400);
    expect((await post({ source: "scan", target: "  " })).status).toBe(400);
  });
});
