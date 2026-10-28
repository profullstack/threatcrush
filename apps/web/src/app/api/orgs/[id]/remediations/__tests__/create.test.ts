import { describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const inserts: unknown[] = [];
const admin = {
  from() {
    const b = {
      select() { return b; },
      eq() { return b; },
      maybeSingle: async () => ({ data: { id: "s1", org_id: "o1", fleet_id: null }, error: null }),
      single: async () => ({ data: null, error: null }),
      insert(row: unknown) { inserts.push(row); return { select: () => ({ single: async () => ({ data: row, error: null }) }) }; },
    };
    return b;
  },
};
vi.mock("@/lib/route-access", () => ({
  requireOrgScope: async () => ({ admin, p: { kind: "user", userId: "u1", email: null }, scope: { all: true, fleetRoles: new Map(), unfleeted: "admin" } }),
  visibleServerIds: async () => null,
}));
vi.mock("@/lib/access", () => ({ atLeast: () => true, serverRoleOf: async () => "admin" }));

const { POST } = await import("../route");
const post = (body: unknown) =>
  POST(new NextRequest("https://threatcrush.com/api/orgs/o1/remediations", {
    method: "POST",
    headers: { authorization: "Bearer t", "content-type": "application/json" },
    body: JSON.stringify(body),
  }), { params: Promise.resolve({ id: "o1" }) });

describe("POST /api/orgs/:id/remediations target checks", () => {
  it("refuses an allowlist_add wide enough to disable blocking", async () => {
    for (const target_value of ["0.0.0.0/0", "::/0", "garbage"]) {
      expect((await post({ server_id: "s1", action_type: "allowlist_add", target_value })).status).toBe(400);
    }
  });

  it("refuses a block that is not a single address", async () => {
    expect((await post({ server_id: "s1", action_type: "block", target_value: "0.0.0.0/0" })).status).toBe(400);
    expect(inserts).toHaveLength(0);
  });

  it("queues a normal block", async () => {
    expect((await post({ server_id: "s1", action_type: "block", target_value: "203.0.113.9" })).status).toBe(201);
    expect(inserts).toHaveLength(1);
  });
});
