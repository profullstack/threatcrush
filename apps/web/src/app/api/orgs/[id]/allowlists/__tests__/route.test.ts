import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const inserted: Array<Record<string, unknown>> = [];
let role = "owner";
const admin = {
  auth: { getUser: async () => ({ data: { user: { id: "u1" } } }) },
  from(table: string) {
    const b = {
      select() { return b; },
      eq() { return b; },
      order: async () => ({ data: [{ id: "a1", type: "ip", value: "203.0.113.9" }], error: null }),
      single: async () => (table === "organization_members" ? { data: { role }, error: null } : { data: inserted.at(-1), error: null }),
      insert(row: Record<string, unknown>) { inserted.push(row); return b; },
    };
    return b;
  },
};
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => admin }));

const { GET, POST } = await import("../route");
const params = { params: Promise.resolve({ id: "o1" }) };
const req = (method: string, body?: unknown) =>
  new NextRequest("https://threatcrush.com/api/orgs/o1/allowlists", {
    method,
    headers: { authorization: "Bearer t", "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

beforeEach(() => {
  inserted.length = 0;
  role = "owner";
});

describe("org allowlist", () => {
  it("refuses entries that would stop every daemon in the org blocking anything", async () => {
    for (const value of ["0.0.0.0/0", "::/0", "0.0.0.0/1", "not-an-ip"]) {
      const res = await POST(req("POST", { type: "cidr", value }), params);
      expect(res.status).toBe(400);
    }
    expect(inserted).toHaveLength(0);
  });

  it("takes a normal address", async () => {
    const res = await POST(req("POST", { type: "ip", value: " 203.0.113.9 " }), params);
    expect(res.status).toBe(201);
    expect(inserted[0]).toMatchObject({ organization_id: "o1", value: "203.0.113.9" });
  });

  it("does not show the org list to a guest", async () => {
    role = "guest";
    expect((await GET(req("GET"), params)).status).toBe(403);
    role = "member";
    expect((await GET(req("GET"), params)).status).toBe(200);
  });
});
