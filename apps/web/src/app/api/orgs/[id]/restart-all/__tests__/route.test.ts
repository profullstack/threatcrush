import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// Minimal supabase stand-in: servers + organization_members, capturing inserts.
type Row = Record<string, unknown>;
const db: Record<string, Row[]> = {};
const inserted: Row[] = [];
let signedInAs: string | null = "owner";

function builder(table: string) {
  const filters: Array<(r: Row) => boolean> = [];
  const b = {
    select() { return b; },
    insert(rows: Row[]) { inserted.push(...rows); return { error: null }; },
    eq(c: string, v: unknown) { filters.push((r) => r[c] === v); return b; },
    async maybeSingle() { const r = (db[table] ?? []).filter((x) => filters.every((f) => f(x))); return { data: r[0] ?? null, error: null }; },
    then(resolve: (v: unknown) => void) { resolve({ data: (db[table] ?? []).filter((x) => filters.every((f) => f(x))), error: null }); },
  };
  return b;
}
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (t: string) => builder(t) }) }));
vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: async () => (signedInAs ? { userId: signedInAs, email: null, githubLogin: null } : null),
  unauthorized: () => new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 }),
}));

const { POST } = await import("../route");
const ORG = "o1";
const post = () => POST(new NextRequest(`https://threatcrush.com/api/orgs/${ORG}/restart-all`, { method: "POST" }), { params: Promise.resolve({ id: ORG }) });

beforeEach(() => {
  for (const k of Object.keys(db)) delete db[k];
  inserted.length = 0;
  signedInAs = "owner";
  db.organization_members = [{ org_id: ORG, user_id: "owner", role: "owner" }];
  db.servers = [
    { id: "s1", org_id: ORG, fleet_id: null },
    { id: "s2", org_id: ORG, fleet_id: null },
  ];
});

describe("POST /api/orgs/:id/restart-all", () => {
  it("queues a restart for every server an org owner administers", async () => {
    const res = await post();
    expect(res.status).toBe(200);
    expect((await res.json()).queued).toBe(2);
    expect(inserted).toHaveLength(2);
    expect(inserted.every((r) => r.action_type === "restart" && r.status === "pending" && r.target_value === "daemon")).toBe(true);
    expect(new Set(inserted.map((r) => r.server_id))).toEqual(new Set(["s1", "s2"]));
  });

  it("401s when not signed in", async () => {
    signedInAs = null;
    expect((await post()).status).toBe(401);
  });

  it("403s a member with no admin servers (fleet-less servers need org admin)", async () => {
    db.organization_members = [{ org_id: ORG, user_id: "owner", role: "guest" }];
    const res = await post();
    expect(res.status).toBe(403);
    expect(inserted).toHaveLength(0);
  });
});
