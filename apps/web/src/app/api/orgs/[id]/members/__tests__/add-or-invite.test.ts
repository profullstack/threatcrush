import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// In-memory tables for the org add-member route and createOrgInvite.
type Row = Record<string, unknown>;
const db: Record<string, Row[]> = {};

function builder(table: string) {
  const filters: Array<(r: Row) => boolean> = [];
  let op: "select" | "insert" | "update" = "select";
  let payload: Row = {};
  const rows = () => (db[table] ??= []);
  const run = (): Row[] => {
    if (op === "insert") { const r = { id: `${table}-${rows().length + 1}`, ...payload }; rows().push(r); return [r]; }
    const matched = rows().filter((r) => filters.every((f) => f(r)));
    if (op === "update") for (const r of matched) Object.assign(r, payload);
    return matched;
  };
  const b = {
    select() { return b; },
    insert(p: Row) { op = "insert"; payload = p; return b; },
    update(p: Row) { op = "update"; payload = p; return b; },
    eq(c: string, v: unknown) { filters.push((r) => r[c] === v); return b; },
    is(c: string, v: unknown) { filters.push((r) => (r[c] ?? null) === v); return b; },
    async single() { const r = run(); return r[0] ? { data: r[0], error: null } : { data: null, error: { message: "none" } }; },
    async maybeSingle() { return { data: run()[0] ?? null, error: null }; },
    then(resolve: (v: unknown) => void) { resolve({ data: run(), error: null }); },
  };
  return b;
}

const admin = {
  from: (t: string) => builder(t),
  auth: { getUser: async (token: string) => (token === "owner-token" ? { data: { user: { id: "owner", email: "owner@acme.com" } } } : { data: { user: null } }) },
};
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => admin }));
// No email in tests.
vi.mock("resend", () => ({ Resend: class { emails = { send: async () => ({ error: null }) }; } }));

const { POST } = await import("../route");

const ORG = "o1";
function post(body: unknown, token = "owner-token") {
  return POST(
    new NextRequest(`https://threatcrush.com/api/orgs/${ORG}/members`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: ORG }) },
  );
}

beforeEach(() => {
  for (const k of Object.keys(db)) delete db[k];
  db.organizations = [{ id: ORG, name: "Acme" }];
  db.organization_members = [{ org_id: ORG, user_id: "owner", role: "owner" }];
  db.user_profiles = [{ id: "u-bob", email: "bob@acme.com" }];
});

describe("POST /api/orgs/:id/members", () => {
  it("adds an existing user directly, no invite", async () => {
    const res = await post({ email: "bob@acme.com", role: "member" });
    expect(res.status).toBe(201);
    expect(db.organization_members.some((m) => m.user_id === "u-bob" && m.role === "member")).toBe(true);
    expect(db.team_invites ?? []).toHaveLength(0);
  });

  it("invites a new email instead of dead-ending (the conversion fix)", async () => {
    const res = await post({ email: "New@Example.com", role: "member" });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body).toMatchObject({ invited: true, email: "new@example.com" });
    expect(body.url).toContain("/invite/");
    // An org invite: org_role set, no team_id, and no org membership created yet.
    const inv = db.team_invites[0];
    expect(inv.org_id).toBe(ORG);
    expect(inv.email).toBe("new@example.com");
    expect(inv.org_role).toBe("member");
    expect(inv.team_id).toBeUndefined();
    expect(inv.token_hash).toBeTruthy();
    // Only the hash is stored, never the token from the link.
    const token = body.url.split("/invite/")[1];
    expect(String(inv.token_hash)).not.toContain(token);
    expect(db.organization_members.some((m) => m.user_id !== "owner")).toBe(false);
  });

  it("still blocks a non-admin", async () => {
    db.organization_members = [{ org_id: ORG, user_id: "owner", role: "member" }];
    expect((await post({ email: "x@example.com" })).status).toBe(403);
  });
});
