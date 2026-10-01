import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash } from "node:crypto";

// In-memory tables behind a PostgREST-shaped builder with just the calls the
// invite route and lib/access make.
type Row = Record<string, unknown>;
const db: Record<string, Row[]> = {};
let signedInAs: string | null = null;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

function builder(table: string) {
  const filters: Array<(r: Row) => boolean> = [];
  let op: "select" | "insert" | "update" | "upsert" = "select";
  let payload: Row = {};
  const rows = () => (db[table] ??= []);
  const run = (): Row[] => {
    if (op === "insert") { rows().push({ ...payload }); return [payload]; }
    if (op === "upsert") {
      const existing = rows().find((r) => r.team_id === payload.team_id && r.user_id === payload.user_id);
      if (existing) Object.assign(existing, payload); else rows().push({ ...payload });
      return [payload];
    }
    const matched = rows().filter((r) => filters.every((f) => f(r)));
    if (op === "update") for (const r of matched) Object.assign(r, payload);
    return matched.map((r) =>
      table === "team_invites" ? { ...r, organizations: { name: "Profullstack" }, teams: { name: "Ops" } } : r);
  };
  const b = {
    select() { return b; },
    insert(p: Row) { op = "insert"; payload = p; return b; },
    update(p: Row) { op = "update"; payload = p; return b; },
    upsert(p: Row) { op = "upsert"; payload = p; return b; },
    eq(c: string, v: unknown) { filters.push((r) => r[c] === v); return b; },
    is(c: string, v: unknown) { filters.push((r) => (r[c] ?? null) === v); return b; },
    gt(c: string, v: string) { filters.push((r) => String(r[c]) > v); return b; },
    async maybeSingle() { return { data: run()[0] ?? null, error: null }; },
    then(resolve: (v: unknown) => void) { resolve({ data: run(), error: null }); },
  };
  return b;
}

vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (t: string) => builder(t) }) }));
vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: async () => (signedInAs ? { userId: signedInAs, email: `${signedInAs}@example.com`, githubLogin: null } : null),
  unauthorized: () => new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 }),
}));

const { GET, POST } = await import("../[token]/route");
const { getPrincipal } = await import("@/lib/access");

const TOKEN = "t".repeat(43);
const req = (method = "GET", auth?: string) =>
  new NextRequest(`https://threatcrush.com/api/invites/${TOKEN}`, { method, headers: auth ? { authorization: auth } : {} });
const ctx = { params: Promise.resolve({ token: TOKEN }) };

beforeEach(() => {
  for (const k of Object.keys(db)) delete db[k];
  signedInAs = null;
  db.organizations = [{ id: "o1", slug: "profullstack" }];
  db.team_invites = [{
    id: "inv1", org_id: "o1", team_id: "t1", email: "new@example.com", role: "write",
    token_hash: sha(TOKEN), expires_at: new Date(Date.now() + 86_400_000).toISOString(),
    accepted_at: null, revoked_at: null,
  }];
});

describe("invites", () => {
  it("previews without sign-in and reveals only what the page shows", async () => {
    const res = await GET(req(), ctx);
    expect(await res.json()).toEqual({
      invite: expect.objectContaining({ org_name: "Profullstack", team_name: "Ops", role: "write", status: "pending" }),
    });
  });

  it("requires sign-in to accept", async () => {
    expect((await POST(req("POST"), ctx)).status).toBe(401);
  });

  it("adds a newcomer to the org as a guest and to the team with the invited role, once", async () => {
    signedInAs = "u-new";
    const res = await POST(req("POST"), ctx);
    expect(await res.json()).toMatchObject({ accepted: true, org_slug: "profullstack", team_id: "t1", role: "write" });
    expect(db.organization_members).toEqual([{ org_id: "o1", user_id: "u-new", role: "guest" }]);
    expect(db.team_members).toEqual([{ team_id: "t1", user_id: "u-new", role: "write" }]);

    // The link is spent.
    expect((await POST(req("POST"), ctx)).status).toBe(410);
  });

  it("never lowers a role the person already has, or their org role", async () => {
    signedInAs = "u-admin";
    db.organization_members = [{ org_id: "o1", user_id: "u-admin", role: "member" }];
    db.team_members = [{ team_id: "t1", user_id: "u-admin", role: "admin" }];
    await POST(req("POST"), ctx);
    expect(db.organization_members).toEqual([{ org_id: "o1", user_id: "u-admin", role: "member" }]);
    expect(db.team_members).toEqual([{ team_id: "t1", user_id: "u-admin", role: "admin" }]);
  });

  it("refuses an expired or revoked invite", async () => {
    signedInAs = "u-new";
    db.team_invites[0].revoked_at = new Date().toISOString();
    expect((await POST(req("POST"), ctx)).status).toBe(410);
    expect(db.team_members ?? []).toEqual([]);
  });
});

describe("agent keys", () => {
  const KEY = `tc_agent_${"k".repeat(43)}`;
  beforeEach(() => {
    db.agent_keys = [{ id: "key1", org_id: "o1", team_id: "t1", role: "read", name: "claude", key_hash: sha(KEY), revoked_at: null }];
  });

  it("authenticates a live key as an agent scoped to its team and role", async () => {
    const p = await getPrincipal(req("GET", `Bearer ${KEY}`), (await import("@/lib/supabase")).getSupabaseAdmin());
    expect(p).toEqual({ kind: "agent", keyId: "key1", orgId: "o1", teamId: "t1", role: "read", name: "claude" });
    expect(db.agent_keys[0].last_used_at).toBeTruthy();
  });

  it("refuses a revoked or unknown key, and never falls back to a user session", async () => {
    signedInAs = "u-new";
    db.agent_keys[0].revoked_at = new Date().toISOString();
    const admin = (await import("@/lib/supabase")).getSupabaseAdmin();
    expect(await getPrincipal(req("GET", `Bearer ${KEY}`), admin)).toBeNull();
    expect(await getPrincipal(req("GET", `Bearer tc_agent_${"x".repeat(43)}`), admin)).toBeNull();
  });
});
