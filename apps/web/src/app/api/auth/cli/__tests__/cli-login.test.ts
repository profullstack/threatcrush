import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash, randomBytes } from "node:crypto";

// An in-memory cli_login_requests table behind a query builder with just the
// calls the routes make: insert/select/update, eq/gt filters, single/maybeSingle.
type Row = Record<string, unknown>;
const rows: Row[] = [];
let signedInAs: string | null = null;
let minted = 0;

function builder(table: string) {
  const filters: Array<(r: Row) => boolean> = [];
  let op: "select" | "insert" | "update" = "select";
  let payload: Row = {};

  const run = (): Row[] => {
    if (table !== "cli_login_requests") return [];
    if (op === "insert") {
      const row: Row = {
        id: crypto.randomUUID(),
        status: "pending",
        user_id: null,
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        ...payload,
      };
      rows.push(row);
      return [row];
    }
    const matched = rows.filter((r) => filters.every((f) => f(r)));
    if (op === "update") for (const r of matched) Object.assign(r, payload);
    return matched;
  };

  const b = {
    insert(p: Row) { op = "insert"; payload = p; return b; },
    update(p: Row) { op = "update"; payload = p; return b; },
    select() { return b; },
    eq(col: string, val: unknown) { filters.push((r) => r[col] === val); return b; },
    gt(col: string, val: string) { filters.push((r) => String(r[col]) > val); return b; },
    async single() { const [r] = run(); return r ? { data: r, error: null } : { data: null, error: { message: "none" } }; },
    async maybeSingle() { const [r] = run(); return { data: r ?? null, error: null }; },
  };
  return b;
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => builder(table),
    auth: {
      admin: {
        getUserById: async (id: string) => ({ data: { user: { id, email: `${id}@example.com` } }, error: null }),
      },
    },
  }),
}));

vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: async () => (signedInAs ? { userId: signedInAs, email: null, githubLogin: null } : null),
  unauthorized: () => new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 }),
}));

vi.mock("@/lib/cli-login", async (importOriginal) => {
  const real = await importOriginal<typeof import("@/lib/cli-login")>();
  return {
    ...real,
    mintSession: async (_admin: unknown, email: string) => {
      minted++;
      return {
        user: { id: email.split("@")[0], email },
        session: { access_token: `access-${minted}`, refresh_token: `refresh-${minted}`, expires_at: 1 },
      };
    },
  };
});

const { POST: start } = await import("../start/route");
const { GET: getRequest } = await import("../request/route");
const { POST: approve } = await import("../approve/route");
const { POST: token } = await import("../token/route");

function post(path: string, body: unknown) {
  return new NextRequest(`https://threatcrush.com${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

async function begin(p = pkce()) {
  const res = await start(post("/api/auth/cli/start", {
    code_challenge: p.challenge,
    code_challenge_method: "S256",
    device_name: "dev2 <script>",
  }));
  return { p, res, data: await res.json() };
}

beforeEach(() => {
  rows.length = 0;
  signedInAs = null;
  minted = 0;
});

describe("CLI login by link", () => {
  it("starts a request and returns a link with a confirmation code", async () => {
    const { res, data } = await begin();
    expect(res.status).toBe(200);
    expect(data.verification_url).toBe(`https://threatcrush.com/cli/login?request=${data.request_id}`);
    expect(data.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(rows[0].device_name).toBe("dev2 script");
  });

  it("refuses a plain challenge: only S256", async () => {
    const res = await start(post("/api/auth/cli/start", { code_challenge: "x".repeat(43), code_challenge_method: "plain" }));
    expect(res.status).toBe(400);
  });

  it("keeps the CLI waiting until someone approves, then hands it a session once", async () => {
    const { p, data } = await begin();
    const poll = () => token(post("/api/auth/cli/token", { request_id: data.request_id, code_verifier: p.verifier }));

    const pending = await poll();
    expect(await pending.json()).toEqual({ error: "authorization_pending" });

    signedInAs = "anthony";
    const approved = await approve(post("/api/auth/cli/approve", { request_id: data.request_id, approve: true }));
    expect(approved.status).toBe(200);

    const done = await poll();
    expect(done.status).toBe(200);
    expect(await done.json()).toMatchObject({ user: { id: "anthony" }, session: { access_token: "access-1" } });

    // A replayed poll must not mint a second session.
    const replay = await poll();
    expect(await replay.json()).toEqual({ error: "invalid_grant" });
    expect(minted).toBe(1);
  });

  it("never redeems with the wrong verifier, and does not burn the request trying", async () => {
    const { p, data } = await begin();
    signedInAs = "anthony";
    await approve(post("/api/auth/cli/approve", { request_id: data.request_id, approve: true }));

    const wrong = await token(post("/api/auth/cli/token", { request_id: data.request_id, code_verifier: pkce().verifier }));
    expect(await wrong.json()).toEqual({ error: "invalid_grant" });
    expect(minted).toBe(0);

    const right = await token(post("/api/auth/cli/token", { request_id: data.request_id, code_verifier: p.verifier }));
    expect(right.status).toBe(200);
  });

  it("reports a denial to the CLI", async () => {
    const { p, data } = await begin();
    signedInAs = "anthony";
    await approve(post("/api/auth/cli/approve", { request_id: data.request_id, approve: false }));
    const res = await token(post("/api/auth/cli/token", { request_id: data.request_id, code_verifier: p.verifier }));
    expect(await res.json()).toEqual({ error: "access_denied" });
  });

  it("reports an expired request instead of waiting forever", async () => {
    const { p, data } = await begin();
    rows[0].expires_at = new Date(Date.now() - 1000).toISOString();
    const res = await token(post("/api/auth/cli/token", { request_id: data.request_id, code_verifier: p.verifier }));
    expect(await res.json()).toEqual({ error: "expired_token" });
  });

  it("only lets a signed-in user see or approve a request, and only once", async () => {
    const { data } = await begin();
    const view = () => getRequest(new NextRequest(`https://threatcrush.com/api/auth/cli/request?id=${data.request_id}`));

    expect((await view()).status).toBe(401);
    expect((await approve(post("/api/auth/cli/approve", { request_id: data.request_id, approve: true }))).status).toBe(401);

    signedInAs = "anthony";
    expect(await (await view()).json()).toMatchObject({ request: { user_code: data.user_code, status: "pending" } });
    expect((await approve(post("/api/auth/cli/approve", { request_id: data.request_id, approve: true }))).status).toBe(200);
    expect((await approve(post("/api/auth/cli/approve", { request_id: data.request_id, approve: false }))).status).toBe(409);
  });
});
