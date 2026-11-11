import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash, randomBytes } from "node:crypto";

// In-memory tables behind a query builder with just the calls lib/mcp-oauth.ts
// makes: insert/select/update, eq/is/gt filters, order, maybeSingle.
type Row = Record<string, unknown>;
const tables: Record<string, Row[]> = {};
let signedInAs: string | null = null;

function builder(table: string) {
  const filters: Array<(r: Row) => boolean> = [];
  let op: "select" | "insert" | "update" = "select";
  let payload: Row = {};
  const rows = () => (tables[table] ??= []);

  const run = (): Row[] => {
    if (op === "insert") {
      const row: Row = { id: crypto.randomUUID(), created_at: new Date().toISOString(), revoked_at: null, used_at: null, last_used_at: null, ...payload };
      rows().push(row);
      return [row];
    }
    const matched = rows().filter((r) => filters.every((f) => f(r)));
    if (op === "update") for (const r of matched) Object.assign(r, payload);
    return matched.map((r) => (table === "oauth_tokens" ? { ...r, oauth_clients: (tables.oauth_clients ?? []).find((c) => c.client_id === r.client_id) } : r));
  };

  const b = {
    insert(p: Row) { op = "insert"; payload = p; return Promise.resolve({ data: null, error: (run(), null) }); },
    update(p: Row) { op = "update"; payload = p; return b; },
    select() { return b; },
    order() { return b; },
    eq(col: string, val: unknown) { filters.push((r) => r[col] === val); return b; },
    is(col: string, val: unknown) { filters.push((r) => (r[col] ?? null) === val); return b; },
    gt(col: string, val: string) { filters.push((r) => String(r[col]) > val); return b; },
    async maybeSingle() { const [r] = run(); return { data: r ?? null, error: null }; },
    then(resolve: (v: { data: Row[]; error: null }) => void) { resolve({ data: run(), error: null }); },
  };
  return b;
}

vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (t: string) => builder(t) }) }));
vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: async () => (signedInAs ? { userId: signedInAs, email: null, githubLogin: null } : null),
  unauthorized: () => new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 }),
}));

const { POST: register } = await import("../register/route");
const { POST: token } = await import("../token/route");
const { GET: checkReq, POST: decide } = await import("../authorize/route");
const { GET: listGrants, DELETE: dropGrant } = await import("../grants/route");
const { POST: revoke } = await import("../revoke/route");
const { GET: resourceMeta } = await import("../../../.well-known/oauth-protected-resource/route");
const { GET: asMeta } = await import("../../../.well-known/oauth-authorization-server/route");
const oauth = await import("@/lib/mcp-oauth");

const CLAUDE = "https://claude.ai/api/mcp/auth_callback";
const json = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  new NextRequest(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const form = (body: Record<string, string>) =>
  new NextRequest("https://threatcrush.com/api/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

async function newClient(redirect_uris = [CLAUDE, "http://localhost:33418/callback"]) {
  const res = await register(json("https://threatcrush.com/api/oauth/register", { client_name: "Claude", redirect_uris }));
  expect(res.status).toBe(201);
  return (await res.json()) as { client_id: string };
}

async function authorize(clientId: string, challenge: string, redirect = CLAUDE) {
  signedInAs = "user-1";
  const res = await decide(
    json("https://threatcrush.com/api/oauth/authorize", {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirect,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: "xyz",
      resource: "https://threatcrush.com/api/mcp",
      approve: true,
    }),
  );
  const { redirect: to } = (await res.json()) as { redirect: string };
  const u = new URL(to);
  expect(u.searchParams.get("state")).toBe("xyz");
  return u.searchParams.get("code")!;
}

beforeEach(() => {
  for (const k of Object.keys(tables)) delete tables[k];
  signedInAs = null;
});

describe("discovery", () => {
  it("serves protected-resource and authorization-server metadata", async () => {
    const r = await resourceMeta().json();
    expect(r).toMatchObject({ resource: "https://threatcrush.com/api/mcp", authorization_servers: ["https://threatcrush.com"], bearer_methods_supported: ["header"] });
    const a = await asMeta().json();
    expect(a).toMatchObject({
      issuer: "https://threatcrush.com",
      authorization_endpoint: "https://threatcrush.com/oauth/authorize",
      token_endpoint: "https://threatcrush.com/api/oauth/token",
      registration_endpoint: "https://threatcrush.com/api/oauth/register",
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  });
});

describe("redirect URIs", () => {
  it("allows https and loopback http, nothing else", () => {
    for (const ok of [CLAUDE, "https://claude.com/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect", "https://platform.openai.com/apps-manage/oauth", "http://localhost:3000/cb", "http://127.0.0.1/cb"]) {
      expect(oauth.isAllowedRedirectUri(ok)).toBe(true);
    }
    for (const bad of ["http://evil.com/cb", "javascript:alert(1)", "https://a.com/cb#frag", "https://u:p@a.com/", "custom://x", 7]) {
      expect(oauth.isAllowedRedirectUri(bad)).toBe(false);
    }
  });

  it("matches exactly, except any port on loopback", () => {
    const reg = [CLAUDE, "http://localhost:33418/callback"];
    expect(oauth.redirectUriMatches(reg, CLAUDE)).toBe(true);
    expect(oauth.redirectUriMatches(reg, "http://localhost:50123/callback")).toBe(true);
    expect(oauth.redirectUriMatches(reg, "http://localhost:50123/other")).toBe(false);
    expect(oauth.redirectUriMatches(reg, "https://claude.ai/api/mcp/auth_callback2")).toBe(false);
  });
});

describe("registration", () => {
  it("refuses confidential clients and bad redirects", async () => {
    const conf = await register(json("https://threatcrush.com/api/oauth/register", { redirect_uris: [CLAUDE], token_endpoint_auth_method: "client_secret_basic" }));
    expect(conf.status).toBe(400);
    const bad = await register(json("https://threatcrush.com/api/oauth/register", { redirect_uris: ["http://evil.com/cb"] }));
    expect((await bad.json()).error).toBe("invalid_redirect_uri");
  });
});

describe("authorize", () => {
  it("shows an unknown client or redirect as an error, never a redirect", async () => {
    const { client_id } = await newClient();
    const unknown = await checkReq(new NextRequest("https://threatcrush.com/api/oauth/authorize?client_id=nope&redirect_uri=" + encodeURIComponent(CLAUDE)));
    expect(unknown.status).toBe(400);
    const wrongRedirect = await checkReq(
      new NextRequest(`https://threatcrush.com/api/oauth/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent("https://evil.com/cb")}`),
    );
    expect(wrongRedirect.status).toBe(400);
    expect((await wrongRedirect.json()).redirect).toBeUndefined();
  });

  it("sends a request without PKCE back to the client with an error", async () => {
    const { client_id } = await newClient();
    const res = await checkReq(
      new NextRequest(`https://threatcrush.com/api/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent(CLAUDE)}&state=s`),
    );
    const { redirect } = await res.json();
    expect(new URL(redirect).searchParams.get("error")).toBe("invalid_request");
    expect(new URL(redirect).searchParams.get("state")).toBe("s");
  });

  it("describes a valid request and needs a session to decide", async () => {
    const { client_id } = await newClient();
    const { challenge } = pkce();
    const q = `response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent(CLAUDE)}&code_challenge=${challenge}&code_challenge_method=S256`;
    const info = await (await checkReq(new NextRequest(`https://threatcrush.com/api/oauth/authorize?${q}`))).json();
    expect(info).toMatchObject({ client: { name: "Claude" }, redirect_host: "claude.ai" });
    const anon = await decide(json("https://threatcrush.com/api/oauth/authorize", { ...Object.fromEntries(new URLSearchParams(q)), approve: true }));
    expect(anon.status).toBe(401);
  });

  it("deny returns access_denied to the client", async () => {
    const { client_id } = await newClient();
    signedInAs = "user-1";
    const res = await decide(
      json("https://threatcrush.com/api/oauth/authorize", {
        response_type: "code", client_id, redirect_uri: CLAUDE, code_challenge: pkce().challenge, code_challenge_method: "S256", state: "q", approve: false,
      }),
    );
    const u = new URL((await res.json()).redirect);
    expect(u.searchParams.get("error")).toBe("access_denied");
    expect(u.searchParams.get("code")).toBeNull();
  });
});

describe("token", () => {
  it("full flow: code + PKCE -> tokens -> MCP principal -> refresh rotates -> revoke", async () => {
    const { client_id } = await newClient();
    const { verifier, challenge } = pkce();
    const code = await authorize(client_id, challenge);

    // Wrong verifier burns nothing useful: the code is single use either way.
    const bad = await token(form({ grant_type: "authorization_code", code, redirect_uri: CLAUDE, client_id, code_verifier: pkce().verifier }));
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("invalid_grant");

    const code2 = await authorize(client_id, challenge);
    const wrongRedirect = await token(form({ grant_type: "authorization_code", code: code2, redirect_uri: "https://claude.com/api/mcp/auth_callback", client_id, code_verifier: verifier }));
    expect(wrongRedirect.status).toBe(400);

    const code3 = await authorize(client_id, challenge);
    const res = await token(form({ grant_type: "authorization_code", code: code3, redirect_uri: CLAUDE, client_id, code_verifier: verifier }));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const t = await res.json();
    expect(t).toMatchObject({ token_type: "Bearer", expires_in: 3600, scope: "mcp" });
    expect(t.access_token.startsWith("tc_oat_")).toBe(true);
    expect(t.refresh_token.startsWith("tc_ort_")).toBe(true);

    // Only hashes are stored.
    const stored = JSON.stringify(tables.oauth_tokens);
    expect(stored).not.toContain(t.access_token);
    expect(stored).not.toContain(t.refresh_token);
    expect(JSON.stringify(tables.oauth_codes)).not.toContain(code3);

    // Replay of a used code fails.
    const replay = await token(form({ grant_type: "authorization_code", code: code3, redirect_uri: CLAUDE, client_id, code_verifier: verifier }));
    expect(replay.status).toBe(400);

    const admin = { from: (x: string) => builder(x) } as never;
    expect(await oauth.resolveAccessToken(admin, t.access_token)).toMatchObject({ kind: "user", userId: "user-1" });

    // Refresh rotates both tokens; the old refresh token and access token stop working.
    const r2 = await (await token(form({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id }))).json();
    expect(r2.access_token).not.toBe(t.access_token);
    expect(await oauth.resolveAccessToken(admin, t.access_token)).toBeNull();
    expect(await oauth.resolveAccessToken(admin, r2.access_token)).toMatchObject({ userId: "user-1" });
    const again = await token(form({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id }));
    expect(again.status).toBe(400);

    // Listed under Connected apps and revocable there.
    signedInAs = "user-1";
    const grants = (await (await listGrants(new NextRequest("https://threatcrush.com/api/oauth/grants"))).json()).grants;
    expect(grants).toHaveLength(1);
    expect(grants[0].client_name).toBe("Claude");
    signedInAs = "someone-else";
    expect((await dropGrant(new NextRequest(`https://threatcrush.com/api/oauth/grants?id=${grants[0].id}`, { method: "DELETE" }))).status).toBe(404);
    signedInAs = "user-1";
    expect((await dropGrant(new NextRequest(`https://threatcrush.com/api/oauth/grants?id=${grants[0].id}`, { method: "DELETE" }))).status).toBe(200);
    expect(await oauth.resolveAccessToken(admin, r2.access_token)).toBeNull();
  });

  it("RFC 7009 revoke ends the grant and always answers 200", async () => {
    const { client_id } = await newClient();
    const { verifier, challenge } = pkce();
    const code = await authorize(client_id, challenge);
    const t = await (await token(form({ grant_type: "authorization_code", code, redirect_uri: CLAUDE, client_id, code_verifier: verifier }))).json();
    expect((await revoke(form({ token: t.refresh_token }))).status).toBe(200);
    expect((await revoke(form({ token: "garbage" }))).status).toBe(200);
    const admin = { from: (x: string) => builder(x) } as never;
    expect(await oauth.resolveAccessToken(admin, t.access_token)).toBeNull();
  });

  it("loopback redirects work on another port (Claude Code)", async () => {
    const { client_id } = await newClient();
    const { verifier, challenge } = pkce();
    const cb = "http://localhost:50999/callback";
    const code = await authorize(client_id, challenge, cb);
    const res = await token(form({ grant_type: "authorization_code", code, redirect_uri: cb, client_id, code_verifier: verifier }));
    expect(res.status).toBe(200);
  });

  it("rejects unknown grant types", async () => {
    const res = await token(form({ grant_type: "password" }));
    expect((await res.json()).error).toBe("unsupported_grant_type");
  });
});
