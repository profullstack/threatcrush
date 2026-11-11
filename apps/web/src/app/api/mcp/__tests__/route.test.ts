import { describe, it, expect, vi } from "vitest";

vi.mock("@/lib/reputation-auth", () => ({
  reputationCallerFor: vi.fn(async (principal: unknown) => ({ admin: {}, principal, orgId: null, tier: "free", caller: "u1" })),
}));
vi.mock("@/lib/feed-auth", () => ({ feedPrincipal: vi.fn().mockResolvedValue(null) }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({}) }));
vi.mock("@/lib/reputation", () => ({ takeLookupShared: vi.fn(async () => ({ ok: true, limit: 100, remaining: 99 })) }));
vi.mock("@/lib/reputation-service", () => ({
  parseIndicator: (raw: string) => (raw ? { kind: "ip", value: raw } : null),
  lookupIndicator: vi.fn(async (_admin: unknown, ind: { value: string }) => ({ query: ind.value, listed: false, score: 0 })),
}));
vi.mock("@/lib/mcp-oauth", () => ({
  ACCESS_PREFIX: "tc_oat_",
  resourceMetadataUrl: () => "https://threatcrush.com/.well-known/oauth-protected-resource",
  resolveAccessToken: vi.fn(async (_admin: unknown, token: string) =>
    token === "tc_oat_good" ? { kind: "user", userId: "u1", email: "u1@example.com" } : null,
  ),
}));
vi.mock("@/lib/av-reputation", () => ({
  lookupReputations: vi.fn(async (hashes: string[]) =>
    new Map(hashes.map((h) => [h, { sha256: h, knownMalicious: "malshare.com", malwareName: null, trust: 0, fileName: "eicar.com" }])),
  ),
}));

import { POST } from "@/app/api/mcp/route";

const call = (body: unknown, opts: { token?: string; url?: string } = {}) =>
  POST(
    new Request(opts.url ?? "http://localhost/api/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}) },
      body: JSON.stringify(body),
    }) as unknown as import("next/server").NextRequest,
  );

describe("/api/mcp", () => {
  it("initializes and lists the tools without a key", async () => {
    const init = await (await call({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })).json();
    expect(init.result.serverInfo).toMatchObject({ name: "threatcrush", title: "ThreatCrush" });
    expect(init.result.instructions).toContain("OAuth");
    const list = await (await call({ jsonrpc: "2.0", id: 2, method: "tools/list" })).json();
    expect(list.result).toMatchObject({ resultType: "complete", cacheScope: "public" });
    expect(list.result.ttlMs).toBeGreaterThan(0);
    for (const t of list.result.tools) {
      expect(typeof t.title).toBe("string");
      expect(typeof t.annotations.readOnlyHint).toBe("boolean");
      expect(typeof t.annotations.openWorldHint).toBe("boolean");
    }
    const byName = Object.fromEntries(list.result.tools.map((t: { name: string; annotations: object }) => [t.name, t.annotations]));
    expect(byName.findings_list).toMatchObject({ readOnlyHint: true });
    expect(byName.findings_triage).toMatchObject({ readOnlyHint: false, destructiveHint: false });
    expect(byName.webhooks_delete).toMatchObject({ readOnlyHint: false, destructiveHint: true });
    expect(list.result.tools.map((t: { name: string }) => t.name)).toEqual(["av_hash_lookup", "reputation_lookup", "reputation_bulk", "redeem_credit_code", "list_invites", "create_invite", "findings_list", "findings_get", "findings_triage", "incidents_list", "incidents_get", "incidents_update", "incidents_raise", "webhooks_list", "webhooks_create", "webhooks_update", "webhooks_delete", "webhooks_test", "webhooks_rotate_secret", "webhooks_deliveries"]);
  });

  it("av_hash_lookup answers without a key", async () => {
    const h = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const res = await (
      await call({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "av_hash_lookup", arguments: { hashes: [h.toUpperCase(), "nope"] } } })
    ).json();
    expect(res.result.isError).toBeUndefined();
    const body = JSON.parse(res.result.content[0].text);
    expect(body).toMatchObject({ checked: 1, known: 1 });
    expect(body.results[h].knownMalicious).toBe("malshare.com");
    const bad = await (await call({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "av_hash_lookup", arguments: { hashes: [] } } })).json();
    expect(bad.result.isError).toBe(true);
  });

  it("a tool call that needs a credential and has none is a 401 that starts OAuth", async () => {
    for (const name of ["reputation_lookup", "findings_list", "incidents_list"]) {
      const res = await call({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: { indicator: "1.2.3.4" } } });
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain('resource_metadata="https://threatcrush.com/.well-known/oauth-protected-resource"');
      const body = await res.json();
      expect(body.id).toBe(3);
      expect(body.error.message).toContain("tc_agent_");
    }
  });

  it("an invalid credential is a 401 invalid_token on any request", async () => {
    const res = await call({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, { token: "tc_oat_revoked" });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain('error="invalid_token"');
  });

  it("?login refuses every request until signed in", async () => {
    const res = await call({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, { url: "http://localhost/api/mcp?login" });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("resource_metadata=");
    const okRes = await call({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, { url: "http://localhost/api/mcp?login", token: "tc_oat_good" });
    expect(okRes.status).toBe(200);
  });

  it("an OAuth access token acts as its user", async () => {
    const res = await call(
      { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "reputation_lookup", arguments: { indicator: "1.2.3.4" } } },
      { token: "tc_oat_good" },
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.result.isError).toBeUndefined();
    expect(JSON.parse(body.result.content[0].text)).toMatchObject({ query: "1.2.3.4" });
  });

  it("notifications get 202, unknown methods an error, bad JSON a parse error", async () => {
    expect((await call({ jsonrpc: "2.0", method: "notifications/initialized" })).status).toBe(202);
    const unknown = await (await call({ jsonrpc: "2.0", id: 4, method: "nope" })).json();
    expect(unknown.error.code).toBe(-32601);
    const bad = await POST(
      new Request("http://localhost/api/mcp", { method: "POST", body: "{" }) as unknown as import("next/server").NextRequest,
    );
    expect(bad.status).toBe(400);
  });
});
