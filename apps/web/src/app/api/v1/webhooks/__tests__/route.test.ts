import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import type { Principal } from "@/lib/access";

let principal: Principal | null = null;
let memberRole: string | null = "owner";
vi.mock("@/lib/feed-auth", () => ({ feedPrincipal: async () => principal }));
vi.mock("@/lib/access", () => ({ orgRoleOf: async () => memberRole }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => {
      const q: Record<string, unknown> = {};
      Object.assign(q, { select: () => q, eq: () => q, in: () => q, order: () => q, limit: async () => ({ data: [{ org_id: "org-1" }] }) });
      return q;
    },
  }),
}));
vi.mock("@/lib/ssrf-guard", () => ({ safeFetch: vi.fn() }));

import { createHooks, setHubForTests } from "@/lib/webhooks/hub";
import { supabaseStore } from "@/lib/webhooks/supabase-store";
import { fakeSupabase } from "@/lib/webhooks/__tests__/fake-supabase";
import { GET, POST } from "../[[...path]]/route";

const agent = (role: "read" | "write" | "admin", orgId = "org-1"): Principal => ({ kind: "agent", keyId: "k", orgId, teamId: "t", role, name: "ci" });
const req = (path: string, init?: RequestInit) => new NextRequest(`http://localhost/api/v1/webhooks${path}`, init as never);

beforeEach(() => {
  principal = null;
  memberRole = "owner";
  const db = fakeSupabase();
  const store = supabaseStore(db);
  setHubForTests({ hooks: createHooks(store, { guard: { lookup: async () => ["93.184.216.34"] } }), store, client: db });
});

describe("/api/v1/webhooks", () => {
  it("is 401 without a key", async () => {
    expect((await GET(req(""))).status).toBe(401);
  });

  it("needs an admin key, in its own org", async () => {
    principal = agent("write");
    expect((await GET(req(""))).status).toBe(403);
    principal = agent("admin");
    expect((await GET(req("?org_id=org-2"))).status).toBe(403);
  });

  it("needs an org owner/admin for a person", async () => {
    principal = { kind: "user", userId: "u1", email: null };
    memberRole = "member";
    expect((await GET(req("?org_id=org-1"))).status).toBe(403);
  });

  it("lists the event types, creates an endpoint owned by the org and returns its secret once", async () => {
    principal = agent("admin");
    const list = await (await GET(req(""))).json();
    expect(list).toEqual({ endpoints: [], event_types: ["detection.created", "findings.raised", "reputation.changed"] });

    const res = await POST(req("", { method: "POST", body: JSON.stringify({ url: "https://hooks.example.com/tc", events: ["findings.*"] }) }));
    expect(res.status).toBe(201);
    const created = await res.json();
    expect(created.secret).toMatch(/^whsec_/);
    expect(created.endpoint).toMatchObject({ url: "https://hooks.example.com/tc", events: ["findings.*"], enabled: true });

    principal = { kind: "user", userId: "u1", email: null };
    const mine = await (await GET(req("?org_id=org-1"))).json();
    expect(mine.endpoints.map((e: { id: string }) => e.id)).toEqual([created.endpoint.id]);
  });

  it("refuses an event pattern ThreatCrush never emits", async () => {
    principal = agent("admin");
    const res = await POST(req("", { method: "POST", body: JSON.stringify({ url: "https://hooks.example.com/tc", events: ["invoice.paid"] }) }));
    expect(res.status).toBe(400);
  });
});
