import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { fakeDb } from "@/lib/incidents/__tests__/fake-db";

const state = vi.hoisted(() => ({ db: null as unknown, principal: null as unknown, pages: [] as Array<() => Promise<void>> }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => state.db }));
vi.mock("@/lib/access", async (original) => ({ ...await original<typeof import("@/lib/access")>(), getPrincipal: async () => state.principal }));
vi.mock("next/server", async (original) => ({ ...await original<typeof import("next/server")>(), after: (fn: () => Promise<void>) => state.pages.push(fn) }));
vi.mock("@/lib/incidents/notify", () => ({ notifyIncident: vi.fn(async () => ({ recipients: 1 })) }));

import { GET, PATCH, POST } from "../route";
import { POST as report } from "../report/route";
import { hashSecret } from "@/lib/access";
import { notifyIncident } from "@/lib/incidents/notify";

const org = "11111111-1111-4111-8111-111111111111", otherOrg = "22222222-2222-4222-8222-222222222222", repo = "33333333-3333-4333-8333-333333333333";
const token = `tc_repo_${"a".repeat(43)}`;
const request = (body: unknown, auth = token) => new NextRequest("https://threatcrush.com/api/github/repositories", { method: "POST", headers: { Authorization: `Bearer ${auth}` }, body: JSON.stringify(body) });
const finding = (severity: string) => ({ ruleId: "secret-private-key", file: ".env.example", line: 5, fingerprint: "b".repeat(32), severity });
let db: ReturnType<typeof fakeDb>;
beforeEach(() => {
  db = fakeDb({
    organization_members: [{ org_id: org, user_id: "operator", role: "owner", organizations: { name: "Our org", slug: "ours" } }],
    github_repository_policies: [{ id: repo, org_id: org, team_id: null, full_name: "our/repo", token_hash: hashSecret(token), silence_examples: true, silence_warnings: true }],
    teams: [{ id: otherOrg, org_id: otherOrg, name: "Another org team" }],
  });
  state.db = db; state.principal = { kind: "user", userId: "operator" }; state.pages = [];
  vi.mocked(notifyIncident).mockClear();
});

describe("repository account authorization", () => {
  it("rejects unauthenticated requests", async () => {
    state.principal = null;
    expect((await GET(request(null))).status).toBe(401);
    expect((await POST(request({ org_id: org, full_name: "our/new" }))).status).toBe(401);
  });
  it("rejects nonadmin changes and IDOR into another org", async () => {
    expect((await PATCH(request({ id: repo, org_id: otherOrg, silence_warnings: false }))).status).toBe(403);
    db.tables.organization_members[0].role = "member";
    expect((await PATCH(request({ id: repo, org_id: org, silence_warnings: false }))).status).toBe(403);
    expect(db.tables.github_repository_policies[0].silence_warnings).toBe(true);
  });
  it("rejects assigning a different organization's paging team", async () => {
    expect((await PATCH(request({ id: repo, org_id: org, team_id: otherOrg }))).status).toBe(400);
  });
  it("creates scoped tokens, stores only hashes, and does not expose hashes", async () => {
    const r = await POST(request({ org_id: org, full_name: "OUR/NEW" }));
    expect(r.status).toBe(201);
    const body = await r.json();
    expect(body.token).toMatch(/^tc_repo_[\w-]{43}$/);
    const stored = db.tables.github_repository_policies.find((x) => x.full_name === "our/new")!;
    expect(stored.token_hash).toBe(hashSecret(body.token));
    expect(body.repository).not.toHaveProperty("token_hash");
    expect(await (await GET(request(null))).json()).not.toHaveProperty("token_hash");
    expect(await r.headers.get("Cache-Control")).toBe("no-store");
  });
  it("rejects nonboolean silence settings and missing records", async () => {
    expect((await PATCH(request({ id: repo, org_id: org, silence_warnings: "false" }))).status).toBe(400);
    expect((await PATCH(request({ id: otherOrg, org_id: org, silence_warnings: false }))).status).toBe(404);
  });
  it("rotates tokens so the previous CI connection stops working", async () => {
    const r = await PATCH(request({ id: repo, org_id: org, rotate_token: true }));
    expect(r.status).toBe(200);
    expect((await report(request({ repository: "our/repo", run_id: "123", findings: [] }))).status).toBe(401);
    const next = await r.json();
    expect((await report(request({ repository: "our/repo", run_id: "123", findings: [] }, next.token))).status).toBe(200);
  });
});

describe("CI critical paging", () => {
  it("refuses invalid tokens and a mismatched repository", async () => {
    expect((await report(request({}, "bad"))).status).toBe(401);
    expect((await report(request({ repository: "not/ours", run_id: "123", findings: [] }))).status).toBe(400);
  });
  it("silences noncritical warnings without raising or paging an incident", async () => {
    const r = await report(request({ repository: "our/repo", run_id: "123", findings: [finding("high")] }));
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ visible: [], counts: { silenced: 1, critical: 0 } });
    expect(state.pages).toHaveLength(0);
    expect(db.tables.incidents ?? []).toHaveLength(0);
  });
  it("critical example findings bypass every warning silence and page the assigned team once", async () => {
    db.tables.github_repository_policies[0].team_id = otherOrg;
    const body = { repository: "our/repo", run_id: "123", findings: [finding("critical"), finding("high")] };
    const r = await report(request(body));
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ visible: [0], counts: { critical: 1, silenced: 1 } });
    expect(db.tables.incidents).toHaveLength(1);
    expect(db.tables.incidents[0].team_id).toBe(otherOrg);
    expect(state.pages).toHaveLength(1);
    await state.pages[0]();
    expect(notifyIncident).toHaveBeenCalledOnce();
    expect((await report(request({ ...body, run_id: "124" }))).status).toBe(200);
    expect(state.pages).toHaveLength(1);
    expect(db.tables.incidents).toHaveLength(1);
  });
});
