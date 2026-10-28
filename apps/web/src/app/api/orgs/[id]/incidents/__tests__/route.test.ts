import type * as NextServer from "next/server";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fakeDb, type Row } from "@/lib/incidents/__tests__/fake-db";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/api-auth", () => ({ getAuthenticatedRequestUser: async () => null }));

const ORG = "00000000-0000-4000-8000-0000000000a1";
const TEAM = "00000000-0000-4000-8000-0000000000b1";
const OTHER_TEAM = "00000000-0000-4000-8000-0000000000b2";
const U = {
  owner: "00000000-0000-4000-8000-00000000000a",
  writer: "00000000-0000-4000-8000-00000000000b",
  reader: "00000000-0000-4000-8000-00000000000c",
  outsider: "00000000-0000-4000-8000-00000000000d",
  muted: "00000000-0000-4000-8000-00000000000e",
};

const h = vi.hoisted(() => ({
  db: null as unknown as ReturnType<typeof import("@/lib/incidents/__tests__/fake-db").fakeDb>,
  principal: null as unknown,
  emails: [] as Array<{ to: string[]; subject: string; text: string; html: string }>,
  sms: [] as Array<{ url: string; body: string; headers: Record<string, string> }>,
  telnyx: [] as Array<{ to: string; text: string }>,
  smshubStatus: 200,
  afterTasks: [] as Array<() => unknown>,
}));

vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => h.db }));
vi.mock("@/lib/access", async (orig) => ({
  ...(await orig<typeof import("@/lib/access")>()),
  getPrincipal: async () => h.principal,
}));
vi.mock("resend", () => ({
  Resend: class {
    emails = { send: async (m: { to: string[]; subject: string; text: string; html: string }) => { h.emails.push(m); return { error: null }; } };
  },
}));
vi.mock("@/lib/telnyx", () => ({
  isTelnyxConfigured: () => true,
  sendTelnyxSms: async (to: string, text: string) => { h.telnyx.push({ to, text }); },
}));
vi.mock("next/server", async (orig) => ({
  ...(await orig<typeof NextServer>()),
  after: (task: () => unknown) => { h.afterTasks.push(task); },
}));

const { GET, POST } = await import("@/app/api/orgs/[id]/incidents/route");
const one = await import("@/app/api/orgs/[id]/incidents/[incident_id]/route");
const testNotify = await import("@/app/api/orgs/[id]/incidents/test-notify/route");
const { notifyIncident, PAGES_PER_HOUR } = await import("@/lib/incidents/notify");

const user = (id: string) => ({ kind: "user", userId: id, email: null });
const ctx = { params: Promise.resolve({ id: ORG }) };
const req = (body?: unknown, method = "POST") =>
  new Request(`http://x/api/orgs/${ORG}/incidents`, { method, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) }) as never;
const flush = async () => { const tasks = h.afterTasks.splice(0); for (const t of tasks) await t(); };

const report = (over: Record<string, unknown> = {}) => ({
  team_id: TEAM, title: "Solana wallet drained", severity: "high", source: "investigate", dedupe_key: "investigate:sol:WaLLet",
  summary: "Full-balance sweep 12 minutes after a new SSH key.", host: "box1", report_version: 1,
  findings: [{ id: "chain:sweep", module: "chain", severity: "critical", title: "Full-balance sweep", evidence: "evidence", at: "2026-10-28T04:56:00Z" }],
  timeline: [
    { at: "2026-10-28T04:44:00Z", module: "host", summary: "new authorized key installed", evidence: true },
    { at: "2026-10-28T04:56:00Z", module: "chain", summary: "wallet swept to collector", evidence: true, ref: "sol:tx:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ" },
  ],
  recommendations: [{ action: "Remove the new authorized key", target: "root@box1", priority: "now" }],
  ...over,
});

beforeEach(() => {
  const profile = (id: string, over: Row = {}) => ({
    id, email: `${id.slice(-1)}@delivered.test`, phone: "+15550000001", phone_verified: true, notification_email: true, notification_sms: true, display_name: id.slice(-1), ...over,
  });
  h.db = fakeDb({
    organizations: [{ id: ORG, slug: "acme" }],
    organization_members: [
      { org_id: ORG, user_id: U.owner, role: "owner" },
      { org_id: ORG, user_id: U.writer, role: "guest" },
      { org_id: ORG, user_id: U.reader, role: "guest" },
      { org_id: ORG, user_id: U.muted, role: "guest" },
    ],
    teams: [{ id: TEAM, org_id: ORG, name: "Ops" }, { id: OTHER_TEAM, org_id: ORG, name: "Web" }],
    team_members: [
      { team_id: TEAM, user_id: U.writer, role: "write", notify_incidents: true, "teams.org_id": ORG },
      { team_id: TEAM, user_id: U.reader, role: "read", notify_incidents: true, "teams.org_id": ORG },
      { team_id: TEAM, user_id: U.muted, role: "read", notify_incidents: false, "teams.org_id": ORG },
    ],
    user_profiles: [
      profile(U.owner),
      profile(U.writer),
      profile(U.reader, { phone_verified: false, notification_email: false }),
      profile(U.muted),
    ],
    incidents: [], incident_notes: [], incident_notifications: [], fleets: [], servers: [],
  });
  h.principal = user(U.writer);
  h.emails.length = 0; h.sms.length = 0; h.telnyx.length = 0; h.afterTasks.length = 0; h.smshubStatus = 200;
  process.env.RESEND_API_KEY = "re_test";
  process.env.SMSHUB_API_KEY = "smshub_test";
  process.env.SMSHUB_URL = "https://smshub.test";
  vi.stubGlobal("fetch", async (url: string, init: { body: string; headers: Record<string, string> }) => {
    h.sms.push({ url, body: init.body, headers: init.headers });
    return new Response(h.smshubStatus === 200 ? JSON.stringify({ alert: { channels: ["call"] } }) : "nope", { status: h.smshubStatus });
  });
});

describe("POST /api/orgs/[id]/incidents", () => {
  it("needs a principal and write on the team", async () => {
    h.principal = null;
    expect((await POST(req(report()), ctx)).status).toBe(401);
    h.principal = user(U.reader);
    expect((await POST(req(report()), ctx)).status).toBe(404);
    h.principal = user(U.writer);
    expect((await POST(req(report({ team_id: OTHER_TEAM })), ctx)).status).toBe(404);
    expect(h.db.tables.incidents).toHaveLength(0);
  });

  it("creates an incident and pages the team once: settings and mutes respected", async () => {
    const res = await POST(req(report()), ctx);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.created).toBe(true);
    expect(body.notified).toMatchObject({ email: 1, sms: 1, queued: true });
    await flush();
    // writer: email + SMS; reader: email off + phone unverified; muted: never.
    expect(h.emails.map((e) => e.to[0])).toEqual([`${U.writer.slice(-1)}@delivered.test`]);
    expect(h.sms).toHaveLength(1);
    // smshub's alert API (texts when it can, else calls): API key in X-API-Key, HIGH rings the phone.
    expect(h.sms[0].url).toBe("https://smshub.test/api/v1/alerts");
    expect(h.sms[0].headers["X-API-Key"]).toBe("smshub_test");
    expect(JSON.parse(h.sms[0].body).severity).toBe("critical");
    const text = JSON.parse(h.sms[0].body).message as string;
    expect(text).toMatch(/^\[ThreatCrush HIGH\] Solana wallet drained on box1\. 1 finding\. https:\/\/.+\/org\/acme\/incidents\//);
    expect(text.length).toBeLessThanOrEqual(320);
    const rows = h.db.tables.incident_notifications;
    expect(rows.filter((r) => r.user_id === U.muted)).toHaveLength(0);
    expect(rows.find((r) => r.user_id === U.reader && r.channel === "sms")).toMatchObject({ status: "skipped", detail: "phone not verified" });
    expect(rows.find((r) => r.user_id === U.writer && r.channel === "sms")).toMatchObject({ status: "sent", detail: "smshub call" });
    expect(rows.find((r) => r.user_id === U.reader && r.channel === "email")).toMatchObject({ status: "skipped" });
    expect(h.db.tables.incidents[0].last_notified_at).toBeTruthy();
  });

  it("a second raise with the same dedupe key folds in and does not page again", async () => {
    await POST(req(report()), ctx);
    await flush();
    const pages = h.emails.length + h.sms.length;
    const res = await POST(req(report({
      findings: [{ id: "host:key", module: "host", severity: "high", title: "New authorized key", evidence: "evidence" }],
      timeline: [{ at: "2026-10-28T04:44:00Z", module: "host", summary: "new authorized key installed", evidence: true }],
    })), ctx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ created: false, paged: false });
    await flush();
    expect(h.emails.length + h.sms.length).toBe(pages);
    expect(h.db.tables.incidents).toHaveLength(1);
    const inc = h.db.tables.incidents[0];
    expect(inc.raise_count).toBe(2);
    expect((inc.findings as unknown[]).length).toBe(2);
    expect((inc.timeline as unknown[]).length).toBe(2);
  });

  it("escalating to critical pages again; a resolved incident frees the key", async () => {
    await POST(req(report()), ctx);
    await flush();
    const before = h.emails.length;
    const res = await POST(req(report({ severity: "critical" })), ctx);
    expect((await res.json()).paged).toBe(true);
    await flush();
    expect(h.emails.length).toBe(before + 1);
    h.db.tables.incidents[0].status = "resolved";
    expect((await POST(req(report()), ctx)).status).toBe(201);
    expect(h.db.tables.incidents).toHaveLength(2);
  });

  it("refuses secret material with 422, stores and sends nothing, and never echoes it", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const bytes = [
      ...Buffer.from(privateKey.export({ format: "jwk" }).d!, "base64url"),
      ...Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url"),
    ];
    const secret = JSON.stringify(bytes);
    const res = await POST(req(report({ findings: [{ ...report().findings[0], detail: `keypair ${secret}` }] })), ctx);
    expect(res.status).toBe(422);
    const raw = await res.text();
    expect(raw).not.toContain(secret);
    expect(raw).not.toContain(bytes.slice(0, 8).join(","));
    expect(raw).toContain("findings[0].detail");
    await flush();
    expect(h.db.tables.incidents).toHaveLength(0);
    expect(h.emails).toHaveLength(0);
    expect(h.sms).toHaveLength(0);
  });

  it("an agent key raises on its own team without naming it", async () => {
    h.principal = { kind: "agent", keyId: "00000000-0000-4000-8000-0000000000c1", orgId: ORG, teamId: TEAM, role: "write", name: "box1" };
    const res = await POST(req(report({ team_id: undefined })), ctx);
    expect(res.status).toBe(201);
    expect(h.db.tables.incidents[0]).toMatchObject({ team_id: TEAM, created_by_agent_key: "00000000-0000-4000-8000-0000000000c1" });
    h.principal = { kind: "agent", keyId: "k", orgId: ORG, teamId: TEAM, role: "read", name: "ro" };
    expect((await POST(req(report({ team_id: undefined, dedupe_key: "x" })), ctx)).status).toBe(403);
  });
});

describe("GET + PATCH", () => {
  it("lists only what the caller can see, with counts", async () => {
    await POST(req(report()), ctx);
    h.principal = user(U.owner);
    await POST(req(report({ team_id: OTHER_TEAM, dedupe_key: "web" })), ctx);
    const all = await (await GET(req(undefined, "GET"), ctx)).json();
    expect(all.incidents).toHaveLength(2);
    h.principal = user(U.reader);
    const mine = await (await GET(req(undefined, "GET"), ctx)).json();
    expect(mine.incidents.map((i: { team_name: string }) => i.team_name)).toEqual(["Ops"]);
    expect(mine.counts).toEqual({ open: 1, acknowledged: 0, resolved: 0 });
    h.principal = user(U.outsider);
    expect((await GET(req(undefined, "GET"), ctx)).status).toBe(403);
  });

  it("acknowledge, assign to a team member, note, resolve; readers cannot", async () => {
    const { incident } = await (await POST(req(report()), ctx)).json();
    const c = { params: Promise.resolve({ id: ORG, incident_id: incident.id }) };
    const patch = (b: unknown) => one.PATCH(req(b, "PATCH"), c);
    h.principal = user(U.reader);
    expect((await patch({ status: "acknowledged" })).status).toBe(403);
    expect((await one.GET(req(undefined, "GET"), c)).status).toBe(200);
    h.principal = user(U.writer);
    expect((await patch({ status: "acknowledged", assignee_id: U.reader, note: "on it" })).status).toBe(200);
    expect(h.db.tables.incidents[0]).toMatchObject({ status: "acknowledged", assignee_id: U.reader });
    expect(h.db.tables.incidents[0].acknowledged_at).toBeTruthy();
    expect(h.db.tables.incident_notes[0]).toMatchObject({ author_id: U.writer, body: "on it" });
    expect((await patch({ assignee_id: U.owner })).status).toBe(400); // owner is not on the team
    expect((await patch({ status: "closed" })).status).toBe(400);
    expect((await patch({})).status).toBe(400);
    expect((await patch({ status: "resolved" })).status).toBe(200);
    const detail = await (await one.GET(req(undefined, "GET"), c)).json();
    expect(detail.incident.status).toBe("resolved");
    expect(detail.notes[0].author_name).toBe(U.writer.slice(-1));
    expect(detail.members.map((m: { user_id: string }) => m.user_id)).toContain(U.reader);
  });

  it("an unknown or other-team incident is a 404", async () => {
    const c = { params: Promise.resolve({ id: ORG, incident_id: "00000000-0000-4000-8000-0000000000ff" }) };
    expect((await one.GET(req(undefined, "GET"), c)).status).toBe(404);
  });
});

describe("notify", () => {
  it("falls back to Telnyx when smshub fails or is not configured", async () => {
    h.smshubStatus = 500;
    await POST(req(report()), ctx);
    await flush();
    expect(h.telnyx).toHaveLength(1);
    expect(h.db.tables.incident_notifications.find((r) => r.channel === "sms" && r.user_id === U.writer)).toMatchObject({ status: "sent", detail: "telnyx" });
    delete process.env.SMSHUB_API_KEY;
    h.db.tables.incidents[0].status = "resolved";
    await POST(req(report()), ctx);
    await flush();
    expect(h.telnyx).toHaveLength(2);
  });

  it(`caps pages at ${PAGES_PER_HOUR} per person per channel per hour`, async () => {
    const now = new Date().toISOString();
    for (let i = 0; i < PAGES_PER_HOUR; i++) {
      h.db.tables.incident_notifications.push({ id: `n${i}`, incident_id: null, user_id: U.writer, channel: "sms", status: "sent", created_at: now });
    }
    await notifyIncident({ id: "i1", org_id: ORG, team_id: TEAM, title: "t", severity: "critical", host: null, summary: "", findings_count: 0 }, h.db);
    expect(h.sms).toHaveLength(0);
    expect(h.emails).toHaveLength(1);
    expect(h.db.tables.incident_notifications.find((r) => r.incident_id === "i1" && r.channel === "sms")).toMatchObject({ status: "rate_limited" });
  });

  it("test-notify pages only the one person asked for, org admins only", async () => {
    h.principal = user(U.writer);
    expect((await testNotify.POST(req({}), ctx)).status).toBe(403);
    h.principal = user(U.owner);
    const res = await testNotify.POST(req({ user_id: U.writer }), ctx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.sms.sent).toBe(1);
    expect(body.email.sent).toBe(1);
    expect(h.emails).toHaveLength(1);
    expect(h.emails[0].subject).toContain("TEST");
    expect(JSON.parse(h.sms[0].body).message).toContain("[ThreatCrush TEST]");
    expect((await testNotify.POST(req({ user_id: U.outsider }), ctx)).status).toBe(404);
  });
});
