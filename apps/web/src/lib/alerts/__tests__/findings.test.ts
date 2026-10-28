import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => { throw new Error("pass an admin client"); } }));
const sent: Array<{ dest: string; title: string; body: string; findings: number }> = [];
vi.mock("../senders", () => ({
  deliverAlert: async (d: { id: string }, m: { title: string; body: string; findings?: { findings: unknown[] } }) => {
    sent.push({ dest: d.id, title: m.title, body: m.body, findings: m.findings?.findings.length ?? 0 });
    return d.id === "broken" ? { ok: false, error: "HTTP 500" } : { ok: true };
  },
  webhookAlert: () => null,
}));
vi.mock("@/lib/webhooks/hub", () => ({ emitToOrg: async () => 0 }));

import { buildFindingsMessage, dispatchFindingAlerts } from "../findings";

type Row = Record<string, unknown>;
function fakeAdmin(t: { rules: Row[]; dests: Row[]; recent?: number }) {
  const inserted: Row[] = [];
  const admin = {
    from(table: string) {
      const q: Record<string, unknown> = {};
      const chain = () => q;
      Object.assign(q, {
        select: (_c: string, opts?: { head?: boolean }) => { (q as Row).head = opts?.head; return q; },
        eq: chain, in: chain, gte: chain, order: chain,
        maybeSingle: async () => ({ data: { slug: "acme" }, error: null }),
        insert: async (rows: Row[]) => { inserted.push(...rows); return { error: null }; },
        then: (resolve: (v: unknown) => void) => {
          if (table === "alert_rules") return resolve({ data: t.rules, error: null });
          if (table === "alert_destinations") return resolve({ data: t.dests, error: null });
          if (table === "alert_deliveries") return resolve({ count: t.recent ?? 0, error: null });
          resolve({ data: [], error: null });
        },
      });
      return q;
    },
  };
  return { admin: admin as never, inserted };
}

const rule = (id: string, dest: string, min: string, extra: Row = {}) =>
  ({ id, organization_id: "o1", name: id, min_severity: min, server_scope: null, destination_id: dest, rate_limit_per_hour: 60, enabled: true, ...extra });
const dest = (id: string) => ({ id, organization_id: "o1", name: id, type: "webhook", config: {}, enabled: true });
const payload = (sev: string[]) => ({
  run_id: "r1", organization_id: "o1", source: "scan" as const,
  property: { id: "p1", name: "github.com/acme/app", target: "github.com/acme/app" },
  findings: sev.map((s, i) => ({ severity: s as "high", message: `finding ${i}`, location: i ? `a.ts:${i}` : "github.com/acme/app", reopened: i === 1 })),
});

describe("buildFindingsMessage", () => {
  it("leads with the worst severity, counts each, flags reopens, hides a location equal to the target", () => {
    const m = buildFindingsMessage(payload(["low", "critical", "high"]), "acme");
    expect(m.title).toBe("[CRITICAL] 3 new findings in github.com/acme/app");
    expect(m.severity).toBe("critical");
    expect(m.body).toMatch(/^1 critical, 1 high, 1 low from a code scan \(1 reopened\)\./);
    expect(m.body).toContain("[CRITICAL] (back after a fix) finding 1 — a.ts:1");
    expect(m.body.endsWith("• [LOW] finding 0")).toBe(true);
    expect(m.url).toBe("https://threatcrush.com/org/acme/findings");
  });

  it("lists at most 10", () => {
    const m = buildFindingsMessage(payload(Array(14).fill("high")), null);
    expect(m.body).toContain("…and 4 more");
    expect(m.url).toBe("https://threatcrush.com/dashboard");
  });
});

describe("dispatchFindingAlerts", () => {
  beforeEach(() => { sent.length = 0; });

  it("fires org-wide rules at or above their threshold, one alert per destination, listing only what clears it", async () => {
    const { admin, inserted } = fakeAdmin({
      rules: [rule("crit", "d1", "critical"), rule("high", "d2", "high"), rule("high-dup", "d2", "medium"), rule("scoped", "d3", "info", { server_scope: ["srv"] })],
      dests: [dest("d1"), dest("d2"), dest("d3")],
    });
    const out = await dispatchFindingAlerts(payload(["high", "medium"]), admin);
    expect(out.sent).toBe(1);
    expect(sent).toEqual([expect.objectContaining({ dest: "d2", findings: 1 })]);
    expect(inserted).toEqual([expect.objectContaining({ rule_id: "high", destination_id: "d2", status: "sent", detection_id: null })]);
  });

  it("records rate-limited and failed deliveries", async () => {
    const limited = fakeAdmin({ rules: [rule("r", "d1", "info")], dests: [dest("d1")], recent: 60 });
    await dispatchFindingAlerts(payload(["high"]), limited.admin);
    expect(limited.inserted[0]).toMatchObject({ status: "rate_limited" });
    expect(sent).toHaveLength(0);
    const broken = fakeAdmin({ rules: [rule("r", "broken", "info")], dests: [dest("broken")] });
    await dispatchFindingAlerts(payload(["high"]), broken.admin);
    expect(broken.inserted[0]).toMatchObject({ status: "failed", error: "HTTP 500" });
  });

  it("does nothing without findings, rules or an enabled destination", async () => {
    expect((await dispatchFindingAlerts(payload([]), fakeAdmin({ rules: [rule("r", "d1", "info")], dests: [dest("d1")] }).admin)).sent).toBe(0);
    expect((await dispatchFindingAlerts(payload(["critical"]), fakeAdmin({ rules: [rule("r", "d1", "info")], dests: [] }).admin)).sent).toBe(0);
    expect(sent).toHaveLength(0);
  });
});
