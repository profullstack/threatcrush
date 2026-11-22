import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({}) }));
vi.mock("@/lib/geoip", async (orig) => {
  const real = await orig<typeof import("@/lib/geoip")>();
  return {
    ...real,
    // Documentation ranges count as public here, standing in for real addresses.
    isPublicIp: vi.fn(() => true),
    lookupIps: vi.fn(async () => new Map()),
    lookupAsn: vi.fn(async () => ({ asn: 64500, org: "EXAMPLE-NET", network: null })),
  };
});
// 192.0.2.0/24 stands in for a GitHub Actions range (RFC 5737 documentation addresses only).
vi.mock("@/lib/github-actions-ranges", () => ({
  githubActionsChecker: vi.fn(async () => (ip: string) => ip.startsWith("192.0.2.")),
}));

import { buildTimeline, detailModel } from "@threatcrush/event-detail";
import { detectionHistory, HistoryError } from "../detection-history";
import { fakeDb } from "../incidents/__tests__/fake-db";

const ORG = "11111111-1111-4111-8111-111111111111";
const S1 = "22222222-2222-4222-8222-222222222222";
const S2 = "33333333-3333-4333-8333-333333333333";
const FP = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg";
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

function det(n: number, over: Record<string, unknown>) {
  return {
    id: id(n), organization_id: ORG, server_id: S1, rule_id: "port-scan", severity: "medium", title: "t", description: null,
    source_ip: null, username: null, raw_metadata: null, detected_at: "2026-11-22T03:00:00.000Z", last_detected_at: null,
    occurrences: 1, status: "new", ...over,
  };
}

const sshContext = {
  v: 1, at: "2026-11-22T03:58:33.000Z", host: "web-1", user: "deploy", auth_method: "publickey",
  key: { found: true, fingerprint: FP, command: "/usr/local/bin/ci-deploy example/app", options: ["restrict", 'command="/usr/local/bin/ci-deploy example/app"'], restrict: true, comment: "deploy@example/app" },
  source: { ip: "192.0.2.10", kind: "github-actions" },
  failures: { window_s: 600, total: 2, same_ip: 0, other_ips: 2, ips: [{ ip: "198.51.100.7", count: 2 }] },
  session: { ci_deploy: { decision: "ALLOW", repo: "example/app", action: "deploy app 5addb4f2" } },
  verdict: { level: "likely-ci", severity: "low", summary: "Likely CI deploy: GitHub Actions IP, forced-command deploy key, ci-deploy ALLOW deploy app 5addb4f2", reasons: [] },
};

function db() {
  return fakeDb({
    detections: [
      det(1, { rule_id: "ssh-success-after-failures", severity: "critical", title: "SSH Login Accepted", source_ip: "192.0.2.10", detected_at: "2026-11-22T03:58:33.000Z", raw_metadata: { evidence: { module: "ssh-guard", fingerprint: FP, key_kind: "automation", key_comment: "deploy@example/app", ssh_context: sshContext } } }),
      det(2, { source_ip: "192.0.2.10", server_id: S2, detected_at: "2026-11-21T00:00:00.000Z" }),
      det(3, { server_id: S2, rule_id: "ssh-login-sensitive", raw_metadata: { evidence: { fingerprint: FP } }, detected_at: "2026-11-20T00:00:00.000Z" }),
      det(4, { rule_id: "disk", detected_at: "2026-11-22T04:00:00.000Z" }),
      det(5, { server_id: S2, rule_id: "x", source_ip: "203.0.113.200" }),
      det(6, { source_ip: "192.0.2.10", detected_at: "2026-09-01T00:00:00.000Z" }), // outside 30 days
      det(7, { source_ip: "192.0.2.10", raw_metadata: { leaked: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc" } }),
    ],
    servers: [{ id: S1, org_id: ORG, name: "web-1" }, { id: S2, org_id: ORG, name: "web-2" }],
    incidents: [],
    fleet_inventories: [],
  });
}

describe("detectionHistory", () => {
  it("returns related detections by IP, key, host and rule, with origin and server names", async () => {
    const h = await detectionHistory(db() as never, ORG, id(1), null);
    expect(h.detection.host).toBe("web-1");
    const ids = h.related.map((r) => r.id).sort();
    expect(ids).toEqual([id(2), id(3), id(4), id(7)]);
    expect(h.origin).toContain('GitHub Actions runner deploying with the key "deploy@example/app"');
    const leaked = h.related.find((r) => r.id === id(7))!;
    expect(JSON.stringify(leaked)).not.toContain("PRIVATE KEY");

    const timeline = buildTimeline(h.detection, h.related);
    expect(timeline.find((t) => t.event.id === id(2))?.relations).toEqual(["ip"]);
    expect(timeline.find((t) => t.event.id === id(3))?.relations).toEqual(["key"]);
    expect(timeline.find((t) => t.event.id === id(4))?.relations).toEqual(["host"]);
    const model = detailModel(h.detection, { originLabel: h.origin });
    expect(model.verdict?.level).toBe("likely-ci");
    expect(model.severity).toBe("low");
  });

  it("hides servers the caller cannot see", async () => {
    const h = await detectionHistory(db() as never, ORG, id(1), [S1]);
    expect(h.related.map((r) => r.id).sort()).toEqual([id(4), id(7)]);
    await expect(detectionHistory(db() as never, ORG, id(3), [S1])).rejects.toBeInstanceOf(HistoryError);
  });

  it("rejects a bad id", async () => {
    await expect(detectionHistory(db() as never, ORG, "nope", null)).rejects.toMatchObject({ status: 400 });
  });
});
