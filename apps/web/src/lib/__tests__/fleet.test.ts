import { describe, expect, it } from "vitest";
import { buildFleet, compareVersions } from "@/lib/fleet";

const NOW = Date.parse("2026-10-01T10:30:00Z");
const orgs = new Map([
  ["o1", { name: "Profullstack", slug: "profullstack" }],
  ["o2", { name: "Acme", slug: "acme" }],
]);

function row(over: Partial<Parameters<typeof buildFleet>[0][number]>) {
  return {
    id: "s", name: "s", hostname: null, ip_address: null, org_id: "o1",
    last_seen: "2026-10-01T10:29:30Z", threatcrushd_version: "0.13.15",
    config: null, config_saved_at: null, created_at: "2026-10-01T00:00:00Z",
    ...over,
  };
}

describe("compareVersions", () => {
  it("compares numerically, not as strings", () => {
    expect(compareVersions("0.13.15", "0.13.9")).toBeGreaterThan(0);
    expect(compareVersions("v1.0.0", "0.99.99")).toBeGreaterThan(0);
    expect(compareVersions("0.13.15", "0.13.15")).toBe(0);
    expect(compareVersions(null, "0.0.1")).toBeLessThan(0);
  });
});

describe("buildFleet", () => {
  it("spans every organization and summarizes what needs attention", () => {
    const { servers, summary } = buildFleet([
      row({ id: "a", name: "dev2", org_id: "o1", config: { remediation: { max_ban: "7d", strike_memory: "30d" } } }),
      row({ id: "b", name: "web-1", org_id: "o2", threatcrushd_version: "0.13.9" }),
      row({ id: "c", name: "old-box", org_id: "o2", last_seen: "2026-10-01T09:00:00Z" }),
    ], orgs, NOW);

    expect(summary).toEqual({
      total: 3, online: 2, offline: 1, latest_version: "0.13.15", outdated: 1, organizations: 2,
      patch_reported: 0, patch_hosts_with_fixes: 0, patch_cves: 0, patch_critical_high: 0,
    });
    // Offline first, then behind, then the rest.
    expect(servers.map((s) => s.name)).toEqual(["old-box", "web-1", "dev2"]);
    expect(servers[1]).toMatchObject({ org_name: "Acme", org_slug: "acme", outdated: true });
    expect(servers[2].remediation).toEqual({ max_ban: "7d", strike_memory: "30d" });
  });

  it("never trusts the stored status: a server not seen for 3+ minutes is offline", () => {
    const { servers } = buildFleet([row({ last_seen: "2026-10-01T10:26:00Z" }), row({ id: "n", last_seen: null })], orgs, NOW);
    expect(servers.every((s) => s.connection === "offline")).toBe(true);
  });

  it("handles an empty fleet", () => {
    expect(buildFleet([], orgs, NOW).summary).toMatchObject({ total: 0, latest_version: null, outdated: 0 });
  });

  it("totals pending security fixes from each server's os-patches finding", () => {
    const at = "2026-10-01T06:00:00Z";
    const { servers, summary } = buildFleet(
      [row({ id: "a", name: "a" }), row({ id: "b", name: "b" }), row({ id: "c", name: "c" }), row({ id: "d", name: "d" })],
      orgs, NOW, new Map(),
      [
        { server_id: "a", status: "fail", observed_at: at, details: { supported: true, counts: { packages: 2, cves: 9, critical: 1, high: 2 } } },
        { server_id: "b", status: "pass", observed_at: at, details: { supported: true, lists_stale: true, counts: { packages: 0, cves: 0 } } },
        { server_id: "c", status: "warn", observed_at: at, details: { supported: false } },
        // A row written before the details column existed.
        { server_id: "d", status: "warn", observed_at: at, details: null },
      ],
    );
    const byName = Object.fromEntries(servers.map((s) => [s.name, s.patches]));
    expect(byName.a).toMatchObject({ packages: 2, cves: 9, critical: 1, high: 2, unsupported: false });
    expect(byName.b).toMatchObject({ packages: 0, lists_stale: true });
    expect(byName.c).toMatchObject({ unsupported: true });
    expect(byName.d).toMatchObject({ packages: 0, cves: 0, unsupported: false });
    expect(summary).toMatchObject({ patch_reported: 3, patch_hosts_with_fixes: 1, patch_cves: 9, patch_critical_high: 3 });
  });
});
