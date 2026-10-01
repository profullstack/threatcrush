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

    expect(summary).toEqual({ total: 3, online: 2, offline: 1, latest_version: "0.13.15", outdated: 1, organizations: 2 });
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
});
