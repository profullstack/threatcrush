import { describe, expect, it } from "vitest";
import { buildFleet, compareVersions, monthlyLabel } from "@/lib/fleet";

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
      total: 3, installs: 3, online: 2, offline: 1, no_agent: 0, latest_version: "0.13.15", outdated: 1, organizations: 2,
      patch_reported: 0, patch_hosts_with_fixes: 0, patch_cves: 0, patch_critical_high: 0,
      monthly_total: {}, monthly_total_label: "—", cost_counted: 0, cost_unstated: 0, inventories: 0,
    });
    expect(servers.every((s) => s.agent && s.device === null)).toBe(true);
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

// An OpenDevice inventory shaped like the real one: stated + unstated costs,
// a box that matches by hostname, one by its daemon's public IP, one by name,
// and machines with no daemon at all.
const inventory = {
  operator: { name: "Profullstack" },
  devices: [
    { id: "dev2", name: "dev2", profile: "server", status: "active", hostnames: ["dev2.profullstack.com"],
      addresses: { ipv4: ["23.95.228.174"], ipv6: [] }, provider: { name: "RackNerd" },
      cost: { amount: 149, currency: "USD", interval: "month", payee: "RackNerd" } },
    { id: "vienna", name: "vienna", profile: "server", status: "active", hostnames: ["dev.chovy.com"],
      addresses: { ipv4: ["152.53.47.37"], ipv6: [] }, provider: { name: "netcup" },
      cost: { amount: 53, currency: "USD", interval: "month" } },
    { id: "seed1", name: "seed1", profile: "server", status: "active", hostnames: ["seed1.h4kr.com"],
      addresses: { ipv4: ["104.152.209.195"], ipv6: [] }, cost: { amount: null, currency: "USD", interval: "month" } },
    { id: "dev1", name: "dev1", profile: "server", status: "active", hostnames: ["dev1.w3bs.org"],
      addresses: { ipv4: ["2.56.246.142"], ipv6: [] }, provider: { name: "Servitro" },
      cost: { amount: null, currency: "USD", interval: "month" } },
    { id: "epyc", name: "EPYC (on order)", profile: "server", status: "standby", hostnames: [],
      addresses: { ipv4: [], ipv6: [] }, cost: { amount: 1200, currency: "USD", interval: "year" } },
    { id: "bonita", name: "bonita", profile: "desktop", status: "active", hostnames: [], addresses: { ipv4: [], ipv6: [] } },
    { id: "old", name: "old", profile: "server", status: "retired", hostnames: [], addresses: { ipv4: [], ipv6: [] },
      cost: { amount: 999, currency: "USD", interval: "month" } },
  ],
};

describe("buildFleet with an inventory", () => {
  const inv = [{ org_id: "o1", document: inventory, updated_at: "2026-10-28T00:00:00Z" }];

  it("merges devices onto matched servers and adds the agentless ones as rows", () => {
    const { servers, summary } = buildFleet([
      row({ id: "a", name: "dev2.profullstack.com", hostname: "dev2.profullstack.com" }),
      row({ id: "b", name: "profullstack-dev-vienna", hostname: "profullstack-dev-vienna", public_ip: "152.53.47.37" }),
      row({ id: "c", name: "seed1", hostname: "ubuntu" }),
      row({ id: "d", name: "acme-web", org_id: "o2" }),
    ], orgs, NOW, new Map(), [], inv);

    const by = Object.fromEntries(servers.map((s) => [s.name, s]));
    expect(by["dev2.profullstack.com"]).toMatchObject({ agent: true, connection: "online" });
    expect(by["dev2.profullstack.com"].device).toMatchObject({ id: "dev2", provider: "RackNerd", monthly_label: "$149.00" });
    expect(by["profullstack-dev-vienna"].device).toMatchObject({ id: "vienna", monthly_label: "$53.00" });
    expect(by.seed1.device).toMatchObject({ id: "seed1", monthly_label: "unstated" });
    expect(by.seed1.device?.monthly.amount).toBeNull();
    // Another org's server never picks up this org's inventory.
    expect(by["acme-web"].device).toBeNull();

    const agentless = servers.filter((s) => !s.agent);
    expect(agentless.map((s) => s.name).sort()).toEqual(["EPYC (on order)", "bonita", "dev1"]);
    expect(agentless.every((s) => s.connection === "no-agent" && s.org_slug === "profullstack")).toBe(true);
    expect(by.dev1).toMatchObject({ id: "device:o1:dev1", hostname: "dev1.w3bs.org", ip_address: "2.56.246.142" });
    // Retired machines are neither a row nor a cost.
    expect(by.old).toBeUndefined();
    // Daemons first; agentless rows last.
    expect(servers.slice(-3).every((s) => !s.agent)).toBe(true);

    expect(summary).toMatchObject({
      total: 7, installs: 4, online: 4, offline: 0, no_agent: 3, inventories: 1,
      // 149 + 53 + 1200/12 for the standby box; nothing guessed for the rest.
      monthly_total: { USD: 302 }, monthly_total_label: "$302.00", cost_counted: 3, cost_unstated: 3,
    });
  });

  it("lets a server the caller cannot see claim its device instead of showing it as agentless", () => {
    const { servers } = buildFleet([], orgs, NOW, new Map(), [], inv, [
      { id: "h", name: "dev2", hostname: null, ip_address: null, public_ip: null, org_id: "o1" },
    ]);
    expect(servers.find((s) => s.name === "dev2")).toBeUndefined();
    expect(servers.filter((s) => !s.agent)).toHaveLength(5); // 6 live devices, dev2 claimed
  });

  it("skips an inventory that does not parse instead of failing the fleet", () => {
    const { servers, summary } = buildFleet([row({ id: "a" })], orgs, NOW, new Map(), [], [
      { org_id: "o1", document: "not json", updated_at: "2026-10-28T00:00:00Z" },
    ]);
    expect(servers).toHaveLength(1);
    expect(summary).toMatchObject({ inventories: 0, monthly_total_label: "—" });
  });
});

describe("monthlyLabel", () => {
  it("formats stated costs and never guesses a missing one", () => {
    expect(monthlyLabel({ amount: 388, currency: "USD", state: "stated" })).toBe("$388.00");
    expect(monthlyLabel({ amount: null, currency: "USD", state: "unstated" })).toBe("unstated");
    expect(monthlyLabel({ amount: null, currency: null, state: "grouped" })).toBe("grouped");
  });
});
