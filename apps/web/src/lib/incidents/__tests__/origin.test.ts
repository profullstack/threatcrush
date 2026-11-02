import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({}) }));
vi.mock("@/lib/geoip", async (orig) => {
  const real = await orig<typeof import("@/lib/geoip")>();
  return {
    ...real,
    lookupIps: vi.fn(async (ips: string[]) =>
      new Map(ips.filter((ip) => ip === "20.171.2.194").map((ip) => [ip, { lat: 0, lon: 0, city: "Des Moines", country: "United States", countryCode: "US" }])),
    ),
    lookupAsn: vi.fn(async (ip: string) =>
      ip === "20.171.2.194" ? { asn: 8075, org: "Microsoft Corporation", network: null } : ip === "91.240.118.9" ? { asn: 49505, org: "OOO Network", network: null } : null,
    ),
  };
});

import { describeOrigin, describeOrigins, detectionSourceIp } from "../origin";
import { raiseDetectionIncidents } from "../store";
import { buildPage } from "../notify";
import { fakeDb } from "./fake-db";

const ORG = "b117883a-51b1-4c31-b3ed-8e45eda21f36";
const inventory = {
  document: {
    spec: "opendevice/0.1",
    devices: [
      { id: "dev1", name: "dev1", profile: "server", status: "active", hostnames: [], addresses: { ipv4: ["67.205.189.229"], ipv6: [] } },
    ],
  },
};

describe("describeOrigin", () => {
  it("names one of the org's own servers", () => {
    expect(describeOrigin({ ip: "23.95.228.174", own: "dev2.profullstack.com" })).toBe("From dev2.profullstack.com (23.95.228.174), one of your own servers");
  });

  it("flags an outside address with its place and network", () => {
    expect(describeOrigin({ ip: "91.240.118.9", geo: { lat: 0, lon: 0, city: "Moscow", country: "Russia" }, asn: { asn: 49505, org: "OOO Network", network: null } }))
      .toBe("From 91.240.118.9 in Moscow, Russia (OOO Network, AS49505), NOT one of your servers");
  });

  it("hints at GitHub Actions for Microsoft's network", () => {
    expect(describeOrigin({ ip: "20.171.2.194", asn: { asn: 8075, org: "Microsoft Corporation", network: null } })).toContain("may be GitHub Actions");
  });

  it("still says NOT one of your servers with no geo data", () => {
    expect(describeOrigin({ ip: "185.220.101.7" })).toBe("From 185.220.101.7, NOT one of your servers");
  });

  it("calls a private address local", () => {
    expect(describeOrigin({ ip: "10.0.0.5" })).toBe("From 10.0.0.5, a private or local address");
  });
});

describe("detectionSourceIp", () => {
  it("prefers the column, then evidence, then the log line", () => {
    expect(detectionSourceIp("1.2.3.4", { source_ip: "5.6.7.8" })).toBe("1.2.3.4");
    expect(detectionSourceIp(null, { source_ip: "5.6.7.8" })).toBe("5.6.7.8");
    expect(detectionSourceIp(null, { message: "Accepted publickey for root from 9.9.9.9 port 22 ssh2" })).toBe("9.9.9.9");
    expect(detectionSourceIp(null, { message: "nothing here" })).toBeNull();
    expect(detectionSourceIp("not-an-ip", null)).toBeNull();
  });
});

describe("describeOrigins", () => {
  it("knows servers and inventory devices as own machines", async () => {
    const db = fakeDb({
      servers: [{ org_id: ORG, name: "dev2.profullstack.com", hostname: "dev2.profullstack.com", ip_address: null, public_ip: "23.95.228.174" }],
      fleet_inventories: [{ org_id: ORG, ...inventory }],
    });
    const out = await describeOrigins(db as never, ORG, ["23.95.228.174", "67.205.189.229", "20.171.2.194"]);
    expect(out.get("23.95.228.174")).toBe("From dev2.profullstack.com (23.95.228.174), one of your own servers");
    expect(out.get("67.205.189.229")).toBe("From dev1 (67.205.189.229), one of your own servers");
    expect(out.get("20.171.2.194")).toBe("From 20.171.2.194 in Des Moines, United States (Microsoft Corporation, AS8075, may be GitHub Actions), NOT one of your servers");
  });

  it("does not treat another org's server as yours", async () => {
    const db = fakeDb({ servers: [{ org_id: "other", name: "theirs", public_ip: "23.95.228.174" }] });
    const out = await describeOrigins(db as never, ORG, ["23.95.228.174"]);
    expect(out.get("23.95.228.174")).toBe("From 23.95.228.174, NOT one of your servers");
  });
});

describe("root SSH login page", () => {
  const login = (id: string, ip: string, user = "root") => ({
    id, organization_id: ORG, server_id: "s3", severity: "critical" as const, title: "SSH Login Accepted",
    description: "Successful SSH login (alert only — never grounds for a ban) (1 events in 60s)", source_ip: ip,
    rule_id: `ssh-success-after-failures-${id}`, detected_at: "2026-11-02T06:29:54.644Z",
    evidence: { message: `SSH login accepted for ${user}`, user, source_ip: ip },
  });
  const run = async (d: ReturnType<typeof login>) => {
    const db = fakeDb({
      servers: [{ org_id: ORG, name: "dev2.profullstack.com", public_ip: "23.95.228.174" }],
      detections: [{ id: d.id, username: d.evidence.user, raw_metadata: { evidence: d.evidence } }],
    });
    const { evidence: _e, ...det } = d;
    const [o] = await raiseDetectionIncidents(db as never, [det], new Map([["s3", { fleet_id: null, name: "dev3.profullstack.com" }]]));
    return buildPage({ ...o.incident, findings_count: 1 } as never, "profullstack").sms;
  };

  it("says a login from dev2 came from one of our servers", async () => {
    const sms = await run(login("a", "23.95.228.174"));
    expect(sms).toContain("SSH Login Accepted on dev3.profullstack.com: From dev2.profullstack.com (23.95.228.174), one of your own servers — Target account: root");
    expect(sms.length).toBeLessThanOrEqual(320);
  });

  it("says a login from abroad is NOT one of our servers", async () => {
    const sms = await run(login("b", "91.240.118.9"));
    expect(sms).toContain(": From 91.240.118.9 (OOO Network, AS49505), NOT one of your servers — Target account: root");
    expect(sms.length).toBeLessThanOrEqual(320);
  });
});
