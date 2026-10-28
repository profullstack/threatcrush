import { describe, expect, it } from "vitest";
import { inKnown, knownName, matchKnown, type KnownIp } from "@/lib/known-ips";
import { buildDetectionMessage } from "@/lib/alerts/message";

const e = (type: "ip" | "cidr", value: string, label: string | null = null): KnownIp =>
  ({ id: value, type, value, label, note: null, source: "manual", server_id: null });

describe("inKnown", () => {
  it("matches exact IPv4 and IPv4 ranges", () => {
    expect(inKnown("23.95.228.174", e("ip", "23.95.228.174"))).toBe(true);
    expect(inKnown("23.95.228.175", e("ip", "23.95.228.174"))).toBe(false);
    expect(inKnown("2.56.246.142", e("cidr", "2.56.246.140/30"))).toBe(true);
    expect(inKnown("2.56.246.144", e("cidr", "2.56.246.140/30"))).toBe(false);
    expect(inKnown("10.1.2.3", e("cidr", "10.0.0.0/8"))).toBe(true);
  });

  it("matches IPv6 ranges and never crosses families or accepts junk", () => {
    expect(inKnown("2604:a880:400:d1::4:c3fe:1", e("cidr", "2604:a880:400:d1::/64"))).toBe(true);
    expect(inKnown("2604:a880:400:d2::1", e("cidr", "2604:a880:400:d1::/64"))).toBe(false);
    expect(inKnown("10.0.0.1", e("cidr", "2604:a880::/32"))).toBe(false);
    expect(inKnown("not-an-ip", e("cidr", "10.0.0.0/8"))).toBe(false);
  });
});

describe("matchKnown", () => {
  it("prefers the exact entry over a range and names it by label", () => {
    const list = [e("cidr", "23.95.228.0/24", "DediRock range"), e("ip", "23.95.228.174", "dev2")];
    expect(knownName(matchKnown("23.95.228.174", list)!)).toBe("dev2");
    expect(knownName(matchKnown("23.95.228.9", list)!)).toBe("DediRock range");
    expect(matchKnown("1.2.3.4", list)).toBeNull();
    expect(matchKnown(null, list)).toBeNull();
  });
});

describe("detection alert from a known IP", () => {
  const d = {
    id: "d1", organization_id: "o1", server_id: "s1", severity: "high" as const, title: "SQL Injection Attempt",
    description: "union select", source_ip: "23.95.228.174", rule_id: "web-sqli-attack", detected_at: "2026-10-28T16:00:00Z",
  };
  it("says it is ours and why that matters", () => {
    const m = buildDetectionMessage(d, { orgSlug: "acme", serverName: "vienna", knownSource: "dev2" });
    expect(m.title).toBe("[HIGH] [OURS: dev2] SQL Injection Attempt");
    expect(m.body.split("\n")[0]).toMatch(/one of your Known IPs \(dev2\).*compromised/);
  });
  it("is unchanged for everyone else", () => {
    expect(buildDetectionMessage(d, { orgSlug: "acme", serverName: "vienna" }).title).toBe("[HIGH] SQL Injection Attempt");
  });
});
