import { describe, expect, it } from "vitest";
import { aggregateOrigins, maskIp, parseWindow, serverAddress } from "@/lib/attack-map";
import { isPublicIp } from "@/lib/geoip";

const geo = new Map([
  ["45.155.205.233", { lat: 52.37, lon: 4.9, city: "Amsterdam", country: "Netherlands", countryCode: "NL" }],
  ["45.155.205.9", { lat: 52.37, lon: 4.9, city: "Amsterdam", country: "Netherlands", countryCode: "NL" }],
  ["218.92.0.112", { lat: 32.06, lon: 118.78, city: "Nanjing", country: "China", countryCode: "CN" }],
]);

function row(ip: string | null, severity: "low" | "high" | "critical", at: string, occurrences = 1, server = "s1") {
  return {
    source_ip: ip,
    severity,
    server_id: server,
    occurrences,
    last_detected_at: at,
    detected_at: at,
    category: "ssh-brute-force",
    rule_id: "ssh",
  };
}

describe("isPublicIp", () => {
  it("rejects private, loopback, CGNAT and link-local; accepts public", () => {
    for (const ip of ["10.0.0.1", "172.20.1.1", "192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.1.1", "::1", "fd00::1", "fe80::1", "nope"]) {
      expect(isPublicIp(ip)).toBe(false);
    }
    for (const ip of ["23.95.228.174", "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8"]) {
      expect(isPublicIp(ip)).toBe(true);
    }
  });
});

describe("aggregateOrigins", () => {
  it("folds rows per address: counts occurrences, keeps the worst severity and the latest server", () => {
    const out = aggregateOrigins(
      [
        row("45.155.205.233", "low", "2026-10-17T10:00:00Z", 3, "s1"),
        row("45.155.205.233", "critical", "2026-10-17T10:05:00Z", 2, "s2"),
        row("218.92.0.112", "high", "2026-10-17T09:00:00Z"),
        row("10.0.0.5", "high", "2026-10-17T09:00:00Z"),
        row(null, "high", "2026-10-17T09:00:00Z"),
      ],
      geo,
    );
    expect(out).toHaveLength(2);
    const ams = out.find((o) => o.ip === "45.155.205.233")!;
    expect(ams.count).toBe(5);
    expect(ams.severity).toBe("critical");
    expect(ams.serverId).toBe("s2");
    expect(ams.lastSeen).toBe("2026-10-17T10:05:00Z");
    expect(ams.countryCode).toBe("NL");
  });

  it("leaves out our own servers' addresses", () => {
    const out = aggregateOrigins(
      [row("45.155.205.233", "critical", "2026-10-17T10:00:00Z"), row("218.92.0.112", "high", "2026-10-17T10:01:00Z")],
      geo,
      { exclude: new Set(["45.155.205.233"]) },
    );
    expect(out.map((o) => o.ip)).toEqual(["218.92.0.112"]);
  });

  it("merges a /24 into one masked origin for the public map", () => {
    const out = aggregateOrigins(
      [row("45.155.205.233", "low", "2026-10-17T10:00:00Z"), row("45.155.205.9", "high", "2026-10-17T10:01:00Z")],
      geo,
      { mask: true },
    );
    expect(out).toHaveLength(1);
    expect(out[0].ip).toBe("45.155.205.0/24");
    expect(out[0].count).toBe(2);
  });
});

describe("helpers", () => {
  it("masks v4 to /24 and v6 to /48", () => {
    expect(maskIp("203.0.113.77")).toBe("203.0.113.0/24");
    expect(maskIp("2606:4700:10:1::5")).toBe("2606:4700:10::/48");
  });

  it("places a server by its heartbeat address before the typed one, never a private one", () => {
    const base = { id: "a", name: "a", hostname: null, last_seen: null };
    expect(serverAddress({ ...base, public_ip: "23.95.228.174", ip_address: "8.8.8.8" })).toBe("23.95.228.174");
    expect(serverAddress({ ...base, public_ip: "172.18.0.1", ip_address: "8.8.8.8" })).toBe("8.8.8.8");
    expect(serverAddress({ ...base, public_ip: null, ip_address: "192.168.0.2" })).toBeNull();
  });

  it("only accepts the offered windows", () => {
    expect(parseWindow("15")).toBe(15);
    expect(parseWindow("1440")).toBe(1440);
    expect(parseWindow("7")).toBe(60);
    expect(parseWindow(null)).toBe(60);
  });
});
