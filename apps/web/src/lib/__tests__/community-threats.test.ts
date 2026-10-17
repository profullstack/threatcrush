import { describe, it, expect } from "vitest";
import {
  aggregateBlocklist,
  aggregateSummary,
  isPublishable,
  maskIp,
  type DetectionRow,
} from "@/lib/community-threats";

function row(
  source_ip: string,
  server_id: string,
  severity = "high",
  occurrences = 1,
  rule_id = "web-attack",
): DetectionRow {
  return {
    source_ip,
    server_id,
    organization_id: "org",
    severity,
    rule_id,
    title: rule_id,
    detected_at: "2026-10-17T10:00:00Z",
    last_detected_at: "2026-10-17T10:00:00Z",
    occurrences,
  };
}

const NOW = Date.parse("2026-10-17T12:00:00Z");

describe("maskIp", () => {
  it("hides the host octet of an IPv4 address", () => {
    expect(maskIp("203.0.113.9")).toBe("203.0.113.x");
  });
  it("masks IPv6 to a /48", () => {
    expect(maskIp("2001:db8:abcd:1::9")).toBe("2001:db8:abcd::/48");
  });
});

describe("isPublishable — the anti-poison bar", () => {
  it("publishes a source corroborated by >= 2 reporters", () => {
    expect(isPublishable({ reporters: new Set(["a", "b"]), reports: 2, severity: "low" })).toBe(true);
  });
  it("does not publish a single uncorroborated low-severity report", () => {
    expect(isPublishable({ reporters: new Set(["a"]), reports: 1, severity: "low" })).toBe(false);
  });
  it("publishes a single reporter only when high-severity with repeat hits", () => {
    expect(isPublishable({ reporters: new Set(["a"]), reports: 3, severity: "critical" })).toBe(true);
    expect(isPublishable({ reporters: new Set(["a"]), reports: 2, severity: "critical" })).toBe(false);
  });
});

describe("aggregateBlocklist", () => {
  const rows: DetectionRow[] = [
    row("9.9.9.1", "s1", "medium"),
    row("9.9.9.1", "s2", "medium"), // 2 reporters -> publishable
    row("9.9.9.2", "s1", "low"), // single low -> excluded
    row("9.9.9.3", "s1", "critical", 4), // single but strong+repeat -> publishable
  ];

  it("includes only corroborated / strong sources, with full IPs", () => {
    const list = aggregateBlocklist(rows);
    const ips = list.map((e) => e.ip).sort();
    expect(ips).toEqual(["9.9.9.1", "9.9.9.3"]);
    expect(list.find((e) => e.ip === "9.9.9.1")?.reporters).toBe(2);
  });

  it("excludes the uncorroborated low-severity source", () => {
    expect(aggregateBlocklist(rows).some((e) => e.ip === "9.9.9.2")).toBe(false);
  });
});

describe("aggregateSummary", () => {
  const rows: DetectionRow[] = [
    row("9.9.9.1", "s1", "medium"),
    row("9.9.9.1", "s2", "medium"),
    row("9.9.9.2", "s1", "low"),
    row("9.9.9.3", "s1", "critical", 4),
  ];
  const summary = aggregateSummary(rows, 7, NOW);

  it("counts distinct sources, reporters and published", () => {
    expect(summary.totals.sources).toBe(3);
    expect(summary.totals.reporters).toBe(2); // s1, s2
    expect(summary.totals.published).toBe(2); // 9.9.9.1 and 9.9.9.3
    expect(summary.totals.active_bans).toBe(7);
  });

  it("weights severity counts by occurrences", () => {
    expect(summary.by_severity.medium).toBe(2);
    expect(summary.by_severity.low).toBe(1);
    expect(summary.by_severity.critical).toBe(4);
  });

  it("NEVER leaks a full host address into the public summary", () => {
    const json = JSON.stringify(summary);
    expect(json).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
    expect(json).toContain("9.9.9.x"); // masked form present
  });
});
