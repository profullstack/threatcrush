import { describe, it, expect, beforeEach } from "vitest";
import type { BlocklistEntry, DetectionRow } from "@/lib/community-threats";
import {
  buildReport,
  DAILY_LIMIT,
  hasActivePeriod,
  historyOf,
  isReputationCurrency,
  neighboursOf,
  networkOf,
  periodEnd,
  planById,
  reputationProEnabled,
  resetLookupUsage,
  scoreOf,
  takeLookup,
} from "@/lib/reputation";

const NOW = Date.parse("2026-10-17T12:00:00Z");

function det(server_id: string, severity: string, at: string, rule_id = "ssh-brute-force", occurrences = 1): DetectionRow {
  return { source_ip: "45.148.10.7", server_id, organization_id: "org", severity, rule_id, detected_at: at, occurrences };
}

function entry(ip: string, reports = 5): BlocklistEntry {
  return { ip, reports, reporters: 2, severity: "high", first_seen: null, last_seen: "2026-10-17T00:00:00Z", rule_ids: [] };
}

describe("plans and payments", () => {
  it("is crypto only: card is not a currency", () => {
    expect(isReputationCurrency("usdc_pol")).toBe(true);
    expect(isReputationCurrency("btc")).toBe(true);
    expect(isReputationCurrency("card")).toBe(false);
    expect(planById("pro-monthly")?.months).toBe(1);
    expect(planById("nope")).toBeNull();
  });

  it("is off sale until the env flag says so", () => {
    delete process.env.REPUTATION_PRO_ENABLED;
    expect(reputationProEnabled()).toBe(false);
    process.env.REPUTATION_PRO_ENABLED = "true";
    expect(reputationProEnabled()).toBe(true);
    delete process.env.REPUTATION_PRO_ENABLED;
  });

  it("stacks a renewal on the running period, starts now when it lapsed", () => {
    const now = new Date(NOW);
    const running = new Date(NOW + 10 * 86_400_000);
    expect(periodEnd(now, 1, running).getTime()).toBe(running.getTime() + 30 * 86_400_000);
    expect(periodEnd(now, 1, new Date(NOW - 86_400_000)).getTime()).toBe(NOW + 30 * 86_400_000);
    expect(periodEnd(now, 12, null).getTime()).toBe(NOW + 360 * 86_400_000);
  });

  it("is Pro only while a settled period runs", () => {
    const later = new Date(NOW + 86_400_000).toISOString();
    const earlier = new Date(NOW - 86_400_000).toISOString();
    expect(hasActivePeriod([{ status: "confirmed", period_end: later }], NOW)).toBe(true);
    expect(hasActivePeriod([{ status: "forwarded", period_end: later }], NOW)).toBe(true);
    expect(hasActivePeriod([{ status: "pending", period_end: later }], NOW)).toBe(false);
    expect(hasActivePeriod([{ status: "confirmed", period_end: earlier }], NOW)).toBe(false);
    expect(hasActivePeriod([{ status: "confirmed", period_end: null }], NOW)).toBe(false);
  });
});

describe("scoring, neighbourhood, history", () => {
  it("scores corroborated, recent, severe sources higher, and says why", () => {
    const weak = scoreOf({ severity: "low", reports: 1, reporters: 1, last_seen: "2026-09-01T00:00:00Z" }, NOW);
    const strong = scoreOf({ severity: "critical", reports: 40, reporters: 4, last_seen: "2026-10-17T11:00:00Z", neighbours: 3 }, NOW);
    expect(strong.score).toBeGreaterThan(weak.score);
    expect(strong.score).toBeLessThanOrEqual(100);
    expect(strong.reasons.join(" ")).toContain("4 independent reporters");
    expect(strong.reasons.join(" ")).toContain("same /24");
    // Last seen 2026-09-01, over 30 days before NOW: decayed, and it says so.
    expect(weak.reasons).toEqual(["quiet for over 30 days"]);
  });

  it("finds the /24 and the /48", () => {
    expect(networkOf("45.148.10.7")).toBe("45.148.10.0/24");
    expect(networkOf("2a01:4f8:c0c::1")).toBe("2a01:4f8:c0c::/48");
    const n = neighboursOf("45.148.10.7", [entry("45.148.10.7"), entry("45.148.10.9", 9), entry("45.148.11.1"), entry("45.148.10.200", 2)]);
    expect(n.map((e) => e.ip)).toEqual(["45.148.10.9", "45.148.10.200"]);
  });

  it("folds history by day, newest first", () => {
    const h = historyOf([
      det("a", "medium", "2026-10-16T10:00:00Z", "web-scanner-detection"),
      det("b", "high", "2026-10-17T01:00:00Z", "ssh-brute-force", 3),
      det("a", "low", "2026-10-17T02:00:00Z", "web-sqli-attack"),
    ]);
    expect(h).toEqual([
      { day: "2026-10-17", reports: 4, rules: ["ssh-brute-force", "web-sqli-attack"], max_severity: "high" },
      { day: "2026-10-16", reports: 1, rules: ["web-scanner-detection"], max_severity: "medium" },
    ]);
  });
});

describe("buildReport", () => {
  const rows = [det("a", "high", "2026-10-17T10:00:00Z"), det("b", "high", "2026-10-16T10:00:00Z")];
  const blocklist = [entry("45.148.10.7"), entry("45.148.10.8")];
  const geo = { lat: 0, lon: 0, city: "Amsterdam", countryCode: "NL" };

  it("free: the verdict and an upgrade pointer, no history or neighbours", () => {
    const r = buildReport("45.148.10.7", rows, blocklist, geo, "free", NOW);
    expect(r.listed).toBe(true);
    expect(r.reporters).toBe(2);
    expect(r.country).toBe("NL");
    expect(r.pro).toBeUndefined();
    expect(r.upgrade?.url).toContain("/reputation");
    expect(JSON.stringify(r)).not.toContain("Amsterdam");
    expect(r.public_record).toBe("https://nichedb.dev/reputation/45.148.10.7");
  });

  it("pro: history, neighbours, city and reasons", () => {
    const r = buildReport("45.148.10.7", rows, blocklist, geo, "pro", NOW);
    expect(r.pro?.neighbours.count).toBe(1);
    expect(r.pro?.neighbours.addresses[0].ip).toBe("45.148.10.8");
    expect(r.pro?.history.length).toBe(2);
    expect(r.pro?.city).toBe("Amsterdam");
    expect(r.pro?.reasons.length).toBeGreaterThan(0);
    expect(r.upgrade).toBeUndefined();
  });

  it("one uncorroborated low report is not listed, and nothing is score 0", () => {
    const one = buildReport("45.148.10.7", [det("a", "low", "2026-10-17T10:00:00Z")], [], null, "free", NOW);
    expect(one.listed).toBe(false);
    const none = buildReport("45.148.10.7", [], [], null, "free", NOW);
    expect(none.listed).toBe(false);
    expect(none.score).toBe(0);
    expect(none.severity).toBe("none");
  });
});

describe("daily allowance", () => {
  beforeEach(() => resetLookupUsage());
  it("counts per caller per UTC day", () => {
    for (let i = 0; i < DAILY_LIMIT.free; i++) expect(takeLookup("k", "free", NOW).ok).toBe(true);
    expect(takeLookup("k", "free", NOW).ok).toBe(false);
    expect(takeLookup("other", "free", NOW).ok).toBe(true);
    expect(takeLookup("k", "free", NOW + 86_400_000).ok).toBe(true);
    expect(takeLookup("p", "pro", NOW).limit).toBe(DAILY_LIMIT.pro);
  });
});
