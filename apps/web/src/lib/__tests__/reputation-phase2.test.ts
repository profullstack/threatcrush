import { describe, it, expect, vi } from "vitest";

const deliverAlert = vi.fn().mockResolvedValue({ ok: true });
vi.mock("@/lib/alerts/senders", () => ({ deliverAlert: (...a: unknown[]) => deliverAlert(...a) }));
import type { DetectionRow } from "@/lib/community-threats";
import { networkBase } from "@/lib/geoip";
import { buildReport, ruleClassOf, scoreOf, takeLookup, resetLookupUsage, type ReputationReport } from "@/lib/reputation";
import { assembleDomain, nichedbDomain, parseIndicator, type AnyReport } from "@/lib/reputation-service";
import { runWatches, watchChange, watchMessage, type WatchRow } from "@/lib/reputation-watches";

const NOW = Date.parse("2026-10-17T12:00:00Z");

function det(rule_id: string, at = "2026-10-17T10:00:00Z", server_id = "a"): DetectionRow {
  return { source_ip: "45.148.10.7", server_id, organization_id: "org", severity: "high", rule_id, detected_at: at, occurrences: 1 };
}

describe("score v2", () => {
  it("weighs intent: exploit > brute force > scanning", () => {
    expect(ruleClassOf(["web-scanner-detection", "web-sqli-attack"])?.name).toBe("exploit attempts");
    expect(ruleClassOf(["attack-path_traversal"])?.name).toBe("exploit attempts");
    expect(ruleClassOf(["ssh-brute-force"])?.name).toBe("brute force");
    expect(ruleClassOf(["web-scanner-user-agent"])?.name).toBe("scanning");
    expect(ruleClassOf(["paywall-hammering"])).toBeNull();
    const base = { severity: "high", reports: 5, reporters: 2, last_seen: "2026-10-17T11:00:00Z" };
    const exploit = scoreOf({ ...base, rule_ids: ["web-sqli-attack"] }, NOW).score;
    const scan = scoreOf({ ...base, rule_ids: ["web-scanner-detection"] }, NOW).score;
    expect(exploit).toBeGreaterThan(scan);
  });

  it("halves a source that has been quiet for 30 days", () => {
    const loud = scoreOf({ severity: "high", reports: 5, reporters: 2, last_seen: "2026-10-17T11:00:00Z" }, NOW);
    const quiet = scoreOf({ severity: "high", reports: 5, reporters: 2, last_seen: "2026-08-01T00:00:00Z" }, NOW);
    expect(quiet.score).toBeLessThan(loud.score / 2 + 1);
    expect(quiet.reasons).toContain("quiet for over 30 days");
  });

  it("Pro reports the network owner and how much of it is listed", () => {
    const r = buildReport("45.148.10.7", [det("ssh-brute-force"), det("ssh-brute-force", undefined, "b")], [], null, "pro", NOW, {
      asn: { asn: 49870, org: "Alsycon B.V.", network: "45.148.10.0/24" },
      listed: 25,
    });
    expect(r.pro?.owner).toEqual({ asn: 49870, org: "Alsycon B.V.", network: "45.148.10.0/24", listed_addresses: 25 });
    expect(r.pro?.reasons.join(" ")).toContain("25 other listed addresses on the same network owner");
    const free = buildReport("45.148.10.7", [det("ssh-brute-force")], [], null, "free", NOW, {
      asn: { asn: 1, org: "x", network: null },
      listed: 25,
    });
    expect(JSON.stringify(free)).not.toContain("Alsycon");
  });

  it("finds the network base for a prefix", () => {
    expect(networkBase("45.148.10.7", 22)).toBe("45.148.8.0");
    expect(networkBase("45.148.10.7", 32)).toBe("45.148.10.7");
  });

  it("counts a bulk request as many lookups", () => {
    resetLookupUsage();
    expect(takeLookup("k", "free", NOW, 60).ok).toBe(true);
    expect(takeLookup("k", "free", NOW, 41).ok).toBe(false);
  });
});

describe("nichedb review decisions", () => {
  it("reads approvals and rejections with the shared token, drops junk, and is empty without it", async () => {
    const { loadReviewDecisions, resetCommunityCache } = await import("@/lib/community-threats");
    resetCommunityCache();
    delete process.env.TRAFFIC_FEED_TOKEN;
    const f = vi.fn();
    expect(await loadReviewDecisions(NOW, f as never)).toEqual({ approved: [], rejected: [] });
    expect(f).not.toHaveBeenCalled();
    process.env.TRAFFIC_FEED_TOKEN = "t";
    const good = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ approved: ["45.148.10.7", "junk"], rejected: ["172.12.140.170", 5] })),
    );
    expect(await loadReviewDecisions(NOW, good as never)).toEqual({ approved: ["45.148.10.7"], rejected: ["172.12.140.170"] });
    expect(good.mock.calls[0][1].headers.authorization).toBe("Bearer t");
    delete process.env.TRAFFIC_FEED_TOKEN;
    resetCommunityCache();
  });

  it("a reviewer's approval lists a single-reporter source and raises its score", () => {
    const rows = [det("ssh-brute-force")];
    const plain = buildReport("45.148.10.7", rows, [], null, "pro", NOW);
    const approved = buildReport("45.148.10.7", rows, [], null, "pro", NOW, { asn: null, listed: 0, reviewed: true });
    expect(plain.listed).toBe(false);
    expect(approved.listed).toBe(true);
    expect(approved.score).toBeGreaterThan(plain.score);
    expect(approved.pro?.reasons).toContain("approved by a reviewer on nichedb.dev/traffic");
  });
});

describe("indicators and domains", () => {
  it("parses IPs, domains and URLs; refuses private space and junk", () => {
    expect(parseIndicator("45.148.10.7")).toEqual({ type: "ip", value: "45.148.10.7" });
    expect(parseIndicator("[2A01:4F8::1]")).toEqual({ type: "ip", value: "2a01:4f8::1" });
    expect(parseIndicator("https://www.Evil.example/x?y")).toEqual({ type: "domain", value: "evil.example" });
    expect(parseIndicator("10.0.0.1")).toBeNull();
    expect(parseIndicator("watches")).toBeNull();
    expect(parseIndicator("1.2.3")).toBeNull();
  });

  const addr = (ip: string, listed: boolean, score: number) => ({ ip, listed, score }) as unknown as ReputationReport;

  it("a domain is listed when nichedb lists the name or any address is listed", () => {
    const clean = assembleDomain("ok.example", "free", [addr("1.1.1.2", false, 0)], { listed: false, score: 0, reasons: [] });
    expect(clean.listed).toBe(false);
    const byName = assembleDomain("evil.example", "free", [], { listed: true, score: 65, reasons: ["abuse.ch urlhaus: malware host"] });
    expect(byName.listed).toBe(true);
    expect(byName.reasons[0]).toContain("nichedb: abuse.ch");
    const byAddr = assembleDomain("x.example", "pro", [addr("45.148.10.7", true, 88), addr("1.1.1.2", false, 0)], null);
    expect(byAddr.listed).toBe(true);
    expect(byAddr.score).toBe(88);
    expect(byAddr.reasons).toEqual(["resolves to 45.148.10.7, listed (score 88)"]);
  });

  it("reads nichedb's answer, and treats a slow or failed one as unknown", async () => {
    const good = vi.fn().mockResolvedValue(new Response(JSON.stringify({ listed: true, score: 65, reasons: ["r"] })));
    expect(await nichedbDomain("evil.example", good as unknown as typeof fetch)).toEqual({ listed: true, score: 65, reasons: ["r"] });
    const bad = vi.fn().mockResolvedValue(new Response("no", { status: 503 }));
    expect(await nichedbDomain("evil.example", bad as unknown as typeof fetch)).toBeNull();
    const boom = vi.fn().mockRejectedValue(new Error("down"));
    expect(await nichedbDomain("evil.example", boom as unknown as typeof fetch)).toBeNull();
  });
});

describe("watch lists", () => {
  it("alerts on listed, cleared and a big score move; a clean first check is silent", () => {
    expect(watchChange({ last_listed: null, last_score: null }, { listed: false, score: 0 })).toBeNull();
    expect(watchChange({ last_listed: null, last_score: null }, { listed: true, score: 80 })).toBe("listed");
    expect(watchChange({ last_listed: false, last_score: 0 }, { listed: true, score: 80 })).toBe("listed");
    expect(watchChange({ last_listed: true, last_score: 80 }, { listed: false, score: 0 })).toBe("cleared");
    expect(watchChange({ last_listed: true, last_score: 60 }, { listed: true, score: 85 })).toBe("score");
    expect(watchChange({ last_listed: true, last_score: 80 }, { listed: true, score: 85 })).toBeNull();
  });

  const watch: WatchRow = {
    id: "w1",
    org_id: "org-1",
    indicator: "mail.example",
    kind: "domain",
    destination_id: null,
    note: "our MX",
    last_listed: false,
    last_score: 0,
  };
  const listedReport = {
    domain: "mail.example",
    type: "domain",
    tier: "pro",
    listed: true,
    score: 75,
    reasons: ["resolves to 45.148.10.7, listed (score 75)"],
    addresses: [],
    nichedb: null,
    public_record: "https://nichedb.dev/reputation/mail.example",
  } as unknown as AnyReport;

  it("writes a message a person can act on", () => {
    const m = watchMessage(watch, listedReport, "listed", "profullstack");
    expect(m.title).toBe("Domain mail.example is now listed");
    expect(m.severity).toBe("high");
    expect(m.body).toContain("our MX");
    expect(m.body).toContain("nichedb.dev/reputation/mail.example");
    expect(m.url).toContain("/org/profullstack");
  });

  it("checks Pro orgs only, records the result and alerts every destination on a change", async () => {
    const updates: Array<Record<string, unknown>> = [];
    const watches = [watch, { ...watch, id: "w2", org_id: "org-free", indicator: "x.example" }];
    const admin = {
      from(table: string) {
        const chain: Record<string, unknown> = {};
        const self = () => chain;
        Object.assign(chain, {
          select: self, eq: self, gt: self, in: self, not: self,
          order: (..._a: unknown[]) => (table === "reputation_watches" ? { limit: async () => ({ data: watches, error: null }) } : chain),
          limit: async () => ({ data: [], error: null }),
          update: (patch: Record<string, unknown>) => {
            updates.push(patch);
            return { eq: async () => ({ error: null }) };
          },
          maybeSingle: async () => ({ data: { slug: "profullstack" }, error: null }),
          then: (resolve: (v: unknown) => void) => {
            if (table === "reputation_subscriptions") {
              resolve({ data: [{ status: "confirmed", period_end: "2099-01-01T00:00:00Z" }], error: null });
            } else if (table === "alert_destinations") {
              resolve({ data: [{ id: "d1", organization_id: "org-1", name: "hook", type: "webhook", config: { url: "https://example.com/hook" }, enabled: true }], error: null });
            } else resolve({ data: [], error: null });
          },
        });
        return chain;
      },
    };
    // Only org-1 is Pro: tierFor reads reputation_subscriptions filtered by org; fake it per org.
    const tierAdmin = new Proxy(admin, {
      get(target, prop) {
        if (prop !== "from") return Reflect.get(target, prop);
        return (table: string) => {
          const c = target.from(table) as Record<string, unknown>;
          if (table !== "reputation_subscriptions") return c;
          let org = "";
          const wrap: Record<string, unknown> = {
            select: () => wrap,
            eq: (_k: string, v: string) => {
              org = v;
              return wrap;
            },
            gt: () =>
              Promise.resolve(
                org === "org-1"
                  ? { data: [{ status: "confirmed", period_end: "2099-01-01T00:00:00Z" }], error: null }
                  : { data: [], error: null },
              ),
          };
          return wrap;
        };
      },
    });
    const lookup = vi.fn().mockResolvedValue(listedReport);
    const result = await runWatches(tierAdmin as never, { lookup: lookup as never });
    expect(result).toEqual({ checked: 1, alerts: 1, skipped: 1, failed: 0 });
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(deliverAlert).toHaveBeenCalledTimes(1);
    expect(deliverAlert.mock.calls[0][1].title).toBe("Domain mail.example is now listed");
    expect(updates[0]).toMatchObject({ last_listed: true, last_score: 75 });
    expect(updates[0].last_changed_at).toBeDefined();
  });
});
