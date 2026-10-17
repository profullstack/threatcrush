import { describe, it, expect } from "vitest";
import { authFor, formatAny, formatReport } from "../reputation.js";

const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");

describe("reputation CLI", () => {
  it("prefers THREATCRUSH_API_KEY, falls back to the login session and its org", () => {
    expect(authFor({ THREATCRUSH_API_KEY: "tc_agent_x" }, { token: "t", current_org_id: "o" })).toEqual({
      headers: { Authorization: "Bearer tc_agent_x" },
      orgId: null,
    });
    expect(authFor({}, { token: "t", current_org_id: "o" })).toEqual({
      headers: { Authorization: "Bearer t" },
      orgId: "o",
    });
    expect(authFor({}, {})).toBeNull();
  });

  it("prints the verdict, and for free keys where the rest lives", () => {
    const lines = formatReport({
      ip: "45.148.10.7",
      tier: "free",
      listed: true,
      score: 71,
      severity: "high",
      reports: 9,
      reporters: 2,
      last_seen: "2026-10-17T10:00:00Z",
      rule_ids: ["ssh-brute-force"],
      country: "NL",
      public_record: "https://nichedb.dev/reputation/45.148.10.7",
      upgrade: { url: "https://threatcrush.com/reputation" },
    }).map(strip);
    expect(lines[0]).toContain("LISTED  score 71/100");
    expect(lines.join("\n")).toContain("2 reporters");
    expect(lines.join("\n")).toContain("threatcrush.com/reputation");
  });

  it("prints a domain verdict with its addresses", () => {
    const lines = formatAny({
      domain: "mail.example",
      type: "domain",
      tier: "pro",
      listed: true,
      score: 75,
      reasons: ["resolves to 45.148.10.7, listed (score 75)"],
      addresses: [{ ip: "45.148.10.7", listed: true, score: 75 } as never],
      public_record: "https://nichedb.dev/reputation/mail.example",
    }).map(strip);
    expect(lines[0]).toContain("mail.example  LISTED  score 75/100");
    expect(lines.join("\n")).toContain("45.148.10.7: listed, 75/100");
  });

  it("prints Pro history and neighbours", () => {
    const lines = formatReport({
      ip: "45.148.10.7",
      tier: "pro",
      listed: false,
      score: 0,
      severity: "none",
      reports: 0,
      reporters: 0,
      last_seen: null,
      rule_ids: [],
      country: null,
      public_record: "https://nichedb.dev/reputation/45.148.10.7",
      pro: {
        reasons: [],
        city: null,
        network: "45.148.10.0/24",
        neighbours: { count: 3, addresses: [] },
        history: [{ day: "2026-10-17", reports: 4, rules: ["ssh-brute-force"] }],
      },
    }).map(strip);
    expect(lines[0]).toContain("not listed");
    expect(lines.join("\n")).toContain("45.148.10.0/24: 3 other listed");
    expect(lines.join("\n")).toContain("2026-10-17");
  });
});
