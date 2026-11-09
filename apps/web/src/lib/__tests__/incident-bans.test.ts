import { describe, expect, it } from "vitest";
import { ipsInText, summarizeBans, type BanAction } from "@/lib/incidents/bans";

const block = (ip: string, executed: string, expires: string | null, extra: Partial<BanAction> = {}): BanAction => ({
  action_type: "block", target_value: ip, status: "executed", created_at: executed, executed_at: executed, expires_at: expires,
  metadata: { source: "daemon", dry_run: false }, ...extra,
});
const unblock = (ip: string, executed: string, reason = "ban expired"): BanAction => ({
  action_type: "unblock", target_value: ip, status: "executed", created_at: executed, executed_at: executed, expires_at: null,
  metadata: { source: "daemon", reason },
});

describe("ipsInText", () => {
  it("finds IPv4 and IPv6 addresses in incident summaries but not times or ports", () => {
    expect(ipsInText("From 121.224.78.164 in Nanjing — Invalid SSH user: ubuntu from 121.224.78.164 port 51234 at 01:19:05")).toEqual(["121.224.78.164"]);
    expect(ipsInText("from 2001:db8::1 and 999.1.1.1")).toEqual(["2001:db8::1"]);
    expect(ipsInText(null)).toEqual([]);
  });
});

describe("summarizeBans", () => {
  // Real shape from incident 34bebad3 (dev2 SSH User Enumeration, 2026-11-09).
  const actions = [
    block("50.6.200.152", "2026-11-08T17:19:14.698Z", "2026-11-08T17:24:14.698Z"),
    unblock("50.6.200.152", "2026-11-08T17:24:17.870Z"),
    block("50.6.200.152", "2026-11-08T17:29:16.964Z", "2026-11-08T17:39:16.964Z"),
    block("50.6.200.152", "2026-11-08T17:29:16.984Z", "2026-11-08T17:49:16.984Z"),
    unblock("50.6.200.152", "2026-11-08T17:50:06.031Z"),
    block("121.224.78.164", "2026-11-09T01:19:16.095Z", "2026-11-09T01:24:16.095Z"),
    block("121.224.78.164", "2026-11-09T01:19:16.654Z", "2026-11-09T02:39:16.654Z"),
  ];

  it("reports an active laddered ban with its expiry and longest block", () => {
    const [chinese] = summarizeBans(["121.224.78.164"], actions, Date.parse("2026-11-09T02:00:00Z"));
    expect(chinese).toMatchObject({ state: "active", blocks: 2, banned_until: "2026-11-09T02:39:16.654Z", longest_seconds: 4800 });
  });

  it("reports a ban that the daemon released as expired, not lifted", () => {
    const [oracle] = summarizeBans(["50.6.200.152"], actions, Date.parse("2026-11-09T02:00:00Z"));
    expect(oracle).toMatchObject({ state: "expired", blocks: 3, lifted_at: "2026-11-08T17:50:06.031Z", longest_seconds: 1200 });
  });

  it("expires an active ban once its time passes even before the unblock arrives", () => {
    const [chinese] = summarizeBans(["121.224.78.164"], actions, Date.parse("2026-11-09T03:00:00Z"));
    expect(chinese.state).toBe("expired");
  });

  it("distinguishes a manual unblock, a failed block, a dry run and no block at all", () => {
    const out = summarizeBans(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"], [
      block("1.1.1.1", "2026-11-09T00:00:00Z", "2026-11-09T05:00:00Z"),
      unblock("1.1.1.1", "2026-11-09T00:10:00Z", "unblocked from the dashboard"),
      block("2.2.2.2", "2026-11-09T00:00:00Z", null, { status: "failed", metadata: { error: "Operation not permitted" } }),
      block("3.3.3.3", "2026-11-09T00:00:00Z", "2026-11-09T00:05:00Z", { metadata: { dry_run: true } }),
    ], Date.parse("2026-11-09T01:00:00Z"));
    expect(out.map((b) => b.state)).toEqual(["lifted", "failed", "dry_run", "none"]);
    expect(out[1].last_error).toBe("Operation not permitted");
  });

  it("treats a block with no expiry as active until unblocked", () => {
    const [b] = summarizeBans(["5.5.5.5"], [block("5.5.5.5", "2026-11-01T00:00:00Z", null)], Date.parse("2026-11-09T00:00:00Z"));
    expect(b).toMatchObject({ state: "active", banned_until: null });
  });
});
