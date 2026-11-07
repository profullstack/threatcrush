import { describe, expect, it } from "vitest";
import { applyCoinpayPass, PASS_CREDITS, passFromUserinfo, passSource, type PassStore } from "@/lib/coinpay-pass";

function memoryStore() {
  const until = new Map<string, string | null>();
  const sources = new Set<string>();
  const balance = new Map<string, number>();
  const store: PassStore = {
    async setPassUntil(sub, u) { until.set(sub, u); },
    async grantOnce(userId, credits, source) {
      const key = `${userId}:${source}`; // credit_deposits_grant_source_uniq
      if (sources.has(key)) return { applied: false };
      sources.add(key);
      balance.set(userId, (balance.get(userId) ?? 0) + credits);
      return { applied: true };
    },
  };
  return { store, until, balance };
}

const now = new Date("2026-11-07T12:00:00Z");
const until = "2026-12-07T12:00:00.000Z";

describe("Profullstack Pass credits", () => {
  it("is worth the smallest top-up ($1 = 1 scan credit)", () => {
    expect(PASS_CREDITS).toBe(1);
    expect(passSource("s", new Date(until))).toBe(`coinpay-pass:s:${until}`);
  });

  it("pays once per pass, records pass_until, and pays again on renewal", async () => {
    const m = memoryStore();
    const pass = passFromUserinfo({ pass: { active: true, expires_at: until } }, now);
    expect(await applyCoinpayPass(m.store, "u1", "sub1", pass, now)).toBe(true);
    expect(await applyCoinpayPass(m.store, "u1", "sub1", pass, now)).toBe(false);
    expect(m.balance.get("u1")).toBe(PASS_CREDITS);
    expect(m.until.get("sub1")).toBe(until);
    const renewed = passFromUserinfo({ pass: { active: true, expires_at: "2027-01-07T12:00:00.000Z" } }, now);
    expect(await applyCoinpayPass(m.store, "u1", "sub1", renewed, now)).toBe(true);
    expect(m.balance.get("u1")).toBe(2 * PASS_CREDITS);
  });

  it("pays nothing without an active, unexpired pass", async () => {
    const m = memoryStore();
    for (const claims of [{}, { pass: { active: false } }, { pass: { active: true } }, { pass: { active: true, expires_at: "x" } }, { pass: { active: true, expires_at: "2026-10-01T00:00:00Z" } }]) {
      expect(await applyCoinpayPass(m.store, "u2", "sub2", passFromUserinfo(claims, now), now)).toBe(false);
    }
    expect(m.balance.get("u2")).toBeUndefined();
    expect(m.until.get("sub2")).toBeNull();
  });
});
