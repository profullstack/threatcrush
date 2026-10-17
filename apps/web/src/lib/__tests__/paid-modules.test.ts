import { describe, expect, it } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { entitlementFor, latestPeriodEnd, modulePlan, paidModule, PAID_MODULES } from "@/lib/paid-modules";

const NOW = Date.parse("2026-10-17T12:00:00Z");
const LW = PAID_MODULES["link-watch"];

/** Just enough of the query builder for entitlementFor: rows filtered by module, org and period_end. */
function fakeAdmin(rows: Array<{ org_id: string; module: string; status: string; period_end: string | null }>) {
  const q = (filters: Array<(r: (typeof rows)[number]) => boolean>) => {
    const b = {
      select: () => b,
      eq: (k: string, v: string) => q([...filters, (r) => (r as Record<string, unknown>)[k] === v]),
      in: (k: string, vs: string[]) => q([...filters, (r) => vs.includes((r as Record<string, string>)[k])]),
      gt: (k: string, v: string) =>
        q([...filters, (r) => (r as Record<string, string | null>)[k] != null && Date.parse((r as Record<string, string>)[k]) > Date.parse(v)]),
      then: (res: (x: { data: unknown; error: null }) => unknown) => res({ data: rows.filter((r) => filters.every((f) => f(r))), error: null }),
    };
    return b;
  };
  return { from: () => q([]) } as unknown as SupabaseClient;
}

describe("paid modules", () => {
  it("knows link-watch and its plans, nothing else", () => {
    expect(paidModule("link-watch")?.name).toBe("Link Watch");
    expect(paidModule("constructor")).toBeNull();
    expect(modulePlan(LW, "monthly")?.months).toBe(1);
    expect(modulePlan(LW, "lifetime")).toBeNull();
  });

  it("latestPeriodEnd ignores unsettled rows", () => {
    expect(
      latestPeriodEnd([
        { status: "pending", period_end: "2030-01-01T00:00:00Z" },
        { status: "confirmed", period_end: "2027-01-01T00:00:00Z" },
      ])?.toISOString(),
    ).toBe("2027-01-01T00:00:00.000Z");
    expect(latestPeriodEnd([])).toBeNull();
  });

  it("a comp grant on the org entitles it; another module's or an expired row does not", async () => {
    const admin = fakeAdmin([
      { org_id: "house", module: "link-watch", status: "confirmed", period_end: "2126-01-01T00:00:00Z" },
      { org_id: "other", module: "spend-guard", status: "confirmed", period_end: "2126-01-01T00:00:00Z" },
      { org_id: "lapsed", module: "link-watch", status: "confirmed", period_end: "2026-01-01T00:00:00Z" },
      { org_id: "unpaid", module: "link-watch", status: "pending", period_end: "2126-01-01T00:00:00Z" },
    ]);
    expect(await entitlementFor(admin, LW, ["house"], NOW)).toMatchObject({ active: true, org_id: "house" });
    for (const org of ["other", "lapsed", "unpaid"])
      expect((await entitlementFor(admin, LW, [org], NOW)).active).toBe(false);
    expect((await entitlementFor(admin, LW, [], NOW)).active).toBe(false);
  });
});
