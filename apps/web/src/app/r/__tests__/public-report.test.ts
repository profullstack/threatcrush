import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const TOKEN = "a".repeat(43);
let shares: Array<{ id: string; org_id: string; token: string; revoked_at: string | null; last_viewed_at?: string }> = [];

function builder(table: string) {
  const filters: Array<(r: Record<string, unknown>) => boolean> = [];
  let update: Record<string, unknown> | null = null;
  const b = {
    select() { return b; },
    update(p: Record<string, unknown>) { update = p; return b; },
    eq(col: string, val: unknown) { filters.push((r) => r[col] === val); return b; },
    is(col: string, val: unknown) { filters.push((r) => r[col] === val); return b; },
    async maybeSingle() {
      const rows = table === "report_shares" ? shares.filter((r) => filters.every((f) => f(r))) : [];
      return { data: rows[0] ?? null, error: null };
    },
    then(resolve: (v: unknown) => void) {
      if (table === "report_shares" && update) {
        for (const r of shares.filter((row) => filters.every((f) => f(row)))) Object.assign(r, update);
      }
      resolve({ data: null, error: null });
    },
  };
  return b;
}

vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (t: string) => builder(t) }) }));
vi.mock("@/lib/fix-report", async (importOriginal) => {
  const real = await importOriginal<typeof import("@/lib/fix-report")>();
  return {
    ...real,
    loadFixReport: async () => real.buildFixReport({ name: "Profullstack", slug: "profullstack" }, [], [], []),
  };
});

const { GET } = await import("../[token]/route");
const get = (token: string, query = "") =>
  GET(new NextRequest(`https://threatcrush.com/r/${token}${query}`), { params: Promise.resolve({ token }) });

beforeEach(() => {
  shares = [{ id: "sh1", org_id: "o1", token: TOKEN, revoked_at: null }];
});

describe("GET /r/<token>", () => {
  it("serves the report as markdown, never indexed or cached", async () => {
    const res = await get(TOKEN);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/markdown");
    expect(res.headers.get("x-robots-tag")).toContain("noindex");
    expect(res.headers.get("cache-control")).toContain("no-store");
    expect(await res.text()).toContain("# ThreatCrush fix report: Profullstack");
    expect(shares[0].last_viewed_at).toBeTruthy();
  });

  it("serves JSON on request", async () => {
    const res = await get(TOKEN, "?format=json");
    expect((await res.json()).org).toEqual({ name: "Profullstack", slug: "profullstack" });
  });

  it("answers 404 for a revoked, unknown or malformed token", async () => {
    shares[0].revoked_at = "2026-10-01T11:00:00Z";
    expect((await get(TOKEN)).status).toBe(404);
    expect((await get("b".repeat(43))).status).toBe(404);
    expect((await get("short")).status).toBe(404);
  });
});
