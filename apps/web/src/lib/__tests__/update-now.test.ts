import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
import { queueUpdate } from "@/lib/restart";
import { latestPublishedVersion, resetLatestReleaseCache } from "@/lib/latest-release";
import { buildFleet } from "@/lib/fleet";

describe("queueUpdate", () => {
  it("sends update to daemons that know it and restart to older ones", async () => {
    const inserted: Array<{ server_id: string; action_type: string; expires_at: string }> = [];
    const admin = { from: () => ({ insert: async (rows: typeof inserted) => { inserted.push(...rows); return { error: null }; } }) } as never;
    const out = await queueUpdate(admin, "o1", [
      { id: "old", version: "0.13.51" }, { id: "new", version: "0.13.57" }, { id: "newer", version: "0.14.0" }, { id: "unknown", version: null },
    ]);
    expect(out).toEqual({ updates: 2, restarts: 2 });
    expect(Object.fromEntries(inserted.map((r) => [r.server_id, r.action_type]))).toEqual({ old: "restart", new: "update", newer: "update", unknown: "restart" });
    expect(Date.parse(inserted[0].expires_at) - Date.now()).toBeLessThanOrEqual(10 * 60_000);
  });

  it("queues nothing for an empty list", async () => {
    expect(await queueUpdate({} as never, "o1", [])).toEqual({ updates: 0, restarts: 0 });
  });
});

describe("latestPublishedVersion", () => {
  beforeEach(() => resetLatestReleaseCache());

  it("reads npm once per ten minutes and keeps the last good answer when npm fails", async () => {
    let calls = 0;
    const ok = (async () => { calls++; return new Response(JSON.stringify({ version: "0.13.57" })); }) as unknown as typeof fetch;
    const down = (async () => { calls++; throw new Error("ENOTFOUND"); }) as unknown as typeof fetch;
    expect(await latestPublishedVersion(ok, 0)).toBe("0.13.57");
    expect(await latestPublishedVersion(down, 60_000)).toBe("0.13.57");
    expect(calls).toBe(1);
    expect(await latestPublishedVersion(down, 11 * 60_000)).toBe("0.13.57");
    expect(calls).toBe(2);
  });
});

describe("buildFleet published latest", () => {
  const row = (id: string, v: string) => ({
    id, name: id, hostname: id, ip_address: null, public_ip: null, org_id: "o1", status: "online",
    last_seen: new Date().toISOString(), threatcrushd_version: v, fleet_id: null, created_at: new Date().toISOString(),
  });
  const orgs = new Map([["o1", { name: "Org", slug: "org" }]]);

  it("a fleet all on the same old version is outdated against the published release", () => {
    const rows = [row("a", "0.13.51"), row("b", "0.13.51")] as never[];
    expect(buildFleet(rows, orgs).summary.outdated).toBe(0);
    const f = buildFleet(rows, orgs, Date.now(), new Map(), [], [], [], "0.13.57");
    expect(f.summary).toMatchObject({ outdated: 2, latest_version: "0.13.57" });
  });

  it("a box ahead of npm (fresh publish not visible yet) still sets latest", () => {
    const f = buildFleet([row("a", "0.13.58"), row("b", "0.13.57")] as never[], orgs, Date.now(), new Map(), [], [], [], "0.13.57");
    expect(f.summary).toMatchObject({ outdated: 1, latest_version: "0.13.58" });
  });
});
