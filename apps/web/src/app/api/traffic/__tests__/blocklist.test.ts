import { describe, it, expect, vi, beforeEach } from "vitest";
import type { NextRequest } from "next/server";

vi.mock("@/lib/feed-auth", () => ({ feedPrincipal: vi.fn() }));
vi.mock("@/lib/community-threats", () => ({
  MIN_REPORTERS_FOR_PUBLIC: 2,
  loadBlocklist: vi.fn(async () => [
    { ip: "9.9.9.1", reports: 4, reporters: 2, severity: "high", first_seen: null, last_seen: null, rule_ids: ["web-attack"] },
  ]),
}));

import { feedPrincipal } from "@/lib/feed-auth";
import { GET as getJson } from "@/app/api/traffic/blocklist.json/route";
import { GET as getTxt } from "@/app/api/traffic/blocklist.txt/route";

const mockPrincipal = vi.mocked(feedPrincipal);

function req(): NextRequest {
  return new Request("https://threatcrush.com/api/traffic/blocklist.json") as unknown as NextRequest;
}

describe("community blocklist feed is key-gated", () => {
  beforeEach(() => vi.clearAllMocks());

  it("401s without a valid key (json and txt)", async () => {
    mockPrincipal.mockResolvedValue(null);
    expect((await getJson(req())).status).toBe(401);
    expect((await getTxt(req())).status).toBe(401);
  });

  it("serves full IPs with a valid principal", async () => {
    mockPrincipal.mockResolvedValue({ kind: "agent", keyId: "k", orgId: "o", teamId: "t", role: "read", name: "n" });

    const json = await getJson(req());
    expect(json.status).toBe(200);
    const body = (await json.json()) as { count: number; entries: Array<{ ip: string }> };
    expect(body.count).toBe(1);
    expect(body.entries[0].ip).toBe("9.9.9.1");

    const txt = await getTxt(req());
    expect(txt.status).toBe(200);
    expect(await txt.text()).toContain("9.9.9.1");
  });
});
