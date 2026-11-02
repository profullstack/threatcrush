import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearReputationCache, lookupReputations } from "@/lib/av-reputation";

const EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const GOOD = "a".repeat(64);
const UNKNOWN = "b".repeat(64);

function fakeCircl() {
  return vi.fn(async (url: string) => {
    if (url.endsWith(EICAR)) return new Response(JSON.stringify({ KnownMalicious: "malshare.com", "hashlookup:trust": 100, FileName: "eicar.com" }));
    if (url.endsWith(GOOD)) return new Response(JSON.stringify({ "hashlookup:trust": 90, FileName: "ls" }));
    return new Response("{}", { status: 404 });
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

describe("av reputation", () => {
  beforeEach(() => clearReputationCache());

  it("returns only known hashes and caches answers, misses included", async () => {
    const f = fakeCircl();
    const out = await lookupReputations([EICAR, GOOD, UNKNOWN], f);
    expect([...out.keys()].sort()).toEqual([EICAR, GOOD].sort());
    expect(out.get(EICAR)).toMatchObject({ knownMalicious: "malshare.com", trust: 0 });
    expect(out.get(GOOD)).toMatchObject({ knownMalicious: null, trust: 90 });
    expect(f).toHaveBeenCalledTimes(3);
    await lookupReputations([EICAR, GOOD, UNKNOWN], f);
    expect(f).toHaveBeenCalledTimes(3);
  });
});

describe("POST /api/av/lookup", () => {
  it("validates the body", async () => {
    const { POST } = await import("@/app/api/av/lookup/route");
    const req = (body: unknown) =>
      POST(new Request("http://localhost/api/av/lookup", { method: "POST", body: JSON.stringify(body) }) as never);
    expect((await req({})).status).toBe(400);
    expect((await req({ hashes: Array.from({ length: 101 }, (_, i) => i.toString(16).padStart(64, "0")) })).status).toBe(413);
    const ok = await req({ hashes: ["not-a-hash"] });
    expect(ok.status).toBe(200);
    expect((await ok.json()).results).toEqual({});
  });
});
