import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { vtEnabled, vtIp, vtDomain } from "../virustotal";

const KEY = "VIRUSTOTAL_API_KEY";
let saved: string | undefined;
beforeEach(() => { saved = process.env[KEY]; });
afterEach(() => { if (saved === undefined) delete process.env[KEY]; else process.env[KEY] = saved; });

function fakeFetch(status: number, body: unknown): typeof fetch {
  return (async () => ({ status, json: async () => body })) as unknown as typeof fetch;
}

describe("virustotal enrichment", () => {
  it("vtEnabled reflects the env key", () => {
    delete process.env[KEY];
    expect(vtEnabled()).toBe(false);
    process.env[KEY] = "abc";
    expect(vtEnabled()).toBe(true);
  });

  it("returns null without a key", async () => {
    delete process.env[KEY];
    expect(await vtIp("8.8.8.8", fakeFetch(200, {}))).toBeNull();
  });

  it("maps an IP verdict", async () => {
    process.env[KEY] = "abc";
    const v = await vtIp("45.148.10.9", fakeFetch(200, {
      data: { attributes: { last_analysis_stats: { malicious: 5, suspicious: 1, harmless: 60 }, reputation: -12 } },
    }));
    expect(v).toMatchObject({ malicious: 5, suspicious: 1, harmless: 60, reputation: -12, listed: true, source: "virustotal" });
    expect(v?.permalink).toContain("45.148.10.9");
  });

  it("maps a clean domain verdict (not listed)", async () => {
    process.env[KEY] = "abc";
    const v = await vtDomain("example.com", fakeFetch(200, {
      data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 80 }, reputation: 0 } },
    }));
    expect(v?.listed).toBe(false);
    expect(v?.harmless).toBe(80);
  });

  it("returns null on a non-200", async () => {
    process.env[KEY] = "abc";
    expect(await vtIp("8.8.8.8", fakeFetch(429, {}))).toBeNull();
  });
});
