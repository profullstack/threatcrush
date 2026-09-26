import { describe, it, expect, afterEach, vi } from "vitest";
import { NextRequest } from "next/server";
import { middleware } from "@/middleware";

// /api/auth/send-phone-code allows 5 requests per minute per client.
const LIMITED_PATH = "/api/auth/send-phone-code";
const LIMIT = 5;

// The limiter's buckets live for the whole module, so every test uses
// addresses no other test uses.
let nextIp = 0;
function uniqueIp(): string {
  nextIp++;
  return `198.51.${nextIp >> 8}.${nextIp & 255}`;
}

async function hit(headers: Record<string, string>): Promise<number> {
  const req = new NextRequest(`http://localhost${LIMITED_PATH}`, {
    method: "POST",
    headers: { "user-agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0", ...headers },
  });
  const res = await middleware(req);
  return res?.status ?? 200;
}

async function statuses(count: number, headers: () => Record<string, string>): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < count; i++) out.push(await hit(headers()));
  return out;
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("rate limiter client identity", () => {
  it("ignores spoofed leftmost X-Forwarded-For entries and limits on the proxy-appended one", async () => {
    const realClient = uniqueIp();
    const results = await statuses(LIMIT + 2, () => ({
      "x-forwarded-for": `${uniqueIp()}, ${uniqueIp()}, ${realClient}`,
    }));

    expect(results.slice(0, LIMIT)).toEqual(Array(LIMIT).fill(200));
    expect(results.slice(LIMIT)).toEqual([429, 429]);
  });

  it("gives distinct real clients separate buckets even when their spoofed prefix is identical", async () => {
    const spoofed = "1.2.3.4";
    const first = uniqueIp();
    const second = uniqueIp();

    const firstResults = await statuses(LIMIT + 1, () => ({ "x-forwarded-for": `${spoofed}, ${first}` }));
    const secondResults = await statuses(LIMIT, () => ({ "x-forwarded-for": `${spoofed}, ${second}` }));

    expect(firstResults.at(-1)).toBe(429);
    expect(secondResults).toEqual(Array(LIMIT).fill(200));
  });

  it("skips TRUSTED_PROXY_HOPS entries from the right", async () => {
    vi.stubEnv("TRUSTED_PROXY_HOPS", "2");
    const realClient = uniqueIp();
    // Client -> CDN -> nginx: the CDN appended the client, nginx appended the CDN.
    const results = await statuses(LIMIT + 1, () => ({
      "x-forwarded-for": `${uniqueIp()}, ${realClient}, ${uniqueIp()}`,
    }));

    expect(results.slice(0, LIMIT)).toEqual(Array(LIMIT).fill(200));
    expect(results[LIMIT]).toBe(429);
  });

  it("falls back to X-Real-IP, not the leftmost entry, when the chain is shorter than the hop count", async () => {
    vi.stubEnv("TRUSTED_PROXY_HOPS", "2");
    const realIp = uniqueIp();
    const results = await statuses(LIMIT + 1, () => ({
      "x-forwarded-for": uniqueIp(),
      "x-real-ip": realIp,
    }));

    expect(results[LIMIT]).toBe(429);
  });

  it("falls back to X-Real-IP when there is no X-Forwarded-For", async () => {
    const realIp = uniqueIp();
    const results = await statuses(LIMIT + 1, () => ({ "x-real-ip": realIp }));

    expect(results.slice(0, LIMIT)).toEqual(Array(LIMIT).fill(200));
    expect(results[LIMIT]).toBe(429);
  });

  it("puts requests with no forwarding headers into one shared bucket", async () => {
    const results = await statuses(LIMIT + 1, () => ({}));

    expect(results.slice(0, LIMIT)).toEqual(Array(LIMIT).fill(200));
    expect(results[LIMIT]).toBe(429);
  });
});
