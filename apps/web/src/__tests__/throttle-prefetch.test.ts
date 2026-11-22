// The site-wide allowance must not trust headers a client writes about itself.
import { describe, it, expect } from "vitest";
import { meter } from "@/lib/throttle";

const CHROME =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

const page = (ip: string, extra: Record<string, string> = {}) =>
  new Request("https://example.test/about", {
    headers: { "user-agent": CHROME, "x-real-ip": ip, ...extra },
  });

/** The first refusal within n requests, or null. */
async function refusedWithin(ip: string, extra: Record<string, string>, n: number) {
  for (let i = 0; i < n; i++) {
    const answer = await meter(page(ip, extra));
    if (answer) return answer;
  }
  return null;
}

describe("site-wide allowance", () => {
  it("meters a request that claims to be a Next.js prefetch", async () => {
    const refused = await refusedWithin("198.51.100.21", { "next-router-prefetch": "1" }, 600);
    expect(refused?.status).toBeGreaterThanOrEqual(402);
  });

  it("meters a Sec-Purpose: prefetch request too", async () => {
    const refused = await refusedWithin("198.51.100.22", { "sec-purpose": "prefetch" }, 600);
    expect(refused?.status).toBeGreaterThanOrEqual(402);
  });

  it("lets an ordinary reader through", async () => {
    for (let i = 0; i < 50; i++) expect(await meter(page("198.51.100.23"))).toBeFalsy();
  });
});
