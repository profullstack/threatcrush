/**
 * The site-wide allowance: a hundred requests a minute, per caller, on every
 * page route. Going over is answered 402 with the crawl gateway's offer, not
 * 429. Wired 2026-10-19 (bot hits decisions: "yes" to a gateway on every site).
 *
 * WHY. The gate charges crawlers that say who they are. A scraper wearing a
 * browser string was never counted here at all; that is the shape that walked
 * 19,000 URLs a day off coinpayportal on 2026-09-08.
 *
 * What is never metered: /api/ (webhooks, daemons, CLIs and polling clients
 * have their own limits and must never be answered with a price), a Next.js
 * link prefetch (a page already loaded asking ahead for the links it shows; a
 * front page full of links would otherwise spend a reader's allowance for
 * them), and whatever the gateway vouches for (verified search crawlers,
 * retrieval crawlers, AI chat fetchers, paid passes).
 *
 * Imports nothing Node-only: the middleware may run at the edge.
 */

import { createThrottle } from "@profullstack/throttle";
import { gateway } from "@/lib/crawl-gateway";

const isPrefetch = (request: Request) =>
  request.headers.has("next-router-prefetch") ||
  /prefetch/i.test(request.headers.get("sec-purpose") ?? request.headers.get("purpose") ?? "");

export const throttle = createThrottle({
  gateway,
  exempt: isPrefetch,
  credential: { limit: 600, ceiling: 1200 },
  rules: [{ path: "/api/", open: true }],
});

/** Resolves to a Response for a caller over the allowance, or undefined. */
export const meter = (request: Request) => throttle.handle(request);
