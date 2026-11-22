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
 * have their own limits and must never be answered with a price), and whatever
 * the gateway vouches for (verified search crawlers, retrieval crawlers, AI
 * chat fetchers, paid passes).
 *
 * A Next.js link prefetch IS metered. It used to be exempt, judged by the
 * Next-Router-Prefetch / Sec-Purpose headers, but those are headers any client
 * can write: a scraper sending `Next-Router-Prefetch: 1` skipped the allowance
 * on every page (2026-11-22, the same class as a cookie-name exemption). The
 * allowance is 500 a minute per browser after headroom, far more than a page
 * of prefetched links costs a reader.
 *
 * Imports nothing Node-only: the middleware may run at the edge.
 */

import { createThrottle } from "@profullstack/throttle";
import { gateway } from "@/lib/crawl-gateway";

export const throttle = createThrottle({
  gateway,
  credential: { limit: 600, ceiling: 1200 },
  rules: [{ path: "/api/", open: true }],
});

/** Resolves to a Response for a caller over the allowance, or undefined. */
export const meter = (request: Request) => throttle.handle(request);
