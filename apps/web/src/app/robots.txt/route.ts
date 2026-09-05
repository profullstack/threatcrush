import { robotsRoute } from "@profullstack/x402-gateway/next";
import { gateway } from "@/lib/crawl-gateway";

// Generated from the same crawler lists the gateway enforces: training
// crawlers are refused everywhere but /crawl (where they can buy a pass),
// retrieval crawlers are named as welcome, everyone else gets the rules below.
export const GET = robotsRoute(gateway, {
  disallow: ["/api/"],
});
