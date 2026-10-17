import type { NextRequest } from "next/server";

/**
 * The caller's address.
 *
 * Everything a client sends in X-Forwarded-For arrives before our proxies
 * append to it, so only the right end of the list can be trusted: each trusted
 * proxy appends the address of the peer it accepted the connection from
 * (nginx `proxy_add_x_forwarded_for`). With N trusted hops the client is the
 * Nth entry from the right. Keying on the leftmost entry let a caller pick a
 * fresh identity per request and never hit a limit. A list shorter than the
 * hop count did not come through the proxies we expect, so none of it is used.
 */
export function clientIp(req: NextRequest): string {
  // Non-literal key: a runtime setting, not one Next inlines at build time.
  const hopsKey = "TRUSTED_PROXY_HOPS";
  const configuredHops = Number(process.env[hopsKey] || 1);
  const hops = Number.isInteger(configuredHops) && configuredHops >= 1 ? configuredHops : 1;

  const chain = (req.headers.get("x-forwarded-for") ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (chain.length >= hops) return chain[chain.length - hops];
  return req.headers.get("x-real-ip")?.trim() || "unknown";
}
