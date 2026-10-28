import { isIP } from "node:net";

/**
 * What an org allowlist (never-block) entry may be. Every daemon in the org
 * merges these into its protected set, so one entry like 0.0.0.0/0 or ::/0
 * would switch blocking off across the whole fleet. The daemon refuses the
 * same ranges (apps/cli … allowlist-sync.ts); this keeps them out of the
 * database in the first place.
 */

/** Widest range one entry may cover: a /8 for IPv4, a /16 for IPv6. */
export const MIN_PREFIX = { 4: 8, 6: 16 } as const;

/** A bare IPv4/IPv6 address, or a CIDR no wider than MIN_PREFIX. Returns why not, or null. */
export function allowlistValueError(value: unknown): string | null {
  if (typeof value !== "string" || !value.trim()) return "value must be an IP address or CIDR";
  const [network, prefix, extra] = value.trim().split("/");
  const family = isIP(network);
  if (family === 0 || extra !== undefined) return "value must be an IP address or CIDR";
  if (prefix === undefined) return null;
  if (!/^\d{1,3}$/.test(prefix)) return "value must be an IP address or CIDR";
  const bits = Number(prefix);
  const max = family === 4 ? 32 : 128;
  const min = MIN_PREFIX[family as 4 | 6];
  if (bits > max) return "value must be an IP address or CIDR";
  if (bits < min) return `a range wider than /${min} would stop blocking for most of the internet`;
  return null;
}

/** A single IPv4/IPv6 address (no CIDR): what block and unblock take. */
export function isSingleIp(value: unknown): value is string {
  return typeof value === "string" && isIP(value.trim()) !== 0;
}
