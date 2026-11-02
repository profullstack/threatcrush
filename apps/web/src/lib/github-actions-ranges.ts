import { BlockList, isIP } from "node:net";

/**
 * GitHub-hosted Actions runners run on Microsoft Azure, so every CI deploy
 * that ssh-es into a server shows up as a login from Microsoft. GitHub
 * publishes the exact runner ranges at api.github.com/meta ("actions"); this
 * holds them in memory for a day, keeps the last good copy when a refresh
 * fails, and answers "is this address a GitHub Actions runner".
 *
 * A match is not proof by itself: anyone can run a workflow on a GitHub
 * runner. It only makes a login known automation together with a deploy key
 * (see origin.ts).
 */

const META_URL = "https://api.github.com/meta";
const TTL_MS = 24 * 60 * 60 * 1000;
const RETRY_MS = 10 * 60 * 1000;

interface Ranges {
  list: BlockList;
  count: number;
  at: number;
}

let ranges: Ranges | null = null;
let lastAttempt = 0;
let inflight: Promise<void> | null = null;

function build(cidrs: string[]): Ranges {
  const list = new BlockList();
  let count = 0;
  for (const cidr of cidrs) {
    const [addr, bits] = cidr.split("/");
    const family = isIP(addr);
    const prefix = Number(bits);
    if (!family || !Number.isInteger(prefix)) continue;
    list.addSubnet(addr, prefix, family === 6 ? "ipv6" : "ipv4");
    count++;
  }
  return { list, count, at: Date.now() };
}

/** Replace the ranges (tests, or a caller that already fetched meta). */
export function setGitHubActionsRanges(cidrs: string[]): void {
  ranges = build(cidrs);
  lastAttempt = Date.now();
}

async function refresh(timeoutMs: number): Promise<void> {
  lastAttempt = Date.now();
  const res = await fetch(META_URL, {
    headers: { accept: "application/vnd.github+json", "user-agent": "threatcrush-web" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`GitHub meta ${res.status}`);
  const body = (await res.json()) as { actions?: unknown };
  const cidrs = Array.isArray(body.actions) ? body.actions.filter((c): c is string => typeof c === "string") : [];
  if (cidrs.length === 0) throw new Error("GitHub meta has no actions ranges");
  ranges = build(cidrs);
}

/**
 * A checker for GitHub Actions runner addresses. Never throws: with no ranges
 * loaded (GitHub unreachable on a cold start) every address answers false, so
 * nothing is wrongly treated as known.
 */
export async function githubActionsChecker(timeoutMs = 3000): Promise<(ip: string) => boolean> {
  const stale = !ranges || Date.now() - ranges.at > TTL_MS;
  if (stale && (lastAttempt === 0 || Date.now() - lastAttempt > RETRY_MS)) {
    inflight ??= refresh(timeoutMs)
      .catch((err) => console.error("[github-actions-ranges] refresh failed:", (err as Error).message))
      .finally(() => { inflight = null; });
    await inflight;
  } else if (inflight) {
    await inflight;
  }
  const current = ranges;
  return (ip: string) => {
    const family = isIP(ip);
    if (!current || !family) return false;
    return current.list.check(ip, family === 6 ? "ipv6" : "ipv4");
  };
}
