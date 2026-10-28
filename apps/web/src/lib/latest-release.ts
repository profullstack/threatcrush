import "server-only";

/**
 * The newest @profullstack/threatcrush on npm, so "behind latest" means behind
 * what is published, not only behind the newest box in the fleet (a fleet that
 * is all on an old version would otherwise show nothing outdated). Cached for
 * ten minutes; null when npm cannot be reached.
 */
const REGISTRY = "https://registry.npmjs.org/@profullstack%2Fthreatcrush/latest";
const TTL_MS = 10 * 60_000;
let cache: { at: number; version: string | null } | null = null;

export async function latestPublishedVersion(fetchImpl: typeof fetch = fetch, now = Date.now()): Promise<string | null> {
  if (cache && now - cache.at < TTL_MS) return cache.version;
  let version: string | null = null;
  try {
    const res = await fetchImpl(REGISTRY, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const v = ((await res.json()) as { version?: unknown }).version;
      version = typeof v === "string" && /^\d+\.\d+\.\d+/.test(v) ? v : null;
    }
  } catch {}
  cache = { at: now, version: version ?? cache?.version ?? null };
  return cache.version;
}

/** For tests. */
export function resetLatestReleaseCache(): void {
  cache = null;
}
