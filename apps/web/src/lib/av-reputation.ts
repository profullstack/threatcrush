import { mergeReputation, queryCircl, queryMalwareBazaar, type HashReputation } from "@threatcrush/av";

/**
 * Server-side hash reputation with an in-memory cache, shared by
 * /api/av/lookup and the MCP `av_hash_lookup` tool.
 */

const HIT_TTL_MS = 24 * 60 * 60 * 1000;
const MISS_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_ENTRIES = 50_000;
const CONCURRENCY = 8;

const cache = new Map<string, { rep: HashReputation | null; until: number }>();

function remember(h: string, rep: HashReputation | null) {
  if (cache.size >= MAX_ENTRIES) {
    // Map iterates in insertion order: drop the oldest tenth.
    let n = Math.ceil(MAX_ENTRIES / 10);
    for (const k of cache.keys()) {
      cache.delete(k);
      if (--n <= 0) break;
    }
  }
  cache.set(h, { rep, until: Date.now() + (rep ? HIT_TTL_MS : MISS_TTL_MS) });
}

function authKey(): string {
  const name = "ABUSECH_AUTH_KEY";
  return process.env[name] ?? "";
}

export async function lookupReputations(hashes: string[], f: typeof fetch = fetch): Promise<Map<string, HashReputation>> {
  const out = new Map<string, HashReputation>();
  const todo: string[] = [];
  const now = Date.now();
  for (const h of hashes) {
    const c = cache.get(h);
    if (c && c.until > now) {
      if (c.rep) out.set(h, c.rep);
    } else todo.push(h);
  }
  const key = authKey();
  let i = 0;
  const worker = async () => {
    while (i < todo.length) {
      const h = todo[i++];
      const [circl, mb] = await Promise.all([queryCircl(h, f), key ? queryMalwareBazaar(h, key, f) : Promise.resolve(null)]);
      const rep = mergeReputation(h, [circl, mb]);
      remember(h, rep);
      if (rep) out.set(h, rep);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, todo.length) }, worker));
  return out;
}

/** Test hook. */
export function clearReputationCache() {
  cache.clear();
}
