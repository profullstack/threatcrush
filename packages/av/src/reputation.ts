import { SHA256_RE } from './sha256';
import type { HashReputation } from './types';

type FetchLike = typeof fetch;

/** Public endpoint every CrushAV client uses for hash reputation. */
export const DEFAULT_LOOKUP_ENDPOINT = 'https://threatcrush.com/api/av/lookup';

/** Largest batch the lookup API accepts. */
export const LOOKUP_BATCH = 100;

/**
 * Client side: ask the ThreatCrush API about a set of hashes. Only hashes are
 * sent, never file names or contents. Failures resolve to an empty map so a
 * scan still completes offline.
 */
export async function lookupHashes(
  hashes: string[],
  opts: { endpoint?: string; fetch?: FetchLike; timeoutMs?: number; userAgent?: string } = {},
): Promise<Map<string, HashReputation>> {
  const out = new Map<string, HashReputation>();
  const f = opts.fetch ?? globalThis.fetch;
  const unique = [...new Set(hashes.map((h) => h.toLowerCase()).filter((h) => SHA256_RE.test(h)))];
  if (!f || unique.length === 0) return out;
  for (let i = 0; i < unique.length; i += LOOKUP_BATCH) {
    const batch = unique.slice(i, i + LOOKUP_BATCH);
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 20_000) : null;
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (opts.userAgent) headers['user-agent'] = opts.userAgent;
      const res = await f(opts.endpoint ?? DEFAULT_LOOKUP_ENDPOINT, {
        method: 'POST',
        headers,
        body: JSON.stringify({ hashes: batch }),
        signal: ctrl?.signal,
      });
      if (!res.ok) continue;
      const body = (await res.json()) as { results?: Record<string, HashReputation> };
      for (const [h, rep] of Object.entries(body.results ?? {})) {
        if (SHA256_RE.test(h)) out.set(h, { ...rep, sha256: h });
      }
    } catch {
      /* offline or blocked: scan continues without reputation */
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  return out;
}

/**
 * Server side: CIRCL hashlookup (free, no key). Knows ~2 billion published
 * files (NSRL, distro packages) and flags some as KnownMalicious.
 * Returns null for an unknown hash or an error.
 */
export async function queryCircl(sha256: string, f: FetchLike = fetch): Promise<HashReputation | null> {
  if (!SHA256_RE.test(sha256)) return null;
  try {
    const res = await f(`https://hashlookup.circl.lu/lookup/sha256/${sha256}`, { headers: { accept: 'application/json' } });
    if (res.status !== 200) return null;
    const j = (await res.json()) as Record<string, unknown>;
    const trust = typeof j['hashlookup:trust'] === 'number' ? (j['hashlookup:trust'] as number) : null;
    const km = typeof j.KnownMalicious === 'string' && j.KnownMalicious ? (j.KnownMalicious as string) : null;
    return {
      sha256,
      knownMalicious: km,
      malwareName: null,
      // A KnownMalicious entry still carries a high trust from its NSRL parents; never report it as trusted.
      trust: km ? 0 : trust,
      fileName: typeof j.FileName === 'string' ? (j.FileName as string) : null,
    };
  } catch {
    return null;
  }
}

/**
 * Server side: MalwareBazaar, when the deployment has an abuse.ch Auth-Key
 * (free at auth.abuse.ch). abuse.ch retired its keyless bulk exports, so this
 * is opt-in rather than assumed.
 */
export async function queryMalwareBazaar(sha256: string, authKey: string, f: FetchLike = fetch): Promise<HashReputation | null> {
  if (!SHA256_RE.test(sha256) || !authKey) return null;
  try {
    const res = await f('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Auth-Key': authKey, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ query: 'get_info', hash: sha256 }).toString(),
    });
    if (!res.ok) return null;
    const j = (await res.json()) as { query_status?: string; data?: Array<{ signature?: string | null; file_name?: string | null }> };
    if (j.query_status !== 'ok' || !j.data?.length) return null;
    return {
      sha256,
      knownMalicious: 'MalwareBazaar',
      malwareName: j.data[0].signature ?? null,
      trust: 0,
      fileName: j.data[0].file_name ?? null,
    };
  } catch {
    return null;
  }
}

/** Combine sources: any malicious verdict wins; otherwise the best trust. */
export function mergeReputation(sha256: string, reps: Array<HashReputation | null>): HashReputation | null {
  const found = reps.filter((r): r is HashReputation => !!r);
  if (!found.length) return null;
  const bad = found.find((r) => r.knownMalicious);
  if (bad) return { ...bad, sha256, malwareName: found.find((r) => r.malwareName)?.malwareName ?? bad.malwareName };
  const best = found.reduce((a, b) => ((b.trust ?? 0) > (a.trust ?? 0) ? b : a));
  return { ...best, sha256 };
}
