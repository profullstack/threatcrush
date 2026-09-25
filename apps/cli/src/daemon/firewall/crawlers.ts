import { promises as dns } from 'node:dns';

/**
 * Search-engine crawlers we will not ban on our own initiative.
 *
 * A firewall ban is box-wide. Banning a Googlebot address takes every site on
 * the host out of Google Search from that address, and Googlebot trips rules
 * innocently all the time: it follows any link it finds, including spam links
 * other people plant with `?link=http://…/x.php` in them, which reads as a
 * remote file include. On dev2, 2026-09-25, 66.249.74.135 and .136 were both
 * auto-banned that way.
 *
 * The user agent is trivially forged, so it proves nothing. Forward-confirmed
 * reverse DNS does: the PTR must end in one of these domains AND that name must
 * resolve back to the same address. This is the check Google and Microsoft
 * document for verifying their crawlers.
 *
 * `googleusercontent.com` is deliberately absent: that is Google Cloud
 * customers, i.e. anyone.
 */
export const CRAWLER_DOMAINS = ['googlebot.com', 'google.com', 'search.msn.com'];

export interface Resolver {
  reverse(ip: string): Promise<string[]>;
  lookup(host: string): Promise<string[]>;
}

const systemResolver: Resolver = {
  reverse: (ip) => dns.reverse(ip),
  lookup: async (host) => (await dns.lookup(host, { all: true })).map((a) => a.address),
};

const TIMEOUT_MS = 2000;
const CACHE_MS = 6 * 3600_000;

function withTimeout<T>(p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error('dns timeout')), TIMEOUT_MS).unref()),
  ]);
}

function inCrawlerDomain(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return CRAWLER_DOMAINS.some((d) => h === d || h.endsWith(`.${d}`));
}

/**
 * Returns the verified crawler hostname for `ip`, or null. Never throws: a DNS
 * failure means "not verified", so the ban goes ahead.
 */
export function crawlerVerifier(resolver: Resolver = systemResolver) {
  const cache = new Map<string, { host: string | null; until: number }>();
  return async (ip: string): Promise<string | null> => {
    const hit = cache.get(ip);
    if (hit && hit.until > Date.now()) return hit.host;

    let host: string | null = null;
    try {
      const names = await withTimeout(resolver.reverse(ip));
      for (const name of names.filter(inCrawlerDomain)) {
        const addrs = await withTimeout(resolver.lookup(name));
        if (addrs.includes(ip)) { host = name.replace(/\.$/, ''); break; }
      }
    } catch {
      host = null;
    }
    cache.set(ip, { host, until: Date.now() + CACHE_MS });
    return host;
  };
}
