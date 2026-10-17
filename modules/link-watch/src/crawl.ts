/**
 * The crawler behind Link Watch: walk a site's own HTML pages, collect every
 * link and asset they reference, and check each one once.
 *
 * A link is BROKEN when it answers 404/410 or 5xx, or when one of the site's
 * own URLs cannot be fetched at all (DNS, refused, timeout). Answers that
 * usually mean "not for robots" rather than "gone" (401, 403, 405, 429, and
 * LinkedIn's 999) are never reported, and a third-party URL that merely times
 * out is not either: a flaky stranger's server is not your 404.
 *
 * Every body is either read (HTML pages, capped) or cancelled, and every fetch
 * has its own timeout and its own catch, so one slow server can never take
 * the daemon down (linkinator's unhandled stream error is why this is not
 * linkinator).
 */

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface CrawlOptions {
  fetchImpl?: FetchLike;
  /** The site's own URLs to fetch as pages; links on every HTML one are checked. */
  maxPages?: number;
  /** Unique URLs to check in all, pages included. */
  maxLinks?: number;
  checkExternal?: boolean;
  timeoutMs?: number;
  concurrency?: number;
  userAgent?: string;
  /** Path prefixes never crawled or checked on the site itself (e.g. /api/). */
  ignorePaths?: string[];
}

export interface BrokenLink {
  url: string;
  status: number | null;
  error: string | null;
  internal: boolean;
  /** Pages that link to it, a few at most. */
  foundOn: string[];
}

export interface CrawlResult {
  site: string;
  pages: number;
  checked: number;
  broken: BrokenLink[];
  truncated: boolean;
}

const NOT_BROKEN = new Set([401, 403, 405, 429, 999]);
const MAX_HTML_BYTES = 2_000_000;
const FOUND_ON_LIMIT = 5;

/** Every href/src in an HTML document, resolved against its URL, fragments dropped. */
export function extractLinks(html: string, pageUrl: string): string[] {
  const out = new Set<string>();
  let base = pageUrl;
  const baseTag = html.match(/<base\s[^>]*href\s*=\s*["']([^"']+)["']/i);
  if (baseTag) {
    try {
      base = new URL(baseTag[1], pageUrl).href;
    } catch {
      // keep the page URL
    }
  }
  // Comments and scripts hold URL-looking text that is not a link.
  const clean = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, (tag) =>
    tag.replace(/>[\s\S]*<\/script>$/i, '></script>'),
  );
  const attr = /<(a|link|img|script|iframe|source|video|audio)\b[^>]*?\s(href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  for (const m of clean.matchAll(attr)) {
    const tag = m[1].toLowerCase();
    const raw = (m[3] ?? m[4] ?? m[5] ?? '').trim();
    if (!raw || raw.startsWith('#')) continue;
    if (/^(mailto|tel|javascript|data|blob|sms|about):/i.test(raw)) continue;
    // <link rel=preconnect|dns-prefetch> names an origin, not a resource.
    if (tag === 'link' && /\brel\s*=\s*["']?(preconnect|dns-prefetch)/i.test(m[0])) continue;
    try {
      const u = new URL(raw.replace(/&amp;/g, '&'), base);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
      u.hash = '';
      out.add(u.href);
    } catch {
      // not a URL
    }
  }
  return [...out];
}

/** The <loc> entries of a sitemap (or sitemap index). */
export function sitemapLocs(xml: string): string[] {
  return [...xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1].replace(/&amp;/g, '&'));
}

/** A 'www.' prefix is the same site. */
const hostKey = (u: URL) => u.hostname.replace(/^www\./, '').toLowerCase();

export function isBrokenStatus(status: number): boolean {
  return status >= 400 && !NOT_BROKEN.has(status);
}

interface Answer {
  status: number | null;
  error: string | null;
  html: string | null;
  finalUrl: string;
}

async function fetchOnce(
  url: string,
  method: 'GET' | 'HEAD',
  wantHtml: boolean,
  o: Required<Pick<CrawlOptions, 'fetchImpl' | 'timeoutMs' | 'userAgent'>>,
): Promise<Answer> {
  try {
    const res = await o.fetchImpl(url, {
      method,
      redirect: 'follow',
      signal: AbortSignal.timeout(o.timeoutMs),
      headers: { 'user-agent': o.userAgent, accept: wantHtml ? 'text/html,*/*;q=0.8' : '*/*' },
    });
    let html: string | null = null;
    const type = res.headers.get('content-type') ?? '';
    if (method === 'GET' && wantHtml && res.ok && /text\/html|application\/xhtml/i.test(type)) {
      try {
        html = (await res.text()).slice(0, MAX_HTML_BYTES);
      } catch {
        html = null;
      }
    } else {
      await res.body?.cancel().catch(() => undefined);
    }
    return { status: res.status, error: null, html, finalUrl: res.url || url };
  } catch (err) {
    const e = err as Error & { cause?: { code?: string } };
    const code = e.cause?.code ?? (e.name === 'TimeoutError' ? 'TIMEOUT' : e.name);
    return { status: null, error: code || String(e.message), html: null, finalUrl: url };
  }
}

/** Run `fn` over `items` with at most `n` at once. */
async function pool<T>(items: T[], n: number, fn: (item: T) => Promise<void>): Promise<void> {
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(n, items.length)) }, async () => {
    while (i < items.length) await fn(items[i++]);
  });
  await Promise.all(workers);
}

export async function crawlSite(site: string, opts: CrawlOptions = {}): Promise<CrawlResult> {
  const o = {
    fetchImpl: opts.fetchImpl ?? ((u: string, i?: RequestInit) => fetch(u, i)),
    maxPages: opts.maxPages ?? 200,
    maxLinks: opts.maxLinks ?? 2000,
    checkExternal: opts.checkExternal ?? true,
    timeoutMs: opts.timeoutMs ?? 10_000,
    concurrency: opts.concurrency ?? 6,
    userAgent: opts.userAgent ?? 'ThreatCrush-LinkWatch/0.1 (+https://threatcrush.com/link-watch)',
    ignorePaths: opts.ignorePaths ?? [],
  };
  const root = new URL(site.includes('://') ? site : `https://${site}`);
  root.hash = '';
  const home = hostKey(root);
  const isInternal = (u: string) => {
    try {
      return hostKey(new URL(u)) === home;
    } catch {
      return false;
    }
  };
  const ignored = (u: string) => {
    if (!isInternal(u)) return false;
    const path = new URL(u).pathname;
    return o.ignorePaths.some((p) => path.startsWith(p));
  };

  const foundOn = new Map<string, Set<string>>();
  const note = (url: string, page: string | null) => {
    if (!foundOn.has(url)) foundOn.set(url, new Set());
    if (page && foundOn.get(url)!.size < FOUND_ON_LIMIT) foundOn.get(url)!.add(page);
  };
  const answers = new Map<string, Answer>();
  let truncated = false;

  // Seed from the root and the sitemap, if there is one.
  const queue: string[] = [root.href];
  note(root.href, null);
  try {
    const res = await o.fetchImpl(new URL('/sitemap.xml', root).href, {
      signal: AbortSignal.timeout(o.timeoutMs),
      headers: { 'user-agent': o.userAgent },
    });
    if (res.ok) {
      for (const loc of sitemapLocs((await res.text()).slice(0, MAX_HTML_BYTES)).slice(0, o.maxPages)) {
        if (isInternal(loc) && !/\.xml(\.gz)?$/i.test(loc) && !foundOn.has(loc)) {
          queue.push(loc);
          note(loc, null);
        }
      }
    } else {
      await res.body?.cancel().catch(() => undefined);
    }
  } catch {
    // no usable sitemap
  }

  // Walk the site's pages breadth-first, a batch at a time.
  const crawled = new Set<string>();
  let pages = 0;
  while (queue.length && crawled.size < o.maxPages) {
    const batch = queue.splice(0, Math.min(o.concurrency, o.maxPages - crawled.size));
    await pool(batch, o.concurrency, async (page) => {
      if (crawled.has(page) || ignored(page)) return;
      crawled.add(page);
      const a = await fetchOnce(page, 'GET', true, o);
      answers.set(page, a);
      if (!a.html) return;
      pages++;
      // A redirect off-site is not ours to walk.
      if (!isInternal(a.finalUrl)) return;
      for (const link of extractLinks(a.html, a.finalUrl)) {
        if (ignored(link)) continue;
        const known = foundOn.has(link);
        if (!known && foundOn.size >= o.maxLinks) {
          truncated = true;
          continue;
        }
        note(link, page);
        if (!known && isInternal(link) && !crawled.has(link)) queue.push(link);
      }
    });
  }
  if (queue.some((u) => !crawled.has(u))) truncated = true;

  // Check everything that was referenced but not fetched as a page.
  const rest = [...foundOn.keys()].filter(
    (u) => !answers.has(u) && !ignored(u) && (o.checkExternal || isInternal(u)),
  );
  await pool(rest, o.concurrency, async (url) => {
    let a = await fetchOnce(url, 'HEAD', false, o);
    // Plenty of servers answer HEAD wrongly; only a GET is believed.
    if (a.status === null || a.status >= 400) a = await fetchOnce(url, 'GET', false, o);
    answers.set(url, a);
  });

  const broken: BrokenLink[] = [];
  for (const [url, a] of answers) {
    const internal = isInternal(url);
    const bad =
      a.status !== null
        ? isBrokenStatus(a.status)
        : internal || a.error === 'ENOTFOUND';
    if (!bad) continue;
    broken.push({ url, status: a.status, error: a.error, internal, foundOn: [...(foundOn.get(url) ?? [])] });
  }
  broken.sort((x, y) => Number(y.internal) - Number(x.internal) || x.url.localeCompare(y.url));
  return { site: root.href, pages, checked: answers.size, broken, truncated };
}
