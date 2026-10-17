/**
 * The crawler behind Link Watch: walk a site's own HTML pages, collect every
 * link and asset they reference, and check each one once.
 *
 * A link is BROKEN when it answers 404/410 or 5xx, or when one of the site's
 * own URLs cannot be fetched at all (DNS, refused, timeout). Answers that
 * usually mean "not for robots" rather than "gone" (401, 403, 405, 429, and
 * LinkedIn's 999) and 402 (a paywall metering crawlers) are never reported, and a third-party URL that merely times
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

// 402 is a paywall (x402 metering of crawlers), not a missing page.
const NOT_BROKEN = new Set([401, 402, 403, 405, 429, 999]);
const MAX_HTML_BYTES = 2_000_000;
const FOUND_ON_LIMIT = 5;

const LINK_TAGS = new Set(['a', 'link', 'img', 'script', 'iframe', 'source', 'video', 'audio', 'base']);

/**
 * The attributes of one tag's inner text (`a href="/x" class=y`), lowercased
 * names, one pass, no regular expressions: this runs on any page on the web.
 */
export function parseAttributes(inner: string): Map<string, string> {
  const out = new Map<string, string>();
  let i = 0;
  const n = inner.length;
  const space = (c: string) => c === ' ' || c === '\n' || c === '\t' || c === '\r' || c === '\f' || c === '/';
  while (i < n) {
    while (i < n && space(inner[i])) i++;
    const nameStart = i;
    while (i < n && !space(inner[i]) && inner[i] !== '=') i++;
    const name = inner.slice(nameStart, i).toLowerCase();
    while (i < n && space(inner[i]) && inner[i] !== '/') i++;
    let value = '';
    if (inner[i] === '=') {
      i++;
      while (i < n && space(inner[i]) && inner[i] !== '/') i++;
      const q = inner[i];
      if (q === '"' || q === "'") {
        const close = inner.indexOf(q, i + 1);
        const stop = close === -1 ? n : close;
        value = inner.slice(i + 1, stop);
        i = stop + 1;
      } else {
        const vs = i;
        while (i < n && !space(inner[i])) i++;
        value = inner.slice(vs, i);
      }
    }
    if (name && !out.has(name)) out.set(name, value);
    if (i === nameStart) i++;
  }
  return out;
}

/**
 * Every href/src in an HTML document, resolved against its URL (or its
 * <base>), fragments dropped. A linear scan over tags: comments and the
 * insides of <script>/<style> are skipped by finding where they end.
 */
export function extractLinks(html: string, pageUrl: string): string[] {
  const lower = html.toLowerCase();
  const raw: Array<{ tag: string; attrs: Map<string, string> }> = [];
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt === -1) break;
    if (html.startsWith('<!--', lt)) {
      const end = html.indexOf('-->', lt + 4);
      i = end === -1 ? html.length : end + 3;
      continue;
    }
    const gt = html.indexOf('>', lt + 1);
    if (gt === -1) break;
    let nameEnd = lt + 1;
    while (nameEnd < gt && /[a-z0-9]/i.test(html[nameEnd])) nameEnd++;
    const tag = lower.slice(lt + 1, nameEnd);
    if (LINK_TAGS.has(tag)) raw.push({ tag, attrs: parseAttributes(html.slice(nameEnd, gt)) });
    i = gt + 1;
    if (tag === 'script' || tag === 'style') {
      const close = lower.indexOf(`</${tag}`, i);
      i = close === -1 ? html.length : close;
    }
  }

  let base = pageUrl;
  const baseHref = raw.find((t) => t.tag === 'base' && t.attrs.get('href'))?.attrs.get('href');
  if (baseHref) {
    try {
      base = new URL(baseHref, pageUrl).href;
    } catch {
      // keep the page URL
    }
  }
  const out = new Set<string>();
  for (const { tag, attrs } of raw) {
    if (tag === 'base') continue;
    // <link rel=preconnect|dns-prefetch> names an origin, not a resource.
    if (tag === 'link' && /^(preconnect|dns-prefetch)$/i.test((attrs.get('rel') ?? '').trim())) continue;
    const value = (attrs.get('href') ?? attrs.get('src') ?? '').trim();
    if (!value || value.startsWith('#')) continue;
    try {
      const u = new URL(value.split('&amp;').join('&'), base);
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
  const out: string[] = [];
  const lower = xml.toLowerCase();
  let i = 0;
  for (;;) {
    const open = lower.indexOf('<loc>', i);
    if (open === -1) break;
    const close = lower.indexOf('</loc>', open + 5);
    if (close === -1) break;
    const loc = xml.slice(open + 5, close).trim();
    if (loc) out.push(loc.split('&amp;').join('&'));
    i = close + 6;
  }
  return out;
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

  // A timeout on the site's own URL is often just this crawl's load: ask once
  // more, alone and with twice the time, before calling it broken.
  for (const [url, a] of answers) {
    if (a.error === 'TIMEOUT' && isInternal(url))
      answers.set(url, await fetchOnce(url, 'GET', false, { ...o, timeoutMs: o.timeoutMs * 2 }));
  }

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
