import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { ModuleContext, ThreatCrushModule, ThreatEvent } from '@threatcrush/sdk';

import { type BrokenLink, type CrawlResult, crawlSite, type FetchLike } from './crawl.js';

export { crawlSite, extractLinks, isBrokenStatus, sitemapLocs } from './crawl.js';

/**
 * Link Watch: crawls the sites you list and reports every broken link and
 * asset on them (404s, 5xx, dead hosts) as threat events, once per break.
 * A paid module: each run first asks threatcrush.com whether this daemon's
 * org may run it (GET /api/v1/entitlements/link-watch), using `api_key` from
 * the module config, or the session `threatcrush login` saved.
 */

export const MODULE = 'link-watch';
export const BUY_URL = 'https://threatcrush.com/link-watch';
const STATE_KEY = 'broken';

export interface Entitlement {
  active: boolean;
  until: string | null;
  reason?: string;
}

/** The key to ask with: the module's own `api_key`, else the CLI session. */
export function credentialFrom(config: Record<string, unknown>, home = homedir()): string | null {
  if (typeof config.api_key === 'string' && config.api_key.trim()) return config.api_key.trim();
  try {
    const cli = JSON.parse(readFileSync(join(home, '.threatcrush', 'config.json'), 'utf-8')) as { token?: string };
    return cli.token || null;
  } catch {
    return null;
  }
}

export async function checkEntitlement(
  apiUrl: string,
  key: string | null,
  fetchImpl: FetchLike = (u, i) => fetch(u, i),
): Promise<Entitlement> {
  if (!key) return { active: false, until: null, reason: 'no api_key and no `threatcrush login` session' };
  try {
    const res = await fetchImpl(`${apiUrl.replace(/\/$/, '')}/api/v1/entitlements/${MODULE}`, {
      headers: { authorization: `Bearer ${key}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return { active: false, until: null, reason: `entitlement check answered ${res.status}` };
    const body = (await res.json()) as { active?: boolean; until?: string | null };
    return { active: body.active === true, until: body.until ?? null };
  } catch (err) {
    return { active: false, until: null, reason: `entitlement check failed: ${String((err as Error).message ?? err)}` };
  }
}

export const brokenKey = (b: BrokenLink) => `${b.url}`;

export function toThreatEvent(site: string, b: BrokenLink, now = new Date()): ThreatEvent {
  const what = b.status !== null ? `HTTP ${b.status}` : (b.error ?? 'unreachable');
  const where = b.foundOn.length ? ` (linked from ${b.foundOn[0]}${b.foundOn.length > 1 ? ` +${b.foundOn.length - 1}` : ''})` : '';
  return {
    timestamp: now,
    module: MODULE,
    category: 'web',
    severity: !b.internal ? 'low' : b.status !== null && b.status < 500 ? 'medium' : 'high',
    message: `Broken ${b.internal ? '' : 'external '}link on ${new URL(site).host}: ${b.url} → ${what}${where}`,
    details: {
      site,
      url: b.url,
      status: b.status,
      error: b.error,
      internal: b.internal,
      found_on: b.foundOn,
    },
  };
}

/** Which breaks are new since the last run (only those are emitted), and the set to remember. */
export function diffBroken(previous: string[], result: CrawlResult): { fresh: BrokenLink[]; keep: string[] } {
  const seen = new Set(previous);
  const fresh = result.broken.filter((b) => !seen.has(brokenKey(b)));
  return { fresh, keep: result.broken.map(brokenKey) };
}

const str = (v: unknown, d: string) => (typeof v === 'string' && v.trim() ? v.trim() : d);
const num = (v: unknown, d: number) => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : []);

export default class LinkWatchModule implements ThreatCrushModule {
  name = MODULE;
  version = '0.1.0';
  description = 'Crawls your sites and reports broken links and assets (404s, 5xx, dead hosts)';

  private context!: ModuleContext;
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private warnedUnpaid = false;

  async init(context: ModuleContext): Promise<void> {
    this.context = context;
  }

  async start(): Promise<void> {
    const hours = Math.max(1, num(this.context.config.interval_hours, 24));
    void this.run();
    this.timer = setInterval(() => void this.run(), hours * 3600_000);
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** One pass over every configured site. Public so `threatcrush modules run` and tests can call it. */
  async run(): Promise<void> {
    if (this.running) return;
    this.running = true;
    const c = this.context.config;
    try {
      const sites = strs(c.sites);
      if (!sites.length) {
        this.context.logger.warn('[%s] no sites configured; set sites = ["https://example.com"]', this.name);
        return;
      }
      const ent = await checkEntitlement(str(c.api_url, 'https://threatcrush.com'), credentialFrom(c));
      if (!ent.active) {
        this.context.logger.warn('[%s] not entitled (%s); see %s', this.name, ent.reason ?? 'no active subscription', BUY_URL);
        if (!this.warnedUnpaid) {
          this.warnedUnpaid = true;
          this.context.alert({
            title: 'Link Watch needs a subscription',
            body: `Link Watch is a paid module and this daemon's org has no active subscription (${ent.reason ?? 'none found'}). ${BUY_URL}`,
            severity: 'info',
          });
        }
        return;
      }
      this.warnedUnpaid = false;
      for (const site of sites) {
        const result = await crawlSite(site, {
          maxPages: num(c.max_pages, 200),
          maxLinks: num(c.max_links, 2000),
          checkExternal: c.check_external !== false,
          checkExternalMedia: c.check_external_media === true,
          timeoutMs: num(c.timeout_ms, 10_000),
          concurrency: num(c.concurrency, 6),
          ignorePaths: strs(c.ignore_paths),
        });
        const stateKey = `${STATE_KEY}:${result.site}`;
        const previous = strs(this.context.getState(stateKey));
        const { fresh, keep } = diffBroken(previous, result);
        for (const b of fresh) this.context.emit(toThreatEvent(result.site, b));
        this.context.setState(stateKey, keep);
        this.context.logger.info(
          '[%s] %s: %d pages, %d links checked, %d broken (%d new)%s',
          this.name,
          result.site,
          result.pages,
          result.checked,
          result.broken.length,
          fresh.length,
          result.truncated ? ', limits reached' : '',
        );
      }
    } catch (err) {
      this.context.logger.error('[%s] run failed: %s', this.name, String(err));
    } finally {
      this.running = false;
    }
  }
}
