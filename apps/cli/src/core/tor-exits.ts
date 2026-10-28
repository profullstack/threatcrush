import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { isIP } from 'node:net';

/**
 * Tor exit relays, from the Tor Project's own bulk exit list.
 *
 * Nobody we operate for logs in to a server over SSH through Tor. On
 * 2026-10-26/27 the dev2 intruder did exactly that, with a stolen key, from
 * 185.129.61.4 and 185.129.61.129, and nothing noticed: a successful login is
 * never grounds for a ban, and the address was then remembered as an
 * "operator" and protected. So an SSH connection from a Tor exit is its own
 * signal, checked against this list (see daemon/workers/ssh-intrusion.ts).
 */

export const TOR_BULK_EXIT_LIST_URL = 'https://check.torproject.org/torbulkexitlist';

/** One address per line; `#` comments and anything that is not an IP are skipped. */
export function parseTorExitList(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const ip = line.split(/\s+/)[0];
    if (isIP(ip)) out.add(normalizeIp(ip));
  }
  return out;
}

/** `::ffff:1.2.3.4` is 1.2.3.4; IPv6 lower-cased so lookups match. */
export function normalizeIp(ip: string): string {
  const bare = ip.trim().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(bare);
  return mapped ? mapped[1] : bare.toLowerCase();
}

export type FetchLike = (url: string, init?: { signal?: AbortSignal; headers?: Record<string, string> }) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

export interface TorExitListOptions {
  /** Where the last good copy is kept, so a restart without network still knows the exits. */
  cachePath: string;
  url?: string;
  refreshMs?: number;
  fetchImpl?: FetchLike;
  log?: (line: string) => void;
  now?: () => number;
}

/**
 * The exit list, refreshed hourly, with the last good copy cached on disk.
 * A failed or implausibly small download never replaces a good list.
 */
export class TorExitList {
  private exits = new Set<string>();
  private updatedAt = 0;
  private timer: NodeJS.Timeout | null = null;
  private readonly url: string;
  private readonly refreshMs: number;
  private readonly fetchImpl: FetchLike;
  private readonly log: (line: string) => void;
  private readonly now: () => number;

  /** Fewer than this many exits is a broken download, not the Tor network (it has ~1,000+). */
  static readonly MIN_PLAUSIBLE = 100;

  constructor(private opts: TorExitListOptions) {
    this.url = opts.url ?? TOR_BULK_EXIT_LIST_URL;
    this.refreshMs = Math.max(15 * 60_000, opts.refreshMs ?? 3_600_000);
    this.fetchImpl = opts.fetchImpl ?? (fetch as unknown as FetchLike);
    this.log = opts.log ?? (() => {});
    this.now = opts.now ?? Date.now;
  }

  /** Load the cache, then refresh now and every `refreshMs`. */
  start(): void {
    this.loadCache();
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), this.refreshMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  has(ip: string | undefined | null): boolean {
    if (!ip) return false;
    return this.exits.has(normalizeIp(ip));
  }

  get size(): number { return this.exits.size; }

  /** When the list in memory was downloaded (ms), 0 if never. */
  get updated(): number { return this.updatedAt; }

  /** Replace the list directly (tests, and the CLI reading the cache). */
  load(ips: Iterable<string>, at = this.now()): void {
    this.exits = new Set([...ips].map(normalizeIp));
    this.updatedAt = at;
  }

  loadCache(): boolean {
    try {
      if (!existsSync(this.opts.cachePath)) return false;
      const parsed = parseTorExitList(readFileSync(this.opts.cachePath, 'utf-8'));
      if (parsed.size === 0) return false;
      this.load(parsed, statSync(this.opts.cachePath).mtimeMs);
      this.log(`[tor] loaded ${parsed.size} Tor exit addresses from cache (${new Date(this.updatedAt).toISOString()})`);
      return true;
    } catch (err) {
      this.log(`[tor] could not read the exit list cache: ${(err as Error).message}`);
      return false;
    }
  }

  async refresh(): Promise<boolean> {
    let text: string;
    try {
      const res = await this.fetchImpl(this.url, {
        signal: AbortSignal.timeout(30_000),
        headers: { 'User-Agent': 'threatcrush-daemon (tor exit list)' },
      });
      if (!res.ok) {
        this.log(`[tor] exit list download failed: HTTP ${res.status}; keeping ${this.exits.size} cached`);
        return false;
      }
      text = await res.text();
    } catch (err) {
      this.log(`[tor] exit list download failed: ${(err as Error).message}; keeping ${this.exits.size} cached`);
      return false;
    }
    const parsed = parseTorExitList(text);
    if (parsed.size < TorExitList.MIN_PLAUSIBLE) {
      this.log(`[tor] exit list download had only ${parsed.size} addresses; keeping ${this.exits.size} cached`);
      return false;
    }
    const before = this.exits.size;
    this.load(parsed);
    try {
      mkdirSync(dirname(this.opts.cachePath), { recursive: true });
      writeFileSync(`${this.opts.cachePath}.tmp`, [...parsed].join('\n') + '\n');
      renameSync(`${this.opts.cachePath}.tmp`, this.opts.cachePath);
    } catch (err) {
      this.log(`[tor] could not save the exit list cache: ${(err as Error).message}`);
    }
    if (before !== parsed.size || before === 0) this.log(`[tor] loaded ${parsed.size} Tor exit addresses from ${this.url}`);
    return true;
  }
}
