import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { isIP } from 'node:net';
import type { ThreatEvent } from '../../types/events.js';
import type { ThreatFeedsSection } from '../../types/config.js';
import { parseDuration } from '../firewall/backoff.js';
import {
  RESOLVER_FILES,
  RESOLVER_HOOKS,
  fetchFeeds,
  hostsBlocklist,
  matchIp,
  unboundBlocklist,
  readFeedCache,
  setActiveFeeds,
  writeFeedCache,
  type FeedSet,
  type FetchLike,
  type ThreatFeedSettings,
} from '../../core/threat-feeds/index.js';

/**
 * Keeps the abuse.ch indicators current (issue #304) and acts on them:
 *
 *   - always: flags outbound TCP connections from this box to a listed IP,
 *     naming the process, and shares the domain list with dns-monitor;
 *   - with `[threat_feeds] block = true` and remediation enforcing: drops
 *     egress (and forwarded container traffic) to listed IPs in a table of
 *     its own, `inet threatcrush_egress`, replaced atomically on every refresh.
 *
 * Blocking is opt-in. A wrong ban on an inbound attacker costs one IP; a wrong
 * egress drop costs whatever this box needed from that address.
 */

export const EGRESS_TABLE = 'threatcrush_egress';
const DEFAULT_REFRESH_MS = 3_600_000;
const POLL_MS = 15_000;
const REALERT_MS = 3_600_000;

export function threatFeedSettings(section: ThreatFeedsSection | undefined): ThreatFeedSettings {
  const refresh = parseDuration(section?.refresh);
  return {
    enabled: section?.enabled !== false,
    block: section?.block === true,
    blockDomains: section?.block_domains === true,
    // abuse.ch asks for no more than one fetch per 5 minutes; hourly is plenty.
    refreshMs: refresh ? Math.max(900, refresh) * 1000 : DEFAULT_REFRESH_MS,
    minConfidence: typeof section?.min_confidence === 'number' ? section.min_confidence : 75,
    allow: Array.isArray(section?.allow) ? section.allow.map(String) : [],
  };
}

/**
 * The whole egress table as one `nft -f` transaction: declaring the table
 * first makes the delete safe when it does not exist yet, and the new
 * definition replaces it with no window where the old sets are gone but the
 * new ones are not loaded.
 */
export function egressRuleset(ips: string[]): string {
  const v4 = ips.filter((ip) => isIP(ip) === 4);
  const v6 = ips.filter((ip) => isIP(ip) === 6);
  const set = (name: string, type: string, items: string[]) =>
    `  set ${name} { type ${type};${items.length ? ` elements = { ${items.join(', ')} }` : ''} }`;
  const chain = (name: string, hook: string) => [
    `  chain ${name} {`,
    `    type filter hook ${hook} priority -1; policy accept;`,
    `    ip daddr @c2_v4 counter drop`,
    `    ip6 daddr @c2_v6 counter drop`,
    `  }`,
  ].join('\n');
  return [
    `table inet ${EGRESS_TABLE}`,
    `delete table inet ${EGRESS_TABLE}`,
    `table inet ${EGRESS_TABLE} {`,
    set('c2_v4', 'ipv4_addr', v4),
    set('c2_v6', 'ipv6_addr', v6),
    chain('output', 'output'),
    chain('forward', 'forward'),
    `}`,
    '',
  ].join('\n');
}

export interface OutboundConn {
  state: string;
  localPort: number;
  peerIp: string;
  peerPort: number;
  process: string | null;
  pid: number | null;
}

function splitAddr(addr: string): { ip: string; port: number } | null {
  const m = /^\[?(.+?)\]?:(\d+|\*)$/.exec(addr);
  if (!m) return null;
  const ip = m[1].replace(/%.*$/, '').replace(/^::ffff:/i, '');
  return isIP(ip) ? { ip, port: m[2] === '*' ? 0 : Number(m[2]) } : null;
}

/** `ss -tnpH` lines: `State Recv-Q Send-Q Local Peer [users:(("name",pid=N,fd=M))]`. */
export function parseSs(text: string): OutboundConn[] {
  const out: OutboundConn[] = [];
  for (const line of text.split('\n')) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 5) continue;
    const local = splitAddr(cols[3]);
    const peer = splitAddr(cols[4]);
    if (!local || !peer) continue;
    const proc = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
    out.push({
      state: cols[0],
      localPort: local.port,
      peerIp: peer.ip,
      peerPort: peer.port,
      process: proc?.[1] ?? null,
      pid: proc ? Number(proc[2]) : null,
    });
  }
  return out;
}

/** Listening TCP ports from `ss -ltnH`; a connection on one of them is inbound. */
export function parseListeningPorts(text: string): Set<number> {
  const ports = new Set<number>();
  for (const line of text.split('\n')) {
    const cols = line.trim().split(/\s+/);
    const local = cols.length >= 4 ? splitAddr(cols[3]) : null;
    if (local) ports.add(local.port);
  }
  return ports;
}

export interface ThreatFeedsOptions {
  settings: ThreatFeedSettings;
  /** Remediation is enforcing (not dry_run, and a real firewall exists). */
  enforcing: boolean;
  cachePath: string;
  /** Where the resolver blocklists go (default: beside the cache). */
  resolverDir?: string;
  /** Drop-in paths whose presence means a resolver reads those files (tests override). */
  resolverHooks?: { dnsmasq: string; unbound: string };
  bus: { publish(event: ThreatEvent): void; announceModule(name: string, status: string, detail?: string): void };
  log: (line: string) => void;
  fetchImpl?: FetchLike;
  /** Runs a command, returns stdout (or null on failure); stdin optional. */
  run?: (cmd: string, args: string[], input?: string) => string | null;
  now?: () => number;
}

function defaultRun(cmd: string, args: string[], input?: string): string | null {
  const res = spawnSync(cmd, args, { encoding: 'utf-8', input, timeout: 15_000, stdio: ['pipe', 'pipe', 'pipe'] });
  return res.status === 0 ? res.stdout : null;
}

export class ThreatFeeds {
  private timers: NodeJS.Timeout[] = [];
  private set: FeedSet | null = null;
  private alerted = new Map<string, number>();
  private blocking = false;
  private readonly run: NonNullable<ThreatFeedsOptions['run']>;
  private readonly now: () => number;

  constructor(private opts: ThreatFeedsOptions) {
    this.run = opts.run ?? defaultRun;
    this.now = opts.now ?? Date.now;
  }

  get wantsBlock(): boolean {
    return this.opts.settings.block && this.opts.enforcing;
  }

  start(): void {
    const { settings } = this.opts;
    if (!settings.enabled) {
      this.opts.log('[threat-feeds] disabled by [threat_feeds] enabled = false');
      this.removeBlocking();
      return;
    }
    if (settings.block && !this.opts.enforcing) {
      this.opts.log('[threat-feeds] block = true but remediation is in dry_run (or has no firewall): detecting only');
    }
    const cached = readFeedCache(this.opts.cachePath);
    if (cached) this.apply(cached, 'cache');
    if (!this.wantsBlock) this.removeBlocking();

    const stale = !cached || this.now() - Date.parse(cached.fetched_at) > settings.refreshMs;
    const first = setTimeout(() => void this.refresh(), stale ? 10_000 : settings.refreshMs);
    first.unref?.();
    const every = setInterval(() => void this.refresh(), settings.refreshMs);
    every.unref?.();
    const poll = setInterval(() => this.pollConnections(), POLL_MS);
    poll.unref?.();
    this.timers.push(first, every, poll);
  }

  stop(): void {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
  }

  async refresh(): Promise<void> {
    try {
      const set = await fetchFeeds(this.opts.settings, this.opts.fetchImpl);
      const failed = set.sources.filter((s) => !s.ok);
      // Every feed failing means no data, not an all-clear: keep the old set.
      if (failed.length === set.sources.length) {
        this.opts.log(`[threat-feeds] refresh failed, keeping previous list: ${failed.map((s) => `${s.feed}: ${s.error}`).join('; ')}`);
        return;
      }
      for (const f of failed) this.opts.log(`[threat-feeds] ${f.feed} unavailable: ${f.error}`);
      try { writeFeedCache(this.opts.cachePath, set); } catch (err) {
        this.opts.log(`[threat-feeds] could not write cache: ${(err as Error).message}`);
      }
      this.apply(set, 'refresh');
    } catch (err) {
      this.opts.log(`[threat-feeds] refresh failed: ${(err as Error).message}`);
    }
  }

  private apply(set: FeedSet, from: 'cache' | 'refresh'): void {
    this.set = set;
    setActiveFeeds(set);
    const ips = Object.keys(set.ips);
    const domains = Object.keys(set.domains).length;
    let mode = 'detecting';
    if (this.wantsBlock) {
      const ok = this.run('nft', ['-f', '-'], egressRuleset(ips)) !== null;
      this.blocking = ok;
      mode = ok ? 'blocking egress' : 'detecting (nft load failed)';
    }
    const detail = `${ips.length} IPs, ${domains} domains, ${mode}${this.writeResolverFiles(set)}`;
    this.opts.log(`[threat-feeds] ${from === 'cache' ? 'loaded cached' : 'refreshed'} list: ${detail} (${set.skipped_shared} shared/protected entries skipped)`);
    this.opts.bus.announceModule('threat-feeds', 'running', detail);
  }

  /** Whether listed domains are refused at the resolver: opted in and enforcing. */
  get wantsDomainBlock(): boolean {
    return this.opts.settings.blockDomains && this.opts.enforcing;
  }

  /**
   * Rewrite the resolver blocklists in the state dir and reload any resolver
   * whose hook is installed — only when the content changed, so an hourly
   * refresh with nothing new costs no reload. With domain blocking off the
   * files are emptied, so an installed hook blocks nothing and the config
   * stays the one switch. Returns a status suffix for the log line.
   */
  writeResolverFiles(set: FeedSet): string {
    const domains = this.wantsDomainBlock ? Object.keys(set.domains).sort() : [];
    const dir = this.opts.resolverDir ?? dirname(this.opts.cachePath);
    const hooks = this.opts.resolverHooks ?? RESOLVER_HOOKS;
    const write = (name: string, content: string): boolean => {
      const path = join(dir, name);
      try {
        if (existsSync(path) && readFileSync(path, 'utf-8') === content) return false;
        writeFileSync(path, content);
        return true;
      } catch (err) {
        this.opts.log(`[threat-feeds] could not write ${path}: ${(err as Error).message}`);
        return false;
      }
    };
    const hostsChanged = write(RESOLVER_FILES.hosts, hostsBlocklist(domains));
    const unboundChanged = write(RESOLVER_FILES.unbound, unboundBlocklist(domains));

    const via: string[] = [];
    if (existsSync(hooks.dnsmasq)) {
      via.push('dnsmasq');
      // SIGHUP makes dnsmasq re-read its addn-hosts files without a restart.
      if (hostsChanged) this.run('systemctl', ['kill', '-s', 'HUP', 'dnsmasq.service']);
    }
    if (existsSync(hooks.unbound)) {
      via.push('unbound');
      if (unboundChanged && this.run('unbound-control', ['reload']) === null) {
        this.run('systemctl', ['reload', 'unbound.service']);
      }
    }
    if (!this.opts.settings.blockDomains) return '';
    if (!this.opts.enforcing) return '; domain blocking set but remediation is dry_run';
    return via.length
      ? `; ${domains.length} domains refused via ${via.join(' + ')}`
      : '; domain blocking set but no resolver hook (run `threatcrush feeds resolver install`)';
  }

  private removeBlocking(): void {
    if (this.run('nft', ['list', 'table', 'inet', EGRESS_TABLE]) !== null) {
      this.run('nft', ['delete', 'table', 'inet', EGRESS_TABLE]);
      this.opts.log(`[threat-feeds] removed egress table ${EGRESS_TABLE} (blocking is off)`);
    }
    this.blocking = false;
  }

  /** Outbound connections to listed IPs, one alert per IP and process per hour. */
  pollConnections(): void {
    if (!this.set || Object.keys(this.set.ips).length === 0) return;
    const conns = this.run('ss', ['-tnpH']);
    if (conns === null) return;
    const listening = parseListeningPorts(this.run('ss', ['-ltnH']) ?? '');
    const now = this.now();
    for (const c of parseSs(conns)) {
      if (listening.has(c.localPort)) continue; // inbound to a service of ours
      const ind = matchIp(c.peerIp, this.set);
      if (!ind) continue;
      const key = `${c.peerIp}|${c.process ?? '?'}`;
      if (now - (this.alerted.get(key) ?? 0) < REALERT_MS) continue;
      this.alerted.set(key, now);
      const who = c.process ? `${c.process} (pid ${c.pid})` : 'an unknown process';
      const blocked = this.blocking ? ' — blocked' : '';
      this.opts.bus.publish({
        timestamp: new Date(now),
        module: 'threat-feeds',
        category: 'network',
        severity: 'critical',
        message: `Outbound connection to known ${ind.malware} ${ind.threat === 'botnet_cc' ? 'C2' : 'malware host'} ${c.peerIp}:${c.peerPort} by ${who}${blocked}`,
        // No source_ip on purpose: the remote end is not an attacker to ban
        // inbound, so remediation has nothing to act on and the egress table
        // stays the only enforcement.
        details: {
          rule_id: 'threat-feed-outbound',
          destination_ip: c.peerIp,
          destination_port: c.peerPort,
          state: c.state,
          process: c.process,
          pid: c.pid,
          malware: ind.malware,
          threat: ind.threat,
          feed: ind.feed,
          blocked: this.blocking,
        },
      });
    }
    // Forget old alerts so the map does not grow for the life of the daemon.
    for (const [key, at] of this.alerted) if (now - at > REALERT_MS) this.alerted.delete(key);
  }
}
