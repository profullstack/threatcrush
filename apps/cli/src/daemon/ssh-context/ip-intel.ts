import { BlockList, isIP } from 'node:net';
import { networkInterfaces } from 'node:os';
import { promises as dns } from 'node:dns';
import { readFileSync, writeFileSync } from 'node:fs';
import type { SourceContext, SourceKind } from '@threatcrush/event-detail';

/**
 * What a login's source address is: loopback, one of this host's own
 * addresses, Tailscale (100.64.0.0/10, fd7a:115c:a1e0::/48), a private
 * range, a GitHub Actions runner (api.github.com/meta "actions", cached a
 * day), or the public internet; and for public addresses its reverse DNS and
 * Team Cymru ASN / owner / country (plain DNS TXT lookups, no API key).
 *
 * Every lookup is bounded and cached; a failure only means fewer facts.
 */

function list(entries: Array<[string, number, 'ipv4' | 'ipv6']>): BlockList {
  const b = new BlockList();
  for (const [a, p, f] of entries) b.addSubnet(a, p, f);
  return b;
}

const LOOPBACK = list([['127.0.0.0', 8, 'ipv4'], ['::1', 128, 'ipv6']]);
const TAILSCALE = list([['100.64.0.0', 10, 'ipv4'], ['fd7a:115c:a1e0::', 48, 'ipv6']]);
const PRIVATE = list([
  ['10.0.0.0', 8, 'ipv4'], ['172.16.0.0', 12, 'ipv4'], ['192.168.0.0', 16, 'ipv4'], ['169.254.0.0', 16, 'ipv4'],
  ['fc00::', 7, 'ipv6'], ['fe80::', 10, 'ipv6'],
]);

function family(ip: string): 'ipv4' | 'ipv6' | null {
  const f = isIP(ip);
  return f === 4 ? 'ipv4' : f === 6 ? 'ipv6' : null;
}

/** A v4-mapped v6 address (::ffff:1.2.3.4) as plain v4. */
export function normalizeIp(ip: string): string {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return m ? m[1] : ip;
}

export function ownAddresses(): Set<string> {
  const out = new Set<string>();
  try {
    for (const list of Object.values(networkInterfaces())) for (const a of list ?? []) out.add(a.address.split('%')[0]);
  } catch { /* none */ }
  return out;
}

export interface Classifier {
  own: () => ReadonlySet<string>;
  isGitHubActions: (ip: string) => boolean;
}

/** Pure given its inputs. */
export function classifyAddress(raw: string, c: Classifier): SourceKind {
  const ip = normalizeIp(raw);
  const f = family(ip);
  if (!f) return 'public';
  if (LOOPBACK.check(ip, f)) return 'loopback';
  if (c.own().has(ip)) return 'self';
  if (TAILSCALE.check(ip, f)) return 'tailscale';
  if (PRIVATE.check(ip, f)) return 'private';
  if (c.isGitHubActions(ip)) return 'github-actions';
  return 'public';
}

// ─── GitHub Actions ranges ───────────────────────────────────────────────────

const META_URL = 'https://api.github.com/meta';
const DAY_MS = 24 * 60 * 60 * 1000;
const RETRY_MS = 30 * 60 * 1000;

export interface RangesDeps {
  fetchJson: (url: string) => Promise<unknown>;
  load: () => { at: number; cidrs: string[] } | null;
  save: (v: { at: number; cidrs: string[] }) => void;
  now: () => number;
}

export function rangesDeps(cacheFile: string): RangesDeps {
  return {
    fetchJson: async (url) => {
      const res = await fetch(url, {
        headers: { accept: 'application/vnd.github+json', 'user-agent': 'threatcrush-agent' },
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`GitHub meta ${res.status}`);
      return res.json();
    },
    load: () => {
      try {
        const v = JSON.parse(readFileSync(cacheFile, 'utf-8')) as { at?: unknown; cidrs?: unknown };
        return typeof v.at === 'number' && Array.isArray(v.cidrs) ? { at: v.at, cidrs: v.cidrs.map(String) } : null;
      } catch { return null; }
    },
    save: (v) => { try { writeFileSync(cacheFile, JSON.stringify(v), { mode: 0o644 }); } catch { /* cache optional */ } },
    now: Date.now,
  };
}

/** GitHub's published Actions runner CIDRs, refreshed daily, last good copy kept (on disk too). */
export class GitHubActionsRanges {
  private list: BlockList | null = null;
  private count = 0;
  private at = 0;
  private lastTry = 0;
  private inflight: Promise<void> | null = null;

  constructor(private readonly deps: RangesDeps, private readonly enabled = true) {
    const saved = enabled ? deps.load() : null;
    if (saved?.cidrs.length) this.set(saved.cidrs, saved.at);
  }

  private set(cidrs: string[], at: number): void {
    const b = new BlockList();
    let n = 0;
    for (const c of cidrs) {
      const [addr, bits] = c.split('/');
      const f = family(addr);
      const p = Number(bits);
      if (!f || !Number.isInteger(p)) continue;
      try { b.addSubnet(addr, p, f); n++; } catch { /* bad entry */ }
    }
    if (n) { this.list = b; this.count = n; this.at = at; }
  }

  size(): number { return this.count; }

  /** Refresh when stale; never throws, never blocks a lookup for long. */
  async refresh(): Promise<void> {
    if (!this.enabled) return;
    const now = this.deps.now();
    if (this.list && now - this.at < DAY_MS) return;
    if (now - this.lastTry < RETRY_MS) return;
    this.inflight ??= (async () => {
      this.lastTry = now;
      try {
        const body = (await this.deps.fetchJson(META_URL)) as { actions?: unknown };
        const cidrs = Array.isArray(body?.actions) ? body.actions.filter((c): c is string => typeof c === 'string') : [];
        if (cidrs.length) {
          this.set(cidrs, now);
          this.deps.save({ at: now, cidrs });
        }
      } catch { /* keep the last good copy */ }
    })().finally(() => { this.inflight = null; });
    return this.inflight;
  }

  has(raw: string): boolean {
    const ip = normalizeIp(raw);
    const f = family(ip);
    return !!(this.list && f && this.list.check(ip, f));
  }
}

// ─── Reverse DNS and ASN ─────────────────────────────────────────────────────

export interface NetLookupDeps {
  reverse: (ip: string) => Promise<string[]>;
  txt: (name: string) => Promise<string[][]>;
}

export const realNetLookup: NetLookupDeps = {
  reverse: (ip) => dns.reverse(ip),
  txt: (name) => dns.resolveTxt(name),
};

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([p.catch(() => null), new Promise<null>((r) => setTimeout(() => r(null), ms).unref?.())]);
}

/** The Team Cymru query name for an address: reversed octets (v4) or nibbles (v6). */
export function cymruOriginName(raw: string): string | null {
  const ip = normalizeIp(raw);
  const f = isIP(ip);
  if (f === 4) return `${ip.split('.').reverse().join('.')}.origin.asn.cymru.com`;
  if (f !== 6) return null;
  const parts = ip.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail].map((g) => g.padStart(4, '0'));
  return `${groups.join('').split('').reverse().join('.')}.origin6.asn.cymru.com`;
}

/** "8075 | 192.0.2.0/24 | US | arin | 2017-10-18" -> asn + country. */
export function parseCymruOrigin(txt: string): { asn: number; country: string | null } | null {
  const f = txt.split('|').map((s) => s.trim());
  const asn = Number((f[0] ?? '').split(/\s+/)[0]);
  if (!Number.isInteger(asn) || asn <= 0) return null;
  return { asn, country: f[2] && /^[A-Z]{2}$/.test(f[2]) ? f[2] : null };
}

/** "8075 | US | arin | 2000-06-12 | MICROSOFT-CORP-MSN-AS-BLOCK, US" -> owner. */
export function parseCymruAsName(txt: string): string | null {
  const f = txt.split('|').map((s) => s.trim());
  const name = f[4]?.replace(/,\s*[A-Z]{2}$/, '').trim();
  return name ? name.slice(0, 120) : null;
}

export class NetLookup {
  private cache = new Map<string, { at: number; v: Pick<SourceContext, 'rdns' | 'asn' | 'as_org' | 'country'> }>();

  constructor(private readonly deps: NetLookupDeps = realNetLookup, private readonly timeoutMs = 2500, private readonly now = Date.now) {}

  async lookup(ip: string): Promise<Pick<SourceContext, 'rdns' | 'asn' | 'as_org' | 'country'>> {
    const hit = this.cache.get(ip);
    if (hit && this.now() - hit.at < 6 * 60 * 60 * 1000) return hit.v;
    const originName = cymruOriginName(ip);
    const [names, origin] = await Promise.all([
      withTimeout(this.deps.reverse(normalizeIp(ip)), this.timeoutMs),
      originName ? withTimeout(this.deps.txt(originName), this.timeoutMs) : Promise.resolve(null),
    ]);
    const o = origin?.[0] ? parseCymruOrigin(origin[0].join('')) : null;
    let asOrg: string | null = null;
    if (o) {
      const named = await withTimeout(this.deps.txt(`AS${o.asn}.asn.cymru.com`), this.timeoutMs);
      asOrg = named?.[0] ? parseCymruAsName(named[0].join('')) : null;
    }
    const v = { rdns: names?.[0]?.slice(0, 253) ?? null, asn: o?.asn ?? null, as_org: asOrg, country: o?.country ?? null };
    if (this.cache.size > 2000) this.cache.clear();
    this.cache.set(ip, { at: this.now(), v });
    return v;
  }
}
