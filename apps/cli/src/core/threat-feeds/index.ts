/**
 * Known-bad IPs and domains from abuse.ch (issue #304, PRD 0019 R2).
 *
 * dns-monitor already spots the *shape* of C2 traffic (tunneling, DGA); this
 * adds the indicators themselves, so a server talking to a known botnet
 * controller or malware host is caught by name, and optionally blocked.
 *
 * Feeds, all public, no key:
 *   - ThreatFox recent IOCs (JSON): `ip:port` C2 and payload hosts.
 *   - ThreatFox and URLhaus host files: domains.
 *   - Feodo Tracker IP blocklist: botnet C2 (nearly empty since 2025, kept
 *     because it is the highest-precision list when it has entries).
 *
 * The one way this goes wrong is blocking something shared. Plenty of C2
 * sits behind Cloudflare or a public resolver's anycast address, and an
 * egress drop on such an address takes legitimate traffic with it. So
 * anything in the protected set, the operator's allowlist, or the CDN and
 * resolver ranges below is never listed, whatever the feed says.
 */

import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { isIP } from 'node:net';
import { DEFAULT_PROTECTED, isProtected } from '../../daemon/firewall/protected.js';

export interface Indicator {
  /** Malware family as the feed names it, e.g. "QakBot". */
  malware: string;
  /** botnet_cc, payload_delivery, … or the feed's own label. */
  threat: string;
  feed: string;
}

export interface FeedSet {
  fetched_at: string;
  ips: Record<string, Indicator>;
  domains: Record<string, Indicator>;
  /** Per-feed counts and failures, for status output. */
  sources: { feed: string; ok: boolean; count: number; error?: string }[];
  /** Feed entries left out because they are shared or protected. */
  skipped_shared: number;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export const FEEDS = {
  threatfoxRecent: 'https://threatfox.abuse.ch/export/json/recent/',
  threatfoxHosts: 'https://threatfox.abuse.ch/downloads/hostfile/',
  urlhausHosts: 'https://urlhaus.abuse.ch/downloads/hostfile/',
  feodoIps: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
} as const;

/**
 * Shared infrastructure that must never be matched or blocked: Cloudflare's
 * published ranges (www.cloudflare.com/ips) and the big public resolvers.
 */
export const SHARED_RANGES: string[] = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
  '1.1.1.1/32', '1.0.0.1/32', '8.8.8.8/32', '8.8.4.4/32', '9.9.9.9/32',
  '149.112.112.112/32', '208.67.222.222/32', '208.67.220.220/32',
];

/** Domains that host other people's content: never matched as a whole. */
const SHARED_DOMAINS = new Set([
  'workers.dev', 'pages.dev', 'github.io', 'githubusercontent.com', 'herokuapp.com',
  'vercel.app', 'netlify.app', 'azurewebsites.net', 'blob.core.windows.net',
  'amazonaws.com', 'cloudfront.net', 'googleusercontent.com', 'appspot.com',
  'firebaseapp.com', 'web.app', 'r2.dev', 'ngrok.io', 'ngrok-free.app', 'duckdns.org',
  'discord.com', 'discordapp.com', 'telegram.org', 'dropbox.com', 'google.com',
]);

export interface ThreatFeedSettings {
  enabled: boolean;
  block: boolean;
  refreshMs: number;
  minConfidence: number;
  /** IPs, CIDRs or domains never matched. */
  allow: string[];
}

/** ThreatFox `export/json/recent`: `{ "<id>": [ { ioc_value, ioc_type, … } ] }`. */
export function parseThreatFoxJson(text: string, minConfidence: number): { ips: Map<string, Indicator>; domains: Map<string, Indicator> } {
  const ips = new Map<string, Indicator>();
  const domains = new Map<string, Indicator>();
  const data = JSON.parse(text) as Record<string, Array<Record<string, unknown>>>;
  for (const entries of Object.values(data)) {
    for (const ioc of Array.isArray(entries) ? entries : []) {
      const confidence = typeof ioc.confidence_level === 'number' ? ioc.confidence_level : 0;
      if (confidence < minConfidence) continue;
      const value = String(ioc.ioc_value ?? '').trim();
      const ind: Indicator = {
        malware: String(ioc.malware_printable ?? ioc.malware ?? 'unknown'),
        threat: String(ioc.threat_type ?? 'unknown'),
        feed: 'threatfox',
      };
      if (ioc.ioc_type === 'ip:port') {
        if (ind.threat !== 'botnet_cc' && ind.threat !== 'payload_delivery') continue;
        const ip = stripPort(value);
        if (ip) ips.set(ip, ind);
      } else if (ioc.ioc_type === 'domain') {
        const domain = normalizeDomain(value);
        if (domain) domains.set(domain, ind);
      }
    }
  }
  return { ips, domains };
}

/** `127.0.0.1 <domain>` host files (ThreatFox, URLhaus). */
export function parseHostfile(text: string, feed: string): Map<string, Indicator> {
  const out = new Map<string, Indicator>();
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const domain = normalizeDomain(trimmed.split(/\s+/)[1] ?? '');
    if (domain) out.set(domain, { malware: 'unknown', threat: 'malware_host', feed });
  }
  return out;
}

/** One IP per line, `#` comments (Feodo). */
export function parseIpList(text: string, feed: string): Map<string, Indicator> {
  const out = new Map<string, Indicator>();
  for (const line of text.split('\n')) {
    const ip = line.trim();
    if (ip && !ip.startsWith('#') && isIP(ip)) out.set(ip, { malware: 'unknown', threat: 'botnet_cc', feed });
  }
  return out;
}

function stripPort(value: string): string | null {
  const v6 = /^\[([^\]]+)\]:\d+$/.exec(value);
  const ip = v6 ? v6[1] : value.replace(/:\d+$/, '');
  return isIP(ip) ? ip : null;
}

export function normalizeDomain(value: string): string | null {
  const d = value.trim().toLowerCase().replace(/\.$/, '');
  if (!d || d === 'localhost' || isIP(d) || !/^[a-z0-9_.-]+\.[a-z0-9-]{2,}$/.test(d)) return null;
  return d;
}

function allowedDomain(domain: string, allow: string[]): boolean {
  return allow.some((a) => domain === a || domain.endsWith(`.${a}`));
}

/**
 * Merge parsed feeds into the active set, dropping protected, shared and
 * allowlisted entries. A listed domain that *is* a shared platform suffix
 * (say the feed lists `workers.dev` itself) is dropped; a specific
 * subdomain of it stays.
 */
export function buildFeedSet(
  parts: { ips?: Map<string, Indicator>; domains?: Map<string, Indicator> }[],
  allow: string[],
  sources: FeedSet['sources'],
  now = new Date(),
): FeedSet {
  const neverIps = [...DEFAULT_PROTECTED, ...SHARED_RANGES, ...allow.filter((a) => isIP(a.split('/')[0]))];
  const allowDomains = allow.filter((a) => !isIP(a.split('/')[0])).map((a) => a.toLowerCase());
  const ips: Record<string, Indicator> = {};
  const domains: Record<string, Indicator> = {};
  let skipped = 0;
  for (const part of parts) {
    for (const [ip, ind] of part.ips ?? []) {
      if (isProtected(ip, neverIps)) { skipped++; continue; }
      ips[ip] ??= ind;
    }
    for (const [domain, ind] of part.domains ?? []) {
      if (SHARED_DOMAINS.has(domain) || allowedDomain(domain, allowDomains)) { skipped++; continue; }
      domains[domain] ??= ind;
    }
  }
  return { fetched_at: now.toISOString(), ips, domains, sources, skipped_shared: skipped };
}

/** Fetch every feed; one that fails is reported, not fatal. */
export async function fetchFeeds(settings: Pick<ThreatFeedSettings, 'minConfidence' | 'allow'>, fetchImpl: FetchLike = fetch): Promise<FeedSet> {
  const sources: FeedSet['sources'] = [];
  const parts: { ips?: Map<string, Indicator>; domains?: Map<string, Indicator> }[] = [];
  const get = async (feed: string, url: string, parse: (text: string) => { ips?: Map<string, Indicator>; domains?: Map<string, Indicator> }) => {
    try {
      const res = await fetchImpl(url, { signal: AbortSignal.timeout(60_000), headers: { 'User-Agent': 'threatcrush (+https://threatcrush.com)' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const part = parse(await res.text());
      parts.push(part);
      sources.push({ feed, ok: true, count: (part.ips?.size ?? 0) + (part.domains?.size ?? 0) });
    } catch (err) {
      sources.push({ feed, ok: false, count: 0, error: (err as Error).message });
    }
  };
  await Promise.all([
    get('threatfox', FEEDS.threatfoxRecent, (t) => parseThreatFoxJson(t, settings.minConfidence)),
    get('threatfox-hosts', FEEDS.threatfoxHosts, (t) => ({ domains: parseHostfile(t, 'threatfox') })),
    get('urlhaus-hosts', FEEDS.urlhausHosts, (t) => ({ domains: parseHostfile(t, 'urlhaus') })),
    get('feodo', FEEDS.feodoIps, (t) => ({ ips: parseIpList(t, 'feodo') })),
  ]);
  return buildFeedSet(parts, settings.allow, sources);
}

export function readFeedCache(path: string): FeedSet | null {
  try {
    const set = JSON.parse(readFileSync(path, 'utf-8')) as FeedSet;
    return set && typeof set.ips === 'object' && typeof set.domains === 'object' ? set : null;
  } catch {
    return null;
  }
}

export function writeFeedCache(path: string, set: FeedSet): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(set));
  renameSync(tmp, path);
}

// ─── The active set, shared in-process with dns-monitor ───

let active: FeedSet | null = null;

export function setActiveFeeds(set: FeedSet | null): void {
  active = set;
}

export function activeFeeds(): FeedSet | null {
  return active;
}

/** The indicator for an IP, normalizing `::ffff:a.b.c.d`. */
export function matchIp(ip: string, set: FeedSet | null = active): Indicator | null {
  if (!set) return null;
  const bare = ip.replace(/^::ffff:/i, '');
  return set.ips[bare] ?? null;
}

/** The indicator for a domain or any parent of it that is listed. */
export function matchDomain(name: string, set: FeedSet | null = active): { domain: string; indicator: Indicator } | null {
  if (!set) return null;
  const labels = (normalizeDomain(name) ?? '').split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join('.');
    const hit = set.domains[candidate];
    if (hit) return { domain: candidate, indicator: hit };
  }
  return null;
}
