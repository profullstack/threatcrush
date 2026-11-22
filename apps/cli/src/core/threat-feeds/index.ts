/**
 * Known-bad IPs and domains from abuse.ch (issue #304, PRD 0019 R2).
 *
 * dns-monitor already spots the *shape* of C2 traffic (tunneling, DGA); this
 * adds the indicators themselves, so a server talking to a known botnet
 * controller or malware host is caught by name, and optionally blocked.
 *
 * Feeds:
 *   - ThreatFox recent IOCs (API, `get_iocs`): `ip:port` C2 and payload hosts,
 *     and C2 domains.
 *   - ThreatFox host file: domains.
 *   - URLhaus online malware URLs (CSV): the host of each URL, domain or IP.
 *   - Feodo Tracker IP blocklist: botnet C2 (nearly empty since 2025, kept
 *     because it is the highest-precision list when it has entries).
 *
 * abuse.ch retired its keyless exports in 2026 (issue #430: the old URLs
 * answer 410 Gone). Everything but Feodo now needs a free Auth-Key from
 * auth.abuse.ch, set as `[threat_feeds] auth_key_file`, `auth_key` or the
 * ABUSECH_AUTH_KEY environment variable. Without one those feeds are reported
 * as failed with the reason, never fetched and never shown as an empty list.
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
  /** POST `{ query: 'get_iocs', days }` with an `Auth-Key` header. */
  threatfoxApi: 'https://threatfox-api.abuse.ch/api/v1/',
  /** Keyed file exports: the Auth-Key is a path segment. */
  threatfoxHosts: (key: string) => `https://threatfox-api.abuse.ch/v2/files/exports/${encodeURIComponent(key)}/hostfile.txt`,
  urlhausOnline: (key: string) => `https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(key)}/online.csv`,
  feodoIps: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
} as const;

/** Days of ThreatFox IOCs to ask for (the API allows 1–7). */
const THREATFOX_DAYS = 3;

export const NEEDS_KEY = 'needs an abuse.ch Auth-Key (free at auth.abuse.ch): set [threat_feeds] auth_key_file or ABUSECH_AUTH_KEY';

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
  blockDomains: boolean;
  refreshMs: number;
  minConfidence: number;
  /** IPs, CIDRs or domains never matched. */
  allow: string[];
  /** abuse.ch Auth-Key; without it only Feodo is fetched. */
  authKey?: string;
}

/**
 * ThreatFox IOCs, in either shape abuse.ch has served them: the API's
 * `{ query_status, data: [ { ioc, ioc_type, … } ] }` or the retired export's
 * `{ "<id>": [ { ioc_value, ioc_type, … } ] }`. An API error status throws,
 * so it is reported as a failed feed rather than parsed as an empty list.
 */
export function parseThreatFoxJson(text: string, minConfidence: number): { ips: Map<string, Indicator>; domains: Map<string, Indicator> } {
  const ips = new Map<string, Indicator>();
  const domains = new Map<string, Indicator>();
  const data = JSON.parse(text) as Record<string, unknown>;
  let lists: unknown[];
  if (typeof data.query_status === 'string') {
    if (data.query_status === 'no_result') return { ips, domains };
    if (data.query_status !== 'ok') throw new Error(`ThreatFox API: ${data.query_status}`);
    lists = [data.data];
  } else {
    lists = Object.values(data);
  }
  for (const entries of lists) {
    for (const ioc of Array.isArray(entries) ? (entries as Array<Record<string, unknown>>) : []) {
      const confidence = typeof ioc.confidence_level === 'number' ? ioc.confidence_level : 0;
      if (confidence < minConfidence) continue;
      const value = String(ioc.ioc ?? ioc.ioc_value ?? '').trim();
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

/**
 * Hosts that serve everyone's files. A URLhaus entry on one of these is a
 * single bad URL, not a bad host, so the host is never listed from a URL.
 */
const URL_HOSTING = [
  ...SHARED_DOMAINS,
  'github.com', 'gitlab.com', 'bitbucket.org', 'live.com', '1drv.ms', 'sharepoint.com',
  'mediafire.com', 'pastebin.com', 'transfer.sh', 'catbox.moe', 'gofile.io', 'archive.org',
  'yandex.ru', 'mega.nz', 'sourceforge.net',
];

function urlHosting(host: string): boolean {
  return URL_HOSTING.some((d) => host === d || host.endsWith(`.${d}`));
}

/** One CSV row with `"…"` quoting (URLhaus quotes every field). */
function csvRow(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') quoted = false;
      else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

/**
 * URLhaus `online.csv`: `id,dateadded,url,url_status,last_online,threat,tags,
 * urlhaus_link,reporter`, `#` comments. The host of each online URL becomes a
 * domain or IP indicator, except shared file hosting (see URL_HOSTING).
 */
export function parseUrlhausCsv(text: string): { ips: Map<string, Indicator>; domains: Map<string, Indicator> } {
  const ips = new Map<string, Indicator>();
  const domains = new Map<string, Indicator>();
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const cols = csvRow(trimmed);
    if (cols.length < 6 || (cols[3] && cols[3] !== 'online')) continue;
    let host: string;
    try {
      host = new URL(cols[2]).hostname.replace(/^\[|\]$/g, '');
    } catch {
      continue;
    }
    const ind: Indicator = { malware: cols[6]?.split(',')[0] || 'unknown', threat: cols[5] || 'malware_download', feed: 'urlhaus' };
    if (isIP(host)) {
      ips.set(host, ind);
      continue;
    }
    const domain = normalizeDomain(host);
    if (domain && !urlHosting(domain)) domains.set(domain, ind);
  }
  return { ips, domains };
}

/** `127.0.0.1 <domain>` host files (ThreatFox). */
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

type FeedPart = { ips?: Map<string, Indicator>; domains?: Map<string, Indicator> };

/** Tries per feed per refresh; only transport failures and 5xx are retried. */
const FETCH_ATTEMPTS = 3;

/** A response no retry will fix: refused key, 4xx, an HTML page. */
class FatalFeedError extends Error {}

/** The key out of an error message, should a URL carrying it end up in one. */
function redact(message: string, key: string | undefined): string {
  if (!key) return message;
  return message.split(key).join('<auth-key>').split(encodeURIComponent(key)).join('<auth-key>');
}

/**
 * Fetch every feed; one that fails is reported, not fatal. A feed counts as
 * failed when it answers non-2xx, answers HTML instead of data, or parses to
 * nothing at all, so a dead source never passes for a clean one (issue #430:
 * abuse.ch's retired URLs answer 410 with an HTML page).
 */
export async function fetchFeeds(settings: Pick<ThreatFeedSettings, 'minConfidence' | 'allow' | 'authKey'>, fetchImpl: FetchLike = fetch, retryDelayMs = 5_000): Promise<FeedSet> {
  const sources: FeedSet['sources'] = [];
  const parts: FeedPart[] = [];
  const key = settings.authKey?.trim() || undefined;
  const ua = { 'User-Agent': 'threatcrush (+https://threatcrush.com)' };
  const get = async (feed: string, request: { url: string; init?: RequestInit } | null, parse: (text: string) => FeedPart, emptyOk = false) => {
    if (!request) {
      sources.push({ feed, ok: false, count: 0, error: NEEDS_KEY });
      return;
    }
    try {
      const extra = (request.init?.headers ?? {}) as Record<string, string>;
      // abuse.ch cuts transfers short under load (undici "terminated", or a
      // JSON body that ends mid-string). Those are worth a retry; a refused
      // key, a 4xx or an HTML page is not.
      let part: FeedPart | undefined;
      for (let attempt = 1; ; attempt++) {
        try {
          const res = await fetchImpl(request.url, { ...request.init, signal: AbortSignal.timeout(60_000), headers: { ...ua, ...extra } });
          if (res.status === 401 || res.status === 403) throw new FatalFeedError(`HTTP ${res.status}: abuse.ch refused the Auth-Key`);
          if (res.status >= 400 && res.status < 500) throw new FatalFeedError(`HTTP ${res.status}`);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const text = await res.text();
          const type = res.headers.get('content-type') ?? '';
          if (type.includes('text/html') || /^\s*<(!doctype|html)/i.test(text)) throw new FatalFeedError(`HTTP ${res.status} but an HTML page, not feed data`);
          part = parse(text);
          break;
        } catch (err) {
          const retryable = !(err instanceof FatalFeedError) && !/^ThreatFox API: /.test((err as Error).message);
          if (!retryable || attempt >= FETCH_ATTEMPTS) throw err;
          await new Promise((r) => setTimeout(r, retryDelayMs * attempt));
        }
      }
      const count = (part.ips?.size ?? 0) + (part.domains?.size ?? 0);
      if (count === 0 && !emptyOk) throw new Error('no entries in the response');
      parts.push(part);
      sources.push({ feed, ok: true, count });
    } catch (err) {
      sources.push({ feed, ok: false, count: 0, error: redact((err as Error).message, key) });
    }
  };
  const threatfoxApi = key ? {
    url: FEEDS.threatfoxApi,
    init: {
      method: 'POST',
      headers: { 'Auth-Key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: THREATFOX_DAYS }),
    },
  } : null;
  await Promise.all([
    get('threatfox', threatfoxApi, (t) => parseThreatFoxJson(t, settings.minConfidence), true),
    get('threatfox-hosts', key ? { url: FEEDS.threatfoxHosts(key) } : null, (t) => ({ domains: parseHostfile(t, 'threatfox') })),
    get('urlhaus', key ? { url: FEEDS.urlhausOnline(key) } : null, parseUrlhausCsv),
    // Feodo has been near-empty since 2025; an empty list there is real.
    get('feodo', { url: FEEDS.feodoIps }, (t) => ({ ips: parseIpList(t, 'feodo') }), true),
  ]);
  sources.sort((a, b) => a.feed.localeCompare(b.feed));
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

// ─── Resolver blocklists (dnsmasq, unbound) ───

/**
 * Files the daemon rewrites in its state dir on every refresh, and the
 * drop-ins `threatcrush feeds resolver install` puts in a resolver's config
 * to read them. The daemon cannot write /etc (ProtectSystem); the drop-ins are
 * written once, as root, and only point at these files.
 */
export const RESOLVER_FILES = {
  hosts: 'blocked-domains.hosts',
  unbound: 'blocked-domains.unbound.conf',
} as const;

export const RESOLVER_HOOKS = {
  dnsmasq: '/etc/dnsmasq.d/threatcrush.conf',
  unbound: '/etc/unbound/unbound.conf.d/threatcrush.conf',
} as const;

const GENERATED = '# Written by threatcrushd from abuse.ch feeds; rewritten every refresh. Do not edit.';

/**
 * A hosts file for dnsmasq's `addn-hosts`: both families, so an AAAA lookup is
 * answered here instead of forwarded upstream. dnsmasq matches these names
 * exactly; subdomains of a listed name still resolve.
 */
export function hostsBlocklist(domains: string[]): string {
  const lines = [GENERATED];
  for (const d of domains) lines.push(`0.0.0.0 ${d}`, `:: ${d}`);
  return `${lines.join('\n')}\n`;
}

/** An unbound include: every listed name and everything under it is NXDOMAIN. */
export function unboundBlocklist(domains: string[]): string {
  const lines = [GENERATED, 'server:'];
  // normalizeDomain allows only [a-z0-9_.-], so nothing here can break out of the quotes.
  for (const d of domains) lines.push(`  local-zone: "${d}." always_nxdomain`);
  return `${lines.join('\n')}\n`;
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
