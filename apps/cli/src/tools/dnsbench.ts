/**
 * DNS Benchmark — measure the speed and reliability of DNS resolvers.
 *
 * An independent re-implementation of the idea behind GRC's DNS Benchmark (not
 * affiliated with GRC): query a set of resolvers for a set of names and rank
 * them by latency and success rate. The per-query probe is injectable so the
 * aggregation/ranking is pure and testable; the default probe uses Node's dns.
 */

import dns from 'node:dns';

export interface Resolver {
  name: string;
  ip: string;
}

/** Well-known public resolvers (IPv4). */
export const PUBLIC_RESOLVERS: Resolver[] = [
  { name: 'Cloudflare', ip: '1.1.1.1' },
  { name: 'Google', ip: '8.8.8.8' },
  { name: 'Quad9', ip: '9.9.9.9' },
  { name: 'OpenDNS', ip: '208.67.222.222' },
  { name: 'ControlD', ip: '76.76.2.0' },
  { name: 'AdGuard', ip: '94.140.14.14' },
];

/** A default basket of common names to resolve. */
export const DEFAULT_NAMES = ['google.com', 'cloudflare.com', 'wikipedia.org', 'github.com', 'amazon.com'];

/** Probe one resolver for one name; return latency ms, or null on failure. */
export type DnsProbe = (serverIp: string, name: string, timeoutMs: number) => Promise<number | null>;

const nodeProbe: DnsProbe = async (serverIp, name, timeoutMs) => {
  const r = new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 });
  r.setServers([serverIp]);
  const start = performance.now();
  try {
    await r.resolve4(name);
    return Math.round((performance.now() - start) * 100) / 100;
  } catch {
    return null;
  }
};

export interface ResolverResult {
  name: string;
  ip: string;
  queries: number;
  successes: number;
  reliabilityPct: number;
  avgMs: number | null;
  minMs: number | null;
  maxMs: number | null;
}

export interface BenchOptions {
  names?: string[];
  timeoutMs?: number;
  probe?: DnsProbe;
}

export function summarizeLatencies(latencies: (number | null)[]): Omit<ResolverResult, 'name' | 'ip'> {
  const ok = latencies.filter((x): x is number => x !== null);
  const queries = latencies.length;
  const successes = ok.length;
  return {
    queries,
    successes,
    reliabilityPct: queries ? Math.round((successes / queries) * 1000) / 10 : 0,
    avgMs: ok.length ? Math.round((ok.reduce((a, b) => a + b, 0) / ok.length) * 100) / 100 : null,
    minMs: ok.length ? Math.min(...ok) : null,
    maxMs: ok.length ? Math.max(...ok) : null,
  };
}

/** Rank: successful resolvers by avg latency asc; failed resolvers last. */
export function rankResults(results: ResolverResult[]): ResolverResult[] {
  return [...results].sort((a, b) => {
    if (a.avgMs === null && b.avgMs === null) return 0;
    if (a.avgMs === null) return 1;
    if (b.avgMs === null) return -1;
    return a.avgMs - b.avgMs;
  });
}

export async function benchmarkDns(resolvers: Resolver[], opts: BenchOptions = {}): Promise<ResolverResult[]> {
  const names = opts.names ?? DEFAULT_NAMES;
  const timeoutMs = opts.timeoutMs ?? 2000;
  const probe = opts.probe ?? nodeProbe;
  const results: ResolverResult[] = [];
  for (const res of resolvers) {
    const latencies: (number | null)[] = [];
    for (const name of names) latencies.push(await probe(res.ip, name, timeoutMs));
    results.push({ name: res.name, ip: res.ip, ...summarizeLatencies(latencies) });
  }
  return rankResults(results);
}
