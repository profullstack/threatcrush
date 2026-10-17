import "server-only";
import { resolve4, resolve6 } from "node:dns/promises";
import { isIP } from "node:net";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  loadBlocklist,
  loadProtected,
  loadReviewDecisions,
  withoutProtected,
  type BlocklistEntry,
} from "./community-threats";
import { isPublicIp, lookupAsn, lookupIps } from "./geoip";
import { buildReport, HISTORY_DAYS, loadDetectionsFor, type ReputationReport, type ReputationTier } from "./reputation";

/**
 * One indicator, IP or domain, looked up the same way for every surface:
 * the single and bulk API, the MCP tool and the watch-list job.
 *
 * A domain is answered from two places: its addresses (A and AAAA, each
 * looked up like an IP against the community database), and nichedb.dev's
 * public answer for the name itself (abuse.ch malware domains, SURBL), which
 * ThreatCrush does not keep a copy of.
 */

export type Indicator = { type: "ip"; value: string } | { type: "domain"; value: string };

export function parseIndicator(raw: string): Indicator | null {
  const text = decodeURIComponent(String(raw ?? "")).trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (isIP(text)) return isPublicIp(text) ? { type: "ip", value: text } : null;
  const host = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split(/[/?#]/)[0].replace(/^www\./, "").replace(/\.$/, "");
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host) && /[a-z]/.test(host.split(".").pop() ?? ""))
    return { type: "domain", value: host };
  return null;
}

export interface DomainReport {
  domain: string;
  type: "domain";
  tier: ReputationTier;
  listed: boolean;
  score: number;
  reasons: string[];
  addresses: ReputationReport[];
  nichedb: { listed: boolean; score: number; reasons: string[] } | null;
  public_record: string;
}

export type AnyReport = (ReputationReport & { type: "ip" }) | DomainReport;

/** How many listed blocklist entries share this address's network owner. */
async function listedOnSameAsn(asn: number, blocklist: BlocklistEntry[], self: string): Promise<number> {
  let n = 0;
  for (const e of blocklist) {
    if (e.ip === self) continue;
    const hit = await lookupAsn(e.ip, 0);
    if (hit?.asn === asn) n++;
  }
  return n;
}

export async function ipReport(admin: SupabaseClient, ip: string, tier: ReputationTier): Promise<ReputationReport> {
  const pro = tier === "pro";
  const [rows, blocklist, geo, protectedSet, asn, decisions] = await Promise.all([
    loadDetectionsFor(admin, ip, pro ? HISTORY_DAYS : 7),
    pro ? loadBlocklist() : Promise.resolve([] as BlocklistEntry[]),
    lookupIps([ip], 3000),
    loadProtected(),
    pro ? lookupAsn(ip) : Promise.resolve(null),
    loadReviewDecisions(),
  ]);
  // Registered servers, allowlisted addresses, reviewer rejections and anyone who logged in are never reported.
  const evidence = withoutProtected(rows, protectedSet);
  const listed = asn && pro ? await listedOnSameAsn(asn.asn, blocklist, ip) : 0;
  const reviewed = decisions.approved.includes(ip);
  return buildReport(ip, evidence, blocklist, geo.get(ip) ?? null, tier, Date.now(), { asn, listed, reviewed });
}

const withTimeout = <T>(p: Promise<T>, ms: number, fallback: T): Promise<T> =>
  Promise.race([p.catch(() => fallback), new Promise<T>((r) => setTimeout(() => r(fallback), ms))]);

/** nichedb.dev's public answer for a domain (abuse.ch, SURBL). Null when it cannot answer in time. */
export async function nichedbDomain(domain: string, fetchImpl: typeof fetch = fetch): Promise<DomainReport["nichedb"]> {
  // The shared TRAFFIC_FEED_TOKEN is how nichedb knows the caller is ThreatCrush (no keyless metering).
  const key = process.env["NICHEDB_API_KEY"] || process.env["TRAFFIC_FEED_TOKEN"];
  const res = await withTimeout(
    fetchImpl(`https://nichedb.dev/api/v1/reputation/${encodeURIComponent(domain)}`, {
      headers: key ? { authorization: `Bearer ${key}` } : {},
      signal: AbortSignal.timeout(5000),
    }),
    5500,
    null as Response | null,
  );
  if (!res || !res.ok) return null;
  const body = (await res.json().catch(() => null)) as { listed?: boolean; score?: number; reasons?: string[] } | null;
  if (!body) return null;
  return { listed: Boolean(body.listed), score: Number(body.score) || 0, reasons: Array.isArray(body.reasons) ? body.reasons : [] };
}

export async function domainReport(
  admin: SupabaseClient,
  domain: string,
  tier: ReputationTier,
  deps: { resolve4?: typeof resolve4; resolve6?: typeof resolve6; fetchImpl?: typeof fetch } = {},
): Promise<DomainReport> {
  const r4 = deps.resolve4 ?? resolve4;
  const r6 = deps.resolve6 ?? resolve6;
  const [v4, v6, nd] = await Promise.all([
    withTimeout(r4(domain), 4000, [] as string[]),
    withTimeout(r6(domain), 4000, [] as string[]),
    nichedbDomain(domain, deps.fetchImpl),
  ]);
  const ips = [...new Set([...v4, ...v6].map((a) => a.toLowerCase()))].filter(isPublicIp).slice(0, 8);
  const addresses = await Promise.all(ips.map((ip) => ipReport(admin, ip, tier)));
  return assembleDomain(domain, tier, addresses, nd);
}

/** Fold the address reports and nichedb's answer into one domain verdict. */
export function assembleDomain(
  domain: string,
  tier: ReputationTier,
  addresses: ReputationReport[],
  nd: DomainReport["nichedb"],
): DomainReport {
  const reasons: string[] = [];
  if (nd?.listed) reasons.push(...nd.reasons.map((r) => `nichedb: ${r}`));
  for (const a of addresses) if (a.listed) reasons.push(`resolves to ${a.ip}, listed (score ${a.score})`);
  const score = Math.max(nd?.score ?? 0, ...addresses.map((a) => (a.listed ? a.score : 0)), 0);
  return {
    domain,
    type: "domain",
    tier,
    listed: Boolean(nd?.listed) || addresses.some((a) => a.listed),
    score,
    reasons,
    addresses,
    nichedb: nd,
    public_record: `https://nichedb.dev/reputation/${domain}`,
  };
}

export async function lookupIndicator(admin: SupabaseClient, ind: Indicator, tier: ReputationTier): Promise<AnyReport> {
  if (ind.type === "ip") return { ...(await ipReport(admin, ind.value, tier)), type: "ip" };
  return domainReport(admin, ind.value, tier);
}
