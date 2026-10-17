import "server-only";
import { getSupabaseAdmin } from "./supabase";

/**
 * The community threat database behind threatcrush.com/traffic.
 *
 * Every linked ThreatCrush daemon already submits its detections to the cloud
 * (CloudSync → /api/ingest, on by default). This aggregates those submissions
 * *across all contributors* into a public reputation feed — our own AbuseIPDB,
 * fed by the fleet and anyone who registers.
 *
 * The danger of a crowdsourced blocklist is poisoning: one misconfigured or
 * malicious reporter should not be able to get an innocent address listed. So
 * the public cut is **corroboration-gated** — an address only surfaces once
 * independent reporters agree, or it is high-severity with repeat hits. Single
 * uncorroborated reports stay in the raw data and out of the public feed.
 *
 * Aggregation is done in JS over a bounded, cached window; a materialized
 * rollup is a later optimisation, noted but not needed at current volume.
 */

const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const ROW_CAP = 50_000;
const SUMMARY_CACHE_MS = 60_000;
const BLOCKLIST_CACHE_MS = 5 * 60_000;

/** Distinct reporters an address needs before it is published (the anti-poison bar). */
export const MIN_REPORTERS_FOR_PUBLIC = 2;
/** …unless it is this severe with at least this many hits from a single reporter. */
const STRONG_SEVERITY = new Set(["high", "critical"]);
const STRONG_MIN_REPORTS = 3;
/** Cap on how many addresses the public blocklist carries. */
const MAX_BLOCKLIST = 5000;

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const RANK_SEVERITY = ["info", "low", "medium", "high", "critical"];

export interface DetectionRow {
  source_ip?: string | null;
  severity?: string | null;
  rule_id?: string | null;
  title?: string | null;
  organization_id?: string | null;
  server_id?: string | null;
  detected_at?: string | null;
  last_detected_at?: string | null;
  occurrences?: number | null;
}

export interface PublicSource {
  ip: string; // masked
  reports: number;
  reporters: number;
  severity: string;
  last_seen: string | null;
}

export interface CommunitySummary {
  generated_at: string;
  window_hours: number;
  totals: {
    reports: number;
    sources: number;
    reporters: number;
    active_bans: number;
    published: number;
  };
  by_severity: Record<string, number>;
  top_rules: Array<{ rule_id: string; title: string; count: number }>;
  top_sources: PublicSource[];
}

export interface BlocklistEntry {
  ip: string; // full
  reports: number;
  reporters: number;
  severity: string;
  first_seen: string | null;
  last_seen: string | null;
  rule_ids: string[];
}

/** Hide the host while keeping the network visible, so the public page accuses no one host. */
export function maskIp(ip: string): string {
  if (ip.includes(":")) {
    const groups = ip.split(":").filter(Boolean);
    return `${groups.slice(0, 3).join(":")}::/48`;
  }
  const octets = ip.split(".");
  if (octets.length === 4) return `${octets[0]}.${octets[1]}.${octets[2]}.x`;
  return "x";
}

function higherSeverity(a: string, b: string): string {
  return (SEVERITY_RANK[a] ?? 0) >= (SEVERITY_RANK[b] ?? 0) ? a : b;
}

function timeOf(row: DetectionRow): string | null {
  return row.last_detected_at ?? row.detected_at ?? null;
}

interface Acc {
  ip: string;
  reports: number;
  reporters: Set<string>;
  severity: string;
  first_seen: string | null;
  last_seen: string | null;
  rule_ids: Set<string>;
}

/** Collapse raw detection rows to one record per source address. */
function foldSources(rows: DetectionRow[]): Map<string, Acc> {
  const byIp = new Map<string, Acc>();
  for (const row of rows) {
    const ip = (row.source_ip ?? "").trim();
    if (!ip) continue;
    const severity = (row.severity ?? "info").toLowerCase();
    const weight = Math.max(1, Number(row.occurrences) || 1);
    const reporter = row.server_id ?? row.organization_id ?? "unknown";
    const seen = timeOf(row);

    const acc = byIp.get(ip);
    if (!acc) {
      byIp.set(ip, {
        ip,
        reports: weight,
        reporters: new Set([reporter]),
        severity,
        first_seen: seen,
        last_seen: seen,
        rule_ids: new Set(row.rule_id ? [row.rule_id] : []),
      });
      continue;
    }
    acc.reports += weight;
    acc.reporters.add(reporter);
    acc.severity = higherSeverity(acc.severity, severity);
    if (row.rule_id) acc.rule_ids.add(row.rule_id);
    if (seen && (!acc.last_seen || seen > acc.last_seen)) acc.last_seen = seen;
    if (seen && (!acc.first_seen || seen < acc.first_seen)) acc.first_seen = seen;
  }
  return byIp;
}

/** The corroboration bar: does this source earn a place in the public feed? */
export function isPublishable(acc: { reporters: Set<string>; reports: number; severity: string }): boolean {
  if (acc.reporters.size >= MIN_REPORTERS_FOR_PUBLIC) return true;
  return STRONG_SEVERITY.has(acc.severity) && acc.reports >= STRONG_MIN_REPORTS;
}

/** Build the public, masked summary. Contains no full host address by construction. */
export function aggregateSummary(rows: DetectionRow[], activeBans: number, now: number): CommunitySummary {
  const sources = foldSources(rows);
  const bySeverity: Record<string, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const ruleCounts = new Map<string, { title: string; count: number }>();
  let totalReports = 0;

  for (const row of rows) {
    const sev = (row.severity ?? "info").toLowerCase();
    const weight = Math.max(1, Number(row.occurrences) || 1);
    if (sev in bySeverity) bySeverity[sev] += weight;
    totalReports += weight;
    const rid = row.rule_id;
    if (rid) {
      const r = ruleCounts.get(rid) ?? { title: row.title ?? rid, count: 0 };
      r.count += weight;
      ruleCounts.set(rid, r);
    }
  }

  const published = [...sources.values()].filter(isPublishable);
  const reporters = new Set<string>();
  for (const acc of sources.values()) for (const r of acc.reporters) reporters.add(r);

  const topSources: PublicSource[] = [...sources.values()]
    .sort((a, b) => b.reports - a.reports || b.reporters.size - a.reporters.size)
    .slice(0, 15)
    .map((acc) => ({
      ip: maskIp(acc.ip),
      reports: acc.reports,
      reporters: acc.reporters.size,
      severity: acc.severity,
      last_seen: acc.last_seen,
    }));

  const topRules = [...ruleCounts.entries()]
    .map(([rule_id, r]) => ({ rule_id, title: r.title, count: r.count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    generated_at: new Date(now).toISOString(),
    window_hours: Math.round(WINDOW_MS / 3_600_000),
    totals: {
      reports: totalReports,
      sources: sources.size,
      reporters: reporters.size,
      active_bans: activeBans,
      published: published.length,
    },
    by_severity: bySeverity,
    top_rules: topRules,
    top_sources: topSources,
  };
}

/** Build the full-IP blocklist (key-gated). Only corroborated sources. */
export function aggregateBlocklist(rows: DetectionRow[]): BlocklistEntry[] {
  return [...foldSources(rows).values()]
    .filter(isPublishable)
    .sort((a, b) => b.reports - a.reports || b.reporters.size - a.reporters.size)
    .slice(0, MAX_BLOCKLIST)
    .map((acc) => ({
      ip: acc.ip,
      reports: acc.reports,
      reporters: acc.reporters.size,
      severity: acc.severity,
      first_seen: acc.first_seen,
      last_seen: acc.last_seen,
      rule_ids: [...acc.rule_ids],
    }));
}

// Missing table/column (feed reads a column a box has not migrated yet).
function isMissing(err: { code?: string } | null): boolean {
  return err?.code === "42P01" || err?.code === "42703";
}

async function fetchRows(now: number): Promise<DetectionRow[]> {
  const admin = getSupabaseAdmin();
  const since = new Date(now - WINDOW_MS).toISOString();
  const { data, error } = await admin
    .from("detections")
    .select("*")
    .gte("detected_at", since)
    .order("detected_at", { ascending: false })
    .limit(ROW_CAP);
  if (error) {
    if (isMissing(error)) return [];
    throw new Error(error.message);
  }
  return (data ?? []) as DetectionRow[];
}

async function fetchActiveBans(): Promise<number> {
  const admin = getSupabaseAdmin();
  const { count, error } = await admin
    .from("remediation_actions")
    .select("*", { count: "exact", head: true })
    .eq("action_type", "block")
    .eq("status", "executed");
  if (error) return 0;
  return count ?? 0;
}

let summaryCache: { at: number; value: CommunitySummary } | null = null;
let blocklistCache: { at: number; value: BlocklistEntry[] } | null = null;

export function resetCommunityCache(): void {
  summaryCache = null;
  blocklistCache = null;
}

export async function loadCommunitySummary(now: number = Date.now()): Promise<CommunitySummary> {
  if (summaryCache && now - summaryCache.at < SUMMARY_CACHE_MS) return summaryCache.value;
  const [rows, bans] = await Promise.all([fetchRows(now), fetchActiveBans()]);
  const value = aggregateSummary(rows, bans, now);
  summaryCache = { at: now, value };
  return value;
}

export async function loadBlocklist(now: number = Date.now()): Promise<BlocklistEntry[]> {
  if (blocklistCache && now - blocklistCache.at < BLOCKLIST_CACHE_MS) return blocklistCache.value;
  const rows = await fetchRows(now);
  const value = aggregateBlocklist(rows);
  blocklistCache = { at: now, value };
  return value;
}
