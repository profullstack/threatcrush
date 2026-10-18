import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Principal } from "./access";
import { orgRoleOf } from "./access";
import { isPublishable, type BlocklistEntry, type DetectionRow } from "./community-threats";
import type { AsnHit, GeoHit } from "./geoip";
import { isSettledStatus } from "./payment-status";

/**
 * ThreatCrush Reputation: one address looked up against the community
 * database every linked daemon feeds (the same data as /traffic).
 *
 * The free lookup (any tc_agent_ key) answers the verdict: listed or not,
 * a 0-100 score, severity, how many independent reporters, last seen. The
 * public, human-reviewed cut of the same data is free and keyless on
 * nichedb.dev/reputation.
 *
 * Reputation Pro, paid in crypto through CoinPay, adds what a defender needs
 * to act on it: 90 days of sighting history by day and rule, the /24 around
 * the address (one bad host or a bad neighbourhood?), the country and city,
 * the reasons behind the score, and a much larger daily allowance. Watch
 * lists with alerts and network-owner (ASN) context are the next phase; see
 * the plan in the PR.
 *
 * Every function that decides something is pure and exported for tests; the
 * loaders at the bottom only fetch.
 */

export type ReputationTier = "free" | "pro";

export interface ReputationPlan {
  id: string;
  name: string;
  months: number;
  amount_usd: number;
}

/**
 * Sales are on when REPUTATION_PRO_ENABLED=true (set in app.env since
 * 2026-10-18). The webhook and the tier check work either way.
 */
export function reputationProEnabled(): boolean {
  // Bracket access: read at runtime from app.env, never inlined at build.
  const name = "REPUTATION_PRO_ENABLED";
  return process.env[name] === "true";
}

/**
 * Anthony, 2026-10-18: "make it 4x our cost". Cost basis: dev2 is $149/mo and
 * serves 111 sites; ThreatCrush, with its own Supabase stack, is given a
 * generous 2.5% of it, $3.73/mo. 4x is $14.90, so $15/mo; the year is ten
 * months' price.
 */
export const REPUTATION_PLANS: ReputationPlan[] = [
  { id: "pro-monthly", name: "Reputation Pro, 1 month", months: 1, amount_usd: 15 },
  { id: "pro-yearly", name: "Reputation Pro, 12 months", months: 12, amount_usd: 150 },
];

/** Lookups a day per key or org. */
export const DAILY_LIMIT: Record<ReputationTier, number> = { free: 100, pro: 10_000 };

/** Crypto only: the house has no card checkout. */
export const REPUTATION_CURRENCIES = ["usdc_pol", "usdc_sol", "usdc_eth", "usdt", "pol", "sol", "btc", "eth"] as const;
export type ReputationCurrency = (typeof REPUTATION_CURRENCIES)[number];

export function isReputationCurrency(v: unknown): v is ReputationCurrency {
  return typeof v === "string" && (REPUTATION_CURRENCIES as readonly string[]).includes(v);
}

export function planById(id: unknown): ReputationPlan | null {
  return REPUTATION_PLANS.find((p) => p.id === id) ?? null;
}

const DAY_MS = 24 * 60 * 60 * 1000;
export const PERIOD_DAYS_PER_MONTH = 30;

/**
 * Where a newly paid period ends: stacked on top of whatever is still running,
 * so renewing early never loses days.
 */
export function periodEnd(now: Date, months: number, currentEnd: Date | null): Date {
  const start = currentEnd && currentEnd > now ? currentEnd : now;
  return new Date(start.getTime() + months * PERIOD_DAYS_PER_MONTH * DAY_MS);
}

export interface SubscriptionRow {
  status: string;
  period_end: string | null;
}

/** Is any of these subscriptions paid and still running? */
export function hasActivePeriod(rows: SubscriptionRow[], now: number = Date.now()): boolean {
  return rows.some((r) => isSettledStatus(r.status) && r.period_end != null && Date.parse(r.period_end) > now);
}

// ─── Scoring ───

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface ScoreInput {
  severity: string;
  reports: number;
  reporters: number;
  last_seen: string | null;
  neighbours?: number;
  rule_ids?: string[];
  /** Other listed addresses in the same network owner's range (Pro). */
  asn_listed?: number;
  /** A person approved it on nichedb.dev/traffic after reading the evidence. */
  reviewed?: boolean;
}

/** What a rule says about intent, strongest first: an exploit attempt outranks a scan. */
const RULE_CLASSES: Array<{ name: string; bonus: number; test: (rule: string) => boolean }> = [
  {
    name: "exploit attempts",
    bonus: 15,
    test: (r) =>
      ["web-sqli-attack", "web-xss-attack", "exploit-probe-pattern", "web-path-traversal"].includes(r) ||
      r.startsWith("attack-"),
  },
  { name: "brute force", bonus: 10, test: (r) => ["ssh-brute-force", "ssh-root-login", "ssh-user-enumeration"].includes(r) },
  { name: "scanning", bonus: 5, test: (r) => r.includes("scanner") || r === "quoted-user-agent" },
];

export function ruleClassOf(rules: string[] = []): { name: string; bonus: number } | null {
  for (const c of RULE_CLASSES) if (rules.some(c.test)) return { name: c.name, bonus: c.bonus };
  return null;
}

/**
 * 0-100 from severity, what the rules say about intent, corroboration, volume
 * and recency (and, for Pro, the /24 and the network owner's range). Quiet
 * addresses decay: nothing in 30 days halves the score. A sorting aid with its
 * reasons attached, never a verdict on its own: the verdict is `listed`, which
 * is the corroboration bar.
 */
export function scoreOf(s: ScoreInput, now: number = Date.now()): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  const sev = SEVERITY_RANK[s.severity] ?? 0;
  let score = sev * 12;
  if (sev >= 3) reasons.push(`${s.severity} severity detections`);
  const cls = ruleClassOf(s.rule_ids);
  if (cls) {
    score += cls.bonus;
    reasons.push(cls.name);
  }
  const reporters = Math.min(s.reporters, 5);
  score += reporters * 7;
  if (s.reporters > 1) reasons.push(`${s.reporters} independent reporters`);
  const volume = Math.min(15, Math.round(Math.log2(s.reports + 1) * 3));
  score += volume;
  if (s.reports >= 10) reasons.push(`${s.reports} reports`);
  if (s.last_seen) {
    const age = now - Date.parse(s.last_seen);
    if (age < DAY_MS) {
      score += 10;
      reasons.push("active in the last 24 hours");
    } else if (age < 7 * DAY_MS) score += 5;
  }
  if (s.neighbours && s.neighbours > 0) {
    score += Math.min(10, s.neighbours * 2);
    reasons.push(`${s.neighbours} other listed address${s.neighbours === 1 ? "" : "es"} in the same /24`);
  }
  if (s.asn_listed && s.asn_listed >= 5) {
    score += Math.min(8, Math.floor(s.asn_listed / 5));
    reasons.push(`${s.asn_listed} other listed addresses on the same network owner`);
  }
  if (s.reviewed) {
    score += 10;
    reasons.push("approved by a reviewer on nichedb.dev/traffic");
  }
  if (s.last_seen && now - Date.parse(s.last_seen) > 30 * DAY_MS) {
    score = Math.round(score / 2);
    reasons.push("quiet for over 30 days");
  }
  return { score: Math.max(0, Math.min(100, score)), reasons };
}

// ─── Neighbourhood ───

/** The /24 (v4) or /48 (v6) an address sits in, as a prefix string. */
export function networkOf(ip: string): string {
  if (ip.includes(":")) {
    const groups = ip.toLowerCase().split(":");
    const head = groups.slice(0, 3).map((g) => g || "0");
    return `${head.join(":")}::/48`;
  }
  const o = ip.split(".");
  return `${o[0]}.${o[1]}.${o[2]}.0/24`;
}

/** Other listed addresses in the same network, strongest first. */
export function neighboursOf(ip: string, entries: BlocklistEntry[], limit = 25): BlocklistEntry[] {
  const net = networkOf(ip);
  return entries
    .filter((e) => e.ip !== ip && networkOf(e.ip) === net)
    .sort((a, b) => b.reports - a.reports)
    .slice(0, limit);
}

// ─── History ───

export interface HistoryDay {
  day: string;
  reports: number;
  rules: string[];
  max_severity: string;
}

/** Sightings folded by UTC day, newest first. */
export function historyOf(rows: DetectionRow[]): HistoryDay[] {
  const byDay = new Map<string, { reports: number; rules: Set<string>; sev: string }>();
  for (const r of rows) {
    const t = r.last_detected_at ?? r.detected_at;
    if (!t) continue;
    const day = t.slice(0, 10);
    const acc = byDay.get(day) ?? { reports: 0, rules: new Set<string>(), sev: "info" };
    acc.reports += Math.max(1, Number(r.occurrences) || 1);
    if (r.rule_id) acc.rules.add(r.rule_id);
    const sev = (r.severity ?? "info").toLowerCase();
    if ((SEVERITY_RANK[sev] ?? 0) > (SEVERITY_RANK[acc.sev] ?? 0)) acc.sev = sev;
    byDay.set(day, acc);
  }
  return [...byDay.entries()]
    .sort((a, b) => (a[0] < b[0] ? 1 : -1))
    .map(([day, a]) => ({ day, reports: a.reports, rules: [...a.rules].sort(), max_severity: a.sev }));
}

// ─── The report ───

export interface ReputationReport {
  ip: string;
  tier: ReputationTier;
  listed: boolean;
  score: number;
  severity: string;
  reports: number;
  reporters: number;
  first_seen: string | null;
  last_seen: string | null;
  rule_ids: string[];
  country: string | null;
  public_record: string;
  pro?: {
    reasons: string[];
    city: string | null;
    network: string;
    neighbours: { count: number; addresses: Array<Pick<BlocklistEntry, "ip" | "reports" | "reporters" | "severity" | "last_seen">> };
    owner: { asn: number; org: string | null; network: string | null; listed_addresses: number } | null;
    history: HistoryDay[];
  };
  upgrade?: { url: string; adds: string[] };
}

export const UPGRADE = {
  url: "https://threatcrush.com/reputation",
  adds: [
    "90 days of sighting history by day and rule",
    "the /24 neighbourhood: other listed addresses nearby",
    "the network owner (ASN) and how much of it is listed",
    "city",
    "bulk lookups and watch lists that alert",
    "the reasons behind the score",
    `${DAILY_LIMIT.pro.toLocaleString("en-US")} lookups a day`,
  ],
};

/**
 * Build the report for one address from its raw detections (any age the
 * caller fetched), the current blocklist and a geo hit.
 */
export function buildReport(
  ip: string,
  rows: DetectionRow[],
  blocklist: BlocklistEntry[],
  geo: GeoHit | null,
  tier: ReputationTier,
  now: number = Date.now(),
  owner: { asn: AsnHit | null; listed: number; reviewed?: boolean } = { asn: null, listed: 0 },
): ReputationReport {
  const reporters = new Set<string>();
  const rules = new Set<string>();
  let reports = 0;
  let severity = "info";
  let first: string | null = null;
  let last: string | null = null;
  for (const r of rows) {
    reports += Math.max(1, Number(r.occurrences) || 1);
    reporters.add(r.server_id ?? r.organization_id ?? "unknown");
    if (r.rule_id) rules.add(r.rule_id);
    const sev = (r.severity ?? "info").toLowerCase();
    if ((SEVERITY_RANK[sev] ?? 0) > (SEVERITY_RANK[severity] ?? 0)) severity = sev;
    const t = r.last_detected_at ?? r.detected_at ?? null;
    const f = r.detected_at ?? t;
    if (t && (!last || t > last)) last = t;
    if (f && (!first || f < first)) first = f;
  }
  // A reviewer's approval is corroboration enough on its own.
  const listed = rows.length > 0 && (Boolean(owner.reviewed) || isPublishable({ reporters, reports, severity }));
  const neighbours = tier === "pro" ? neighboursOf(ip, blocklist) : [];
  const { score, reasons } = scoreOf(
    {
      severity,
      reports,
      reporters: reporters.size,
      last_seen: last,
      rule_ids: [...rules],
      neighbours: tier === "pro" ? neighbours.length : 0,
      asn_listed: tier === "pro" ? owner.listed : 0,
      reviewed: owner.reviewed,
    },
    now,
  );
  const report: ReputationReport = {
    ip,
    tier,
    listed,
    score: rows.length ? score : 0,
    severity: rows.length ? severity : "none",
    reports,
    reporters: reporters.size,
    first_seen: first,
    last_seen: last,
    rule_ids: [...rules].sort(),
    country: geo?.countryCode ?? null,
    public_record: `https://nichedb.dev/reputation/${ip}`,
  };
  if (tier === "pro") {
    report.pro = {
      reasons: rows.length ? reasons : [],
      city: geo?.city ?? null,
      network: networkOf(ip),
      neighbours: {
        count: neighbours.length,
        addresses: neighbours.map((n) => ({
          ip: n.ip,
          reports: n.reports,
          reporters: n.reporters,
          severity: n.severity,
          last_seen: n.last_seen,
        })),
      },
      owner: owner.asn
        ? { asn: owner.asn.asn, org: owner.asn.org, network: owner.asn.network, listed_addresses: owner.listed }
        : null,
      history: historyOf(rows),
    };
  } else {
    report.upgrade = UPGRADE;
  }
  return report;
}

// ─── Allowance ───

const usage = new Map<string, { day: string; n: number }>();

export interface Allowance {
  ok: boolean;
  remaining: number;
  limit: number;
}

const allowanceOf = (n: number, limit: number): Allowance => ({ ok: n <= limit, remaining: Math.max(0, limit - n), limit });

/**
 * Count `count` lookups against a caller's daily allowance in this process
 * only. The fallback when the database counter is unreachable, and what the
 * tests exercise.
 */
export function takeLookup(caller: string, tier: ReputationTier, now: number = Date.now(), count = 1): Allowance {
  const day = new Date(now).toISOString().slice(0, 10);
  const u = usage.get(caller);
  const n = (u && u.day === day ? u.n : 0) + count;
  usage.set(caller, { day, n });
  return allowanceOf(n, DAILY_LIMIT[tier]);
}

/**
 * Count lookups in the shared counter (reputation_take, one atomic upsert),
 * so the allowance survives restarts and holds across processes. Falls back
 * to the in-process count when the database cannot answer.
 */
export async function takeLookupShared(
  admin: SupabaseClient,
  caller: string,
  tier: ReputationTier,
  count = 1,
  now: number = Date.now(),
): Promise<Allowance> {
  const day = new Date(now).toISOString().slice(0, 10);
  const { data, error } = await admin.rpc("reputation_take", { p_caller: caller, p_day: day, p_n: count });
  if (error || typeof data !== "number") return takeLookup(caller, tier, now, count);
  return allowanceOf(data, DAILY_LIMIT[tier]);
}

export function resetLookupUsage(): void {
  usage.clear();
}

// ─── Loaders ───

export const HISTORY_DAYS = 90;
const HISTORY_ROW_CAP = 2000;

export async function loadDetectionsFor(admin: SupabaseClient, ip: string, days: number, now: number = Date.now()): Promise<DetectionRow[]> {
  const since = new Date(now - days * DAY_MS).toISOString();
  const { data, error } = await admin
    .from("detections")
    .select("source_ip, severity, rule_id, title, organization_id, server_id, detected_at, last_detected_at, occurrences")
    .eq("source_ip", ip)
    .gte("detected_at", since)
    .order("detected_at", { ascending: false })
    .limit(HISTORY_ROW_CAP);
  if (error) {
    if (error.code === "42P01" || error.code === "42703") return [];
    throw new Error(error.message);
  }
  return (data ?? []) as DetectionRow[];
}

/** The org a caller acts for: an agent key's own org, or one the user names and administers. */
export async function orgFor(admin: SupabaseClient, p: Principal, requested: string | null): Promise<string | null> {
  if (p.kind === "agent") return p.orgId;
  if (!requested) return null;
  const role = await orgRoleOf(admin, p, requested);
  return role === "owner" || role === "admin" ? requested : null;
}

/** The org a reading caller belongs to, for the tier check (any role). */
export async function readingOrgFor(admin: SupabaseClient, p: Principal, requested: string | null): Promise<string | null> {
  if (p.kind === "agent") return p.orgId;
  if (!requested) return null;
  return (await orgRoleOf(admin, p, requested)) ? requested : null;
}

export async function tierFor(admin: SupabaseClient, orgId: string | null, now: number = Date.now()): Promise<ReputationTier> {
  if (!orgId) return "free";
  const { data, error } = await admin
    .from("reputation_subscriptions")
    .select("status, period_end")
    .eq("org_id", orgId)
    .gt("period_end", new Date(now).toISOString());
  if (error) return "free";
  return hasActivePeriod((data ?? []) as SubscriptionRow[], now) ? "pro" : "free";
}

/** The latest paid period end for an org, for stacking a renewal. */
export async function currentPeriodEnd(admin: SupabaseClient, orgId: string): Promise<Date | null> {
  const { data } = await admin
    .from("reputation_subscriptions")
    .select("status, period_end")
    .eq("org_id", orgId)
    .in("status", ["confirmed", "forwarded"])
    // The row being settled has no period yet, and DESC sorts NULLs first.
    .not("period_end", "is", null)
    .order("period_end", { ascending: false })
    .limit(1);
  const end = (data?.[0] as SubscriptionRow | undefined)?.period_end;
  return end ? new Date(end) : null;
}
