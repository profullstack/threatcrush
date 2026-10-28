import { findSecret } from "./secret-guard";

/**
 * The incident report contract (report_version 1): what `threatcrush
 * investigate --raise`, the daemon and the MCP `incidents_raise` tool POST.
 * Validation is strict on types and caps; unknown fields are dropped.
 */

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const SOURCES = ["investigate", "watchdog", "daemon", "manual"] as const;
export type IncidentSource = (typeof SOURCES)[number];
export const STATUSES = ["open", "acknowledged", "resolved"] as const;
export type IncidentStatus = (typeof STATUSES)[number];
export const PRIORITIES = ["now", "soon", "later"] as const;

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface ReportFinding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  detail?: string;
  evidence: "evidence" | "inference";
  at?: string;
}
export interface TimelineEntry {
  at: string;
  module: string;
  summary: string;
  evidence: boolean;
  ref?: string;
}
export interface Recommendation {
  action: string;
  target?: string;
  priority: (typeof PRIORITIES)[number];
}
export interface IncidentReport {
  team_id: string | null;
  server_id: string | null;
  title: string;
  severity: Severity;
  source: IncidentSource;
  dedupe_key: string;
  summary: string;
  verdict: string | null;
  host: string | null;
  findings: ReportFinding[];
  timeline: TimelineEntry[];
  recommendations: Recommendation[];
}

export const LIMITS = { title: 300, dedupe: 200, summary: 4000, verdict: 4000, host: 255, findings: 200, timeline: 500, recommendations: 50 };

export class IncidentError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (v: unknown): v is string => typeof v === "string" && UUID.test(v);
export const isSeverity = (v: unknown): v is Severity => typeof v === "string" && (SEVERITIES as readonly string[]).includes(v);
export const isStatus = (v: unknown): v is IncidentStatus => typeof v === "string" && (STATUSES as readonly string[]).includes(v);

const bad = (msg: string) => new IncidentError(400, msg);

function reqStr(o: Record<string, unknown>, key: string, max: number, path: string): string {
  const v = o[key];
  if (typeof v !== "string" || !v.trim()) throw bad(`${path}${key} is required`);
  if (v.length > max) throw bad(`${path}${key} is longer than ${max} characters`);
  return v.trim();
}
function optStr(o: Record<string, unknown>, key: string, max: number, path: string): string | undefined {
  const v = o[key];
  if (v === undefined || v === null || v === "") return undefined;
  if (typeof v !== "string") throw bad(`${path}${key} must be a string`);
  if (v.length > max) throw bad(`${path}${key} is longer than ${max} characters`);
  return v;
}
function iso(v: unknown, path: string): string {
  if (typeof v !== "string" || Number.isNaN(Date.parse(v))) throw bad(`${path} must be an ISO timestamp`);
  return new Date(v).toISOString();
}
function list(o: Record<string, unknown>, key: string, max: number): unknown[] {
  const v = o[key];
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw bad(`${key} must be an array`);
  if (v.length > max) throw bad(`At most ${max} ${key}`);
  return v;
}
function obj(v: unknown, path: string): Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw bad(`${path} must be an object`);
  return v as Record<string, unknown>;
}

/**
 * Parse a raised report. Refuses (422) anything carrying secret-shaped values
 * anywhere in the body, naming only the kind and field.
 */
export function parseIncidentReport(raw: unknown): IncidentReport {
  const hit = findSecret(raw);
  if (hit) {
    throw new IncidentError(
      422,
      `Refused: ${hit.path} looks like secret material (${hit.kind}). Incidents never carry secret values; nothing was stored.`,
    );
  }
  const o = obj(raw, "body");
  if (o.report_version !== undefined && o.report_version !== 1) throw bad("report_version must be 1");
  if (o.team_id != null && !isUuid(o.team_id)) throw bad("team_id must be a uuid");
  if (o.server_id != null && !isUuid(o.server_id)) throw bad("server_id must be a uuid");
  if (!isSeverity(o.severity)) throw bad(`severity must be one of ${SEVERITIES.join(", ")}`);
  if (typeof o.source !== "string" || !(SOURCES as readonly string[]).includes(o.source)) {
    throw bad(`source must be one of ${SOURCES.join(", ")}`);
  }

  const findings = list(o, "findings", LIMITS.findings).map((r, i): ReportFinding => {
    const p = `findings[${i}].`;
    const f = obj(r, `findings[${i}]`);
    if (!isSeverity(f.severity)) throw bad(`${p}severity is invalid`);
    if (f.evidence !== "evidence" && f.evidence !== "inference") throw bad(`${p}evidence must be "evidence" or "inference"`);
    const detail = optStr(f, "detail", 4000, p);
    return {
      id: reqStr(f, "id", 120, p),
      module: reqStr(f, "module", 40, p),
      severity: f.severity,
      title: reqStr(f, "title", 300, p),
      ...(detail ? { detail } : {}),
      evidence: f.evidence,
      ...(f.at != null ? { at: iso(f.at, `${p}at`) } : {}),
    };
  });
  const timeline = list(o, "timeline", LIMITS.timeline).map((r, i): TimelineEntry => {
    const p = `timeline[${i}].`;
    const t = obj(r, `timeline[${i}]`);
    if (typeof t.evidence !== "boolean") throw bad(`${p}evidence must be a boolean`);
    const ref = optStr(t, "ref", 300, p);
    return {
      at: iso(t.at, `${p}at`),
      module: reqStr(t, "module", 40, p),
      summary: reqStr(t, "summary", 1000, p),
      evidence: t.evidence,
      ...(ref ? { ref } : {}),
    };
  });
  const recommendations = list(o, "recommendations", LIMITS.recommendations).map((r, i): Recommendation => {
    const p = `recommendations[${i}].`;
    const x = obj(r, `recommendations[${i}]`);
    if (typeof x.priority !== "string" || !(PRIORITIES as readonly string[]).includes(x.priority)) {
      throw bad(`${p}priority must be now, soon or later`);
    }
    const target = optStr(x, "target", 300, p);
    return { action: reqStr(x, "action", 500, p), ...(target ? { target } : {}), priority: x.priority as Recommendation["priority"] };
  });

  return {
    team_id: (o.team_id as string | null | undefined) ?? null,
    server_id: (o.server_id as string | null | undefined) ?? null,
    title: reqStr(o, "title", LIMITS.title, ""),
    severity: o.severity,
    source: o.source as IncidentSource,
    dedupe_key: reqStr(o, "dedupe_key", LIMITS.dedupe, ""),
    summary: optStr(o, "summary", LIMITS.summary, "") ?? "",
    verdict: optStr(o, "verdict", LIMITS.verdict, "") ?? null,
    host: optStr(o, "host", LIMITS.host, "") ?? null,
    findings,
    timeline: timeline.sort((a, b) => a.at.localeCompare(b.at)),
    recommendations,
  };
}

/** Fold a re-raise into the stored report: findings by id, timeline by at+summary, recommendations by action+target. */
export function mergeReport(
  prev: { findings: ReportFinding[]; timeline: TimelineEntry[]; recommendations: Recommendation[] },
  next: IncidentReport,
): { findings: ReportFinding[]; timeline: TimelineEntry[]; recommendations: Recommendation[] } {
  const findings = new Map((prev.findings ?? []).map((f) => [f.id, f]));
  for (const f of next.findings) findings.set(f.id, f);
  const tl = new Map((prev.timeline ?? []).map((t) => [`${t.at}\u0000${t.summary}`, t]));
  for (const t of next.timeline) tl.set(`${t.at}\u0000${t.summary}`, t);
  const recs = new Map((prev.recommendations ?? []).map((r) => [`${r.action}\u0000${r.target ?? ""}`, r]));
  for (const r of next.recommendations) recs.set(`${r.action}\u0000${r.target ?? ""}`, r);
  return {
    findings: [...findings.values()].slice(-LIMITS.findings),
    timeline: [...tl.values()].sort((a, b) => a.at.localeCompare(b.at)).slice(-LIMITS.timeline),
    recommendations: [...recs.values()].slice(-LIMITS.recommendations),
  };
}
