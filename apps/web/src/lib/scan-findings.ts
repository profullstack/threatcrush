import "server-only";
import { createHash } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Tracked scan findings (supabase/migrations/20261028120000_scan_findings.sql):
 * turns each finished property_run's raw findings into deduped, stateful rows
 * people triage from the web app, desktop and CLI.
 */

export const FINDING_SOURCES = ["scan", "pentest", "ai-scan"] as const;
export type FindingSource = (typeof FINDING_SOURCES)[number];
export const FINDING_STATUSES = ["open", "acknowledged", "fixed", "false_positive", "ignored"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITIES)[number];

export const isFindingSource = (v: unknown): v is FindingSource =>
  typeof v === "string" && (FINDING_SOURCES as readonly string[]).includes(v);
export const isFindingStatus = (v: unknown): v is FindingStatus =>
  typeof v === "string" && (FINDING_STATUSES as readonly string[]).includes(v);

/** Statuses sync may move: fixed when gone, open again when back. A person's
 * false_positive / ignored call is never overridden by a run. */
const ACTIVE: FindingStatus[] = ["open", "acknowledged"];
const MAX_FINDINGS = 2000;
const MAX_DETAILS = 16_384;

export interface NormalizedFinding {
  fingerprint: string;
  type: string;
  severity: Severity;
  message: string;
  location: string | null;
  details: Record<string, unknown>;
}

const str = (v: unknown, max: number) => (typeof v === "string" ? v.slice(0, max) : "");

/**
 * Identity of a finding across runs: what it is and where, not how it was
 * worded this time.
 *   code (`scan`): rule + file + the matched line's text, not the line number,
 *     so editing above a finding does not turn it into "fixed" plus "new".
 *   anything else: type + location + message with digits folded, so
 *     "took 812ms" and "took 790ms" stay one finding.
 */
export function fingerprintOf(f: { type: string; location: string | null; message: string; details?: Record<string, unknown> }): string {
  const d = f.details ?? {};
  const rule = typeof d.ruleId === "string" ? d.ruleId : typeof d.rule_id === "string" ? d.rule_id : "";
  const parts =
    rule && typeof d.file === "string"
      ? ["code", rule, d.file, typeof d.snippet === "string" ? d.snippet.replace(/\s+/g, " ").trim() : ""]
      : [f.type, rule, f.location ?? "", f.message.toLowerCase().replace(/\d+/g, "#").replace(/\s+/g, " ").trim()];
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 40);
}

/** Validates and dedupes raw RunResult findings; junk entries are dropped. */
export function normalizeFindings(raw: unknown): NormalizedFinding[] {
  if (!Array.isArray(raw)) return [];
  const out = new Map<string, NormalizedFinding>();
  for (const r of raw.slice(0, MAX_FINDINGS)) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    const message = str(o.message, 2000);
    const type = str(o.type, 120) || "finding";
    if (!message) continue;
    const severity = (SEVERITIES as readonly string[]).includes(o.severity as string) ? (o.severity as Severity) : "info";
    let details: Record<string, unknown> = {};
    if (o.details && typeof o.details === "object" && !Array.isArray(o.details)) {
      details = JSON.stringify(o.details).length <= MAX_DETAILS ? (o.details as Record<string, unknown>) : { truncated: true };
    }
    const location = str(o.location, 1000) || null;
    const f = { type, severity, message, location, details };
    const fingerprint = fingerprintOf(f);
    const prev = out.get(fingerprint);
    // Two hits on one fingerprint in a run: keep the more severe wording.
    if (!prev || SEVERITIES.indexOf(severity) < SEVERITIES.indexOf(prev.severity)) out.set(fingerprint, { fingerprint, ...f });
  }
  return [...out.values()];
}

export interface SyncResult { new: number; seen: number; reopened: number; fixed: number }

/**
 * Folds one finished run into scan_findings. Only a succeeded run can mark
 * findings fixed: a failed run proves nothing about what is gone.
 */
export async function syncRunFindings(
  admin: SupabaseClient,
  run: { id: string; org_id: string; property_id: string; type: string; scope?: string | null; status: string; findings: unknown },
): Promise<SyncResult> {
  const result: SyncResult = { new: 0, seen: 0, reopened: 0, fixed: 0 };
  if (!isFindingSource(run.type) || !["succeeded", "failed"].includes(run.status)) return result;
  const scope = run.scope ?? "";
  const now = new Date().toISOString();
  const found = normalizeFindings(run.findings);

  const { data: existing, error } = await admin
    .from("scan_findings")
    .select("id, fingerprint, status, times_seen")
    .eq("org_id", run.org_id)
    .eq("property_id", run.property_id)
    .eq("source", run.type)
    .eq("scope", scope);
  if (error) throw new Error(`scan_findings read: ${error.message}`);
  const byFp = new Map((existing ?? []).map((e) => [e.fingerprint as string, e]));

  const inserts = [];
  for (const f of found) {
    const e = byFp.get(f.fingerprint);
    if (!e) {
      inserts.push({
        org_id: run.org_id, property_id: run.property_id, source: run.type, scope,
        fingerprint: f.fingerprint, type: f.type, severity: f.severity, message: f.message,
        location: f.location, details: f.details, first_run_id: run.id, last_run_id: run.id,
        first_seen_at: now, last_seen_at: now,
      });
      result.new++;
      continue;
    }
    const reopen = e.status === "fixed";
    const { error: upErr } = await admin
      .from("scan_findings")
      .update({
        severity: f.severity, message: f.message, details: f.details, last_run_id: run.id, last_seen_at: now,
        times_seen: (e.times_seen ?? 1) + 1,
        ...(reopen ? { status: "open", resolved_at: null, status_changed_at: now, status_changed_by: null, status_source: "sync" } : {}),
      })
      .eq("id", e.id);
    if (upErr) throw new Error(`scan_findings update: ${upErr.message}`);
    if (reopen) result.reopened++;
    else result.seen++;
  }
  if (inserts.length) {
    const { error: insErr } = await admin.from("scan_findings").insert(inserts);
    if (insErr) throw new Error(`scan_findings insert: ${insErr.message}`);
  }

  if (run.status === "succeeded") {
    const seen = new Set(found.map((f) => f.fingerprint));
    const gone = (existing ?? []).filter((e) => ACTIVE.includes(e.status as FindingStatus) && !seen.has(e.fingerprint as string));
    if (gone.length) {
      const { error: fixErr } = await admin
        .from("scan_findings")
        .update({ status: "fixed", resolved_at: now, status_changed_at: now, status_changed_by: null, status_source: "sync" })
        .in("id", gone.map((e) => e.id));
      if (fixErr) throw new Error(`scan_findings fix: ${fixErr.message}`);
      result.fixed = gone.length;
    }
  }
  return result;
}

// ─── Shared by the REST routes and the MCP tools ───

const SEVERITY_LIST = ["critical", "high", "medium", "low", "info"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const csv = (v: unknown) => (typeof v === "string" ? v.split(",").map((s) => s.trim()).filter(Boolean) : []);

export interface FindingFilters { status?: unknown; severity?: unknown; source?: unknown; property_id?: unknown; limit?: unknown; offset?: unknown }

/** One page of an org's findings, newest-seen first, plus totals per status. Default view: open + acknowledged. */
export async function listFindings(admin: SupabaseClient, orgId: string, f: FindingFilters = {}) {
  const statuses = f.status === "all" ? [...FINDING_STATUSES] : csv(f.status).filter(isFindingStatus);
  const severities = csv(f.severity).filter((s) => SEVERITY_LIST.includes(s));
  const sources = csv(f.source).filter(isFindingSource);
  const limit = Math.min(500, Math.max(1, Number(f.limit) || 100));
  const offset = Math.max(0, Number(f.offset) || 0);

  let q = admin
    .from("scan_findings")
    .select("id, property_id, source, scope, type, severity, message, location, status, note, first_seen_at, last_seen_at, times_seen, resolved_at, status_changed_at, status_source, properties(name, kind, target)", { count: "exact" })
    .eq("org_id", orgId)
    .in("status", statuses.length ? statuses : ["open", "acknowledged"]);
  if (severities.length) q = q.in("severity", severities);
  if (sources.length) q = q.in("source", sources);
  if (typeof f.property_id === "string" && UUID.test(f.property_id)) q = q.eq("property_id", f.property_id);
  const { data, count, error } = await q.order("last_seen_at", { ascending: false }).range(offset, offset + limit - 1);
  if (error) throw new Error(`list findings: ${error.message}`);

  const { data: all } = await admin.from("scan_findings").select("status, severity").eq("org_id", orgId);
  const counts: Record<string, number> = {};
  const openBySeverity: Record<string, number> = {};
  for (const r of all ?? []) {
    counts[r.status] = (counts[r.status] ?? 0) + 1;
    if (r.status === "open") openBySeverity[r.severity] = (openBySeverity[r.severity] ?? 0) + 1;
  }
  return { findings: data ?? [], total: count ?? 0, counts, open_by_severity: openBySeverity };
}

export class TriageError extends Error {}

/** Sets status and/or note on up to 500 of an org's findings. `by` = the person, or null for an agent key. */
export async function triageFindings(admin: SupabaseClient, orgId: string, by: { userId: string | null }, input: { ids?: unknown; status?: unknown; note?: unknown }) {
  const ids = Array.isArray(input.ids) ? input.ids.filter((x): x is string => typeof x === "string" && UUID.test(x)).slice(0, 500) : [];
  if (!ids.length) throw new TriageError("ids required");
  const patch: Record<string, unknown> = {};
  if (input.status !== undefined && input.status !== null) {
    if (!isFindingStatus(input.status)) throw new TriageError(`status must be one of ${FINDING_STATUSES.join(", ")}`);
    const now = new Date().toISOString();
    Object.assign(patch, {
      status: input.status,
      resolved_at: ["fixed", "false_positive", "ignored"].includes(input.status) ? now : null,
      status_changed_at: now,
      status_changed_by: by.userId,
      status_source: by.userId ? "user" : "agent",
    });
  }
  if (input.note !== undefined) {
    if (input.note !== null && typeof input.note !== "string") throw new TriageError("note must be a string");
    patch.note = input.note === null ? null : input.note.slice(0, 4000);
  }
  if (!Object.keys(patch).length) throw new TriageError("Nothing to update");
  const { data, error } = await admin.from("scan_findings").update(patch).eq("org_id", orgId).in("id", ids).select("id, status, note");
  if (error) throw new Error(`triage findings: ${error.message}`);
  return data ?? [];
}

export async function getFinding(admin: SupabaseClient, orgId: string, id: string) {
  if (!UUID.test(id)) return null;
  const { data, error } = await admin.from("scan_findings").select("*, properties(name, kind, target)").eq("org_id", orgId).eq("id", id).maybeSingle();
  if (error) throw new Error(`get finding: ${error.message}`);
  return data;
}
