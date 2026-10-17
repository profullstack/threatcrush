import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PATHS } from '../daemon/paths.js';

/**
 * The local audit trail (PRD 0015 R9): everything the reporter sent, or would
 * have sent, and the evidence that justified it. A reputation feed is slow to
 * forget, so the operator needs a durable record of exactly what was said about
 * whom, and a way to retract it.
 *
 * It lives in a file, not the state DB, for the same reason the watchdog log
 * does: the root daemon writes it and an unprivileged `threatcrush abuse` reads
 * it. The contents are only the already-redacted, publishable facts — no API
 * keys, no local hostnames — so the file is world-readable by design.
 */

export const ABUSE_DIRNAME = 'abuse-reports';
const LOG_FILE = 'reports.jsonl';

export interface AbuseDestinationOutcome {
  destination: string;
  ok: boolean;
  detail: string;
}

export interface AbuseReportRecord {
  /** Short, stable id for `abuse retract <id>`. */
  id: string;
  ip: string;
  reported_at: string;
  mode: 'live' | 'dry_run';
  /** AbuseIPDB numeric categories. */
  categories: number[];
  /** The exact redacted comment that was (or would be) sent. */
  comment: string;
  signals: number;
  total_events: number;
  /** Per-destination result; empty in dry-run. */
  destinations: AbuseDestinationOutcome[];
  retracted_at?: string;
  retract_note?: string;
}

/**
 * Prefer the system daemon's directory when it exists — it is the one watching
 * real traffic — exactly as the watchdog reader does. `THREATCRUSH_ABUSE_DIR`
 * overrides for tests and custom layouts.
 */
export function resolveAbuseDir(dir?: string): string {
  if (dir) return dir;
  if (process.env.THREATCRUSH_ABUSE_DIR) return process.env.THREATCRUSH_ABUSE_DIR;
  const system = join('/var/lib/threatcrush', ABUSE_DIRNAME);
  if (existsSync(system)) return system;
  return join(PATHS.stateDir, ABUSE_DIRNAME);
}

function logPath(dir?: string): string {
  return join(resolveAbuseDir(dir), LOG_FILE);
}

export function appendReport(record: AbuseReportRecord, dir?: string): void {
  const path = logPath(dir);
  mkdirSync(resolveAbuseDir(dir), { recursive: true, mode: 0o755 });
  appendFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o644 });
}

export function readReports(dir?: string): AbuseReportRecord[] {
  const path = logPath(dir);
  let raw: string;
  try {
    raw = readFileSync(path, 'utf-8');
  } catch {
    return [];
  }
  const out: AbuseReportRecord[] = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as AbuseReportRecord);
    } catch {
      // A line cut short by a crash mid-append.
    }
  }
  return out;
}

export function findReport(id: string, dir?: string): AbuseReportRecord | undefined {
  // Last write wins, so read newest-first to see a retraction over its report.
  const all = readReports(dir);
  for (let i = all.length - 1; i >= 0; i--) {
    if (all[i].id === id || all[i].id.startsWith(id)) return all[i];
  }
  return undefined;
}

/**
 * Record a retraction. The file is append-only, so this writes a new line with
 * the same id carrying the retraction; readers that collapse by id see the
 * latest. Note: AbuseIPDB and StopForumSpam have no programmatic delete — a
 * retraction removes the source from *our* published feed and is the record the
 * operator shows when asking the upstream to remove it by hand.
 */
export function markRetracted(id: string, note: string, dir?: string): AbuseReportRecord | undefined {
  const record = findReport(id, dir);
  if (!record) return undefined;
  const retracted: AbuseReportRecord = {
    ...record,
    retracted_at: new Date().toISOString(),
    retract_note: note,
  };
  appendReport(retracted, dir);
  return retracted;
}

/** Collapse append-only history to the current state of each report id. */
export function currentReports(dir?: string): AbuseReportRecord[] {
  const byId = new Map<string, AbuseReportRecord>();
  for (const r of readReports(dir)) byId.set(r.id, r);
  return [...byId.values()].sort((a, b) => b.reported_at.localeCompare(a.reported_at));
}

/** Writes the whole file from scratch — used only by tests and compaction. */
export function rewriteReports(records: AbuseReportRecord[], dir?: string): void {
  mkdirSync(resolveAbuseDir(dir), { recursive: true, mode: 0o755 });
  writeFileSync(logPath(dir), records.map((r) => JSON.stringify(r)).join('\n') + (records.length ? '\n' : ''), { mode: 0o644 });
}
