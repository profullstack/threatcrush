import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, renameSync, statSync, writeFileSync, fstatSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type { EventSeverity, ThreatEvent } from '../types/events.js';

/**
 * Watchdog mode: keep every attack the box saw, so each one can be checked
 * afterwards — "was that a real hole?" — and, when it was, handed to whoever
 * (or whatever agent) writes the fix PR.
 *
 * The live feed cannot do this. It is a 500-line ring buffer, it hides routine
 * lines, and a ban takes the attacker off the screen — none of which says
 * whether the request that got them banned was *answered*. That is the one
 * question that matters for triage: a SQLi probe nginx 404'd is noise; the same
 * probe answered 200 is a finding.
 *
 * Two files under `<stateDir>/watchdog/`:
 *   attacks.jsonl  append-only, one line per attack, rotated to attacks.1.jsonl
 *   triage.json    verdict per finding (a finding = one signature, see below)
 */

export const WATCHDOG_DIRNAME = 'watchdog';
const LOG_FILE = 'attacks.jsonl';
const ROTATED_FILE = 'attacks.1.jsonl';
const TRIAGE_FILE = 'triage.json';
/** Rotate past this, keeping one previous file. A scanner flood is ~200 B/line. */
export const ROTATE_BYTES = 50 * 1024 * 1024;
/** How many recent keys to remember so a reconnect's backfill is not logged twice. */
const SEEN_LIMIT = 5000;

/**
 * How the target answered. This is what decides the triage order: an attack
 * that was `answered` or made the app `errored` needs a human; `refused` is the
 * expected outcome and is mostly there for the record.
 */
export type Outcome = 'answered' | 'errored' | 'redirected' | 'refused' | 'unknown';

export const OUTCOME_ORDER: Outcome[] = ['answered', 'errored', 'unknown', 'redirected', 'refused'];

export type TriageStatus = 'new' | 'hole' | 'fp' | 'fixed';
export const TRIAGE_STATUSES: TriageStatus[] = ['new', 'hole', 'fp', 'fixed'];

export interface AttackRecord {
  v: 1;
  /** Finding id: a short hash of the signature, shared by every repeat. */
  id: string;
  at: string;
  module: string;
  category: string;
  severity: EventSeverity;
  message: string;
  ip?: string;
  host?: string;
  method?: string;
  /** Path without querystring — the part that identifies the endpoint. */
  path?: string;
  /** Full request target as logged, querystring included: the payload. */
  url?: string;
  status?: number;
  outcome: Outcome;
  attack_type?: string;
  rule_id?: string;
  crs_score?: number;
  ua?: string;
}

export interface TriageEntry {
  status: TriageStatus;
  note?: string;
  pr?: string;
  updated_at: string;
}

export type TriageMap = Record<string, TriageEntry>;

export interface Finding {
  id: string;
  /** Worst outcome seen across the repeats: one 200 among a thousand 404s still matters. */
  outcome: Outcome;
  severity: EventSeverity;
  count: number;
  first_seen: string;
  last_seen: string;
  host?: string;
  method?: string;
  path?: string;
  attack_type?: string;
  rule_id?: string;
  module: string;
  title: string;
  /** Distinct source IPs, capped. */
  sources: string[];
  source_count: number;
  /** Status codes seen, with counts. */
  statuses: Record<string, number>;
  /** A few concrete requests, answered ones first, for reproduction. */
  samples: AttackRecord[];
  triage: TriageEntry;
}

const SEVERITY_RANK: Record<EventSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' && v !== '-' ? v : undefined;
}

/**
 * Is this event an attack worth keeping? Medium and above always (rule
 * detections, port scans, brute force), plus any web request the CRS engine
 * matched — even below its ban threshold, because a sub-threshold injection
 * that came back 200 is exactly the kind of hole nothing else would flag.
 *
 * Not attacks: the firewall's own ban/unban notices, monitor heartbeats, and
 * plain web 4xx/5xx with no attack signature (those are traffic, not probes).
 */
export function isAttack(event: ThreatEvent): boolean {
  if (event.module === 'firewall-rules') return false;
  const d = event.details ?? {};
  if (d.heartbeat) return false;
  const crs = typeof d.crs_score === 'number' ? d.crs_score : 0;
  if (crs > 0 || str(d.attack_type)) return true;
  // A web line with a status but no signature is a 4xx/5xx, not a probe.
  if (event.category === 'web' && typeof d.status === 'number' && !str(d.rule_id)) return false;
  return SEVERITY_RANK[event.severity] >= SEVERITY_RANK.medium;
}

export function outcomeFor(status: number | undefined): Outcome {
  if (typeof status !== 'number' || !Number.isFinite(status)) return 'unknown';
  if (status >= 500) return 'errored';
  if (status >= 400) return 'refused';
  if (status >= 300) return 'redirected';
  if (status >= 100) return 'answered';
  return 'unknown';
}

/** `GET /a?b=1` out of `Attack [SQLI]: GET /a?b=1`, for events that predate `details.url`. */
function requestFromMessage(message: string): { method?: string; url?: string } {
  const m = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PROPFIND)\s+(\S+)/.exec(message);
  return m ? { method: m[1], url: m[2] } : {};
}

/**
 * The identity of a finding. Web: the endpoint and attack class, so ten
 * thousand scanner hits on /wp-login.php are one row, not ten thousand. Other
 * modules: the rule, or the message with addresses and numbers blanked.
 */
export function signatureOf(r: Pick<AttackRecord, 'module' | 'host' | 'method' | 'path' | 'attack_type' | 'rule_id' | 'message'>): string {
  if (r.path) {
    return ['web', r.host ?? '', r.method ?? '', r.path, r.attack_type ?? r.rule_id ?? ''].join('|');
  }
  if (r.rule_id) return ['rule', r.module, r.rule_id].join('|');
  const shape = r.message
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d+)?\b/g, '<ip>')
    .replace(/\b[0-9a-f]*:[0-9a-f:]+\b/gi, '<ip>')
    .replace(/\d+/g, '#');
  return ['msg', r.module, shape].join('|');
}

export function findingId(signature: string): string {
  return createHash('sha1').update(signature).digest('hex').slice(0, 10);
}

export function toRecord(event: ThreatEvent): AttackRecord {
  const d = event.details ?? {};
  const fromMsg = requestFromMessage(event.message);
  const url = str(d.url) ?? fromMsg.url;
  const path = str(d.path) ?? (url ? url.split('?')[0] : undefined);
  const status = typeof d.status === 'number' ? d.status : undefined;
  const base = {
    module: event.module,
    host: str(d.host),
    method: str(d.method) ?? fromMsg.method,
    path,
    attack_type: str(d.attack_type),
    rule_id: str(d.rule_id),
    message: event.message,
  };
  const timestamp = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp);
  const record: AttackRecord = {
    v: 1,
    id: findingId(signatureOf(base)),
    at: (Number.isNaN(timestamp.getTime()) ? new Date() : timestamp).toISOString(),
    category: event.category,
    severity: event.severity,
    ...base,
    ip: event.source_ip,
    url,
    status,
    outcome: outcomeFor(status),
    crs_score: typeof d.crs_score === 'number' ? d.crs_score : undefined,
    ua: str(d.ua),
  };
  // Drop undefined keys so the log stays greppable and small.
  for (const k of Object.keys(record) as (keyof AttackRecord)[]) {
    if (record[k] === undefined) delete record[k];
  }
  return record;
}

function dedupeKey(r: AttackRecord): string {
  return `${r.at}|${r.ip ?? ''}|${r.message}`;
}

export interface WatchdogStats {
  logged: number;
  answered: number;
  errored: number;
}

/**
 * Appends attacks to the log. Buffered — a scanner can send hundreds a second
 * and a synchronous write per event would stall the render loop — and flushed
 * on `flush()`, which the dashboard calls once a second and on exit.
 */
export class WatchdogLog {
  readonly dir: string;
  readonly file: string;
  private buffer: string[] = [];
  private seen = new Set<string>();
  readonly stats: WatchdogStats = { logged: 0, answered: 0, errored: 0 };

  constructor(dir: string) {
    this.dir = dir;
    this.file = join(dir, LOG_FILE);
    mkdirSync(dir, { recursive: true });
    // Seed from the tail of the existing log, so the 100-event backfill the
    // dashboard does on every (re)connect does not log the same attacks again.
    for (const r of readTail(this.file, 512 * 1024)) this.remember(dedupeKey(r));
  }

  private remember(key: string): void {
    this.seen.add(key);
    if (this.seen.size > SEEN_LIMIT) {
      const oldest = this.seen.values().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
  }

  /** Logs the event if it is an attack not already logged. Returns the record when it was. */
  record(event: ThreatEvent): AttackRecord | null {
    if (!isAttack(event)) return null;
    const rec = toRecord(event);
    const key = dedupeKey(rec);
    if (this.seen.has(key)) return null;
    this.remember(key);
    this.buffer.push(JSON.stringify(rec));
    this.stats.logged++;
    if (rec.outcome === 'answered') this.stats.answered++;
    if (rec.outcome === 'errored') this.stats.errored++;
    return rec;
  }

  flush(): void {
    if (this.buffer.length === 0) return;
    const chunk = this.buffer.join('\n') + '\n';
    this.buffer = [];
    try {
      if (existsSync(this.file) && statSync(this.file).size > ROTATE_BYTES) {
        renameSync(this.file, join(this.dir, ROTATED_FILE));
      }
    } catch { /* rotation is best-effort; appending still works */ }
    appendFileSync(this.file, chunk, { mode: 0o600 });
  }
}

function parseLines(text: string): AttackRecord[] {
  const out: AttackRecord[] = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try {
      const r = JSON.parse(line) as AttackRecord;
      if (r && r.v === 1 && typeof r.id === 'string') out.push(r);
    } catch { /* a torn last line from a crash; skip it */ }
  }
  return out;
}

function readTail(file: string, bytes: number): AttackRecord[] {
  if (!existsSync(file)) return [];
  const fd = openSync(file, 'r');
  try {
    const size = fstatSync(fd).size;
    const start = Math.max(0, size - bytes);
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    let text = buf.toString('utf8');
    // Starting mid-file lands mid-line; drop the partial first line.
    if (start > 0) text = text.slice(text.indexOf('\n') + 1);
    return parseLines(text);
  } finally {
    closeSync(fd);
  }
}

/** Every logged attack, oldest first, rotated file included. */
export function readAttacks(dir: string): AttackRecord[] {
  const out: AttackRecord[] = [];
  for (const name of [ROTATED_FILE, LOG_FILE]) {
    const file = join(dir, name);
    if (existsSync(file)) out.push(...parseLines(readFileSync(file, 'utf8')));
  }
  return out;
}

export function readTriage(dir: string): TriageMap {
  const file = join(dir, TRIAGE_FILE);
  if (!existsSync(file)) return {};
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as TriageMap;
  } catch {
    return {};
  }
}

export function writeTriage(dir: string, map: TriageMap): void {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, TRIAGE_FILE);
  // Write-then-rename so a crash never leaves half a verdict file.
  writeFileSync(`${file}.tmp`, JSON.stringify(map, null, 2) + '\n', { mode: 0o600 });
  renameSync(`${file}.tmp`, file);
}

export function setTriage(
  dir: string,
  id: string,
  update: { status: TriageStatus; note?: string; pr?: string },
  now = new Date(),
): TriageEntry {
  const map = readTriage(dir);
  const prev = map[id];
  const entry: TriageEntry = {
    status: update.status,
    note: update.note ?? prev?.note,
    pr: update.pr ?? prev?.pr,
    updated_at: now.toISOString(),
  };
  if (!entry.note) delete entry.note;
  if (!entry.pr) delete entry.pr;
  map[id] = entry;
  writeTriage(dir, map);
  return entry;
}

const SOURCES_CAP = 20;
const SAMPLES_CAP = 5;

/**
 * Fold the raw log into findings, worst first: the outcome order above, then
 * severity, then volume. Already-triaged findings sort after untriaged ones.
 */
export function groupFindings(records: AttackRecord[], triage: TriageMap = {}): Finding[] {
  const byId = new Map<string, Finding & { _ips: Set<string> }>();
  for (const r of records) {
    let f = byId.get(r.id);
    if (!f) {
      f = {
        id: r.id,
        outcome: r.outcome,
        severity: r.severity,
        count: 0,
        first_seen: r.at,
        last_seen: r.at,
        host: r.host,
        method: r.method,
        path: r.path,
        attack_type: r.attack_type,
        rule_id: r.rule_id,
        module: r.module,
        title: r.message,
        sources: [],
        source_count: 0,
        statuses: {},
        samples: [],
        triage: triage[r.id] ?? { status: 'new', updated_at: r.at },
        _ips: new Set(),
      };
      byId.set(r.id, f);
    }
    f.count++;
    if (r.at < f.first_seen) f.first_seen = r.at;
    if (r.at > f.last_seen) f.last_seen = r.at;
    if (OUTCOME_ORDER.indexOf(r.outcome) < OUTCOME_ORDER.indexOf(f.outcome)) f.outcome = r.outcome;
    if (SEVERITY_RANK[r.severity] > SEVERITY_RANK[f.severity]) f.severity = r.severity;
    if (r.status !== undefined) f.statuses[r.status] = (f.statuses[r.status] ?? 0) + 1;
    if (r.ip && !f._ips.has(r.ip)) {
      f._ips.add(r.ip);
      if (f.sources.length < SOURCES_CAP) f.sources.push(r.ip);
    }
    f.samples.push(r);
  }

  const findings: Finding[] = [];
  for (const f of byId.values()) {
    const { _ips, ...rest } = f;
    rest.source_count = _ips.size;
    // Keep the samples that best show the hole: worst outcome first, newest next.
    rest.samples = rest.samples
      .sort((a, b) => OUTCOME_ORDER.indexOf(a.outcome) - OUTCOME_ORDER.indexOf(b.outcome) || b.at.localeCompare(a.at))
      .slice(0, SAMPLES_CAP);
    findings.push(rest);
  }

  const triaged = (f: Finding) => (f.triage.status === 'new' ? 0 : 1);
  return findings.sort((a, b) =>
    triaged(a) - triaged(b)
    || OUTCOME_ORDER.indexOf(a.outcome) - OUTCOME_ORDER.indexOf(b.outcome)
    || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
    || b.count - a.count
    || b.last_seen.localeCompare(a.last_seen));
}

/** Resolve a full or prefix id; ambiguous or missing prefixes return null. */
export function findFinding(findings: Finding[], id: string): Finding | null {
  const exact = findings.find((f) => f.id === id);
  if (exact) return exact;
  const matches = findings.filter((f) => f.id.startsWith(id));
  return matches.length === 1 ? matches[0] : null;
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** A curl that replays the sample against the vhost it hit. Only meaningful with a host. */
export function reproCommand(r: AttackRecord): string | null {
  if (!r.host || !r.url) return null;
  const method = r.method && r.method !== 'GET' ? ` -X ${r.method}` : '';
  return `curl -sk -o /dev/null -w '%{http_code}\\n'${method} ${shellQuote(`https://${r.host}${r.url}`)}`;
}

/**
 * The hand-off for verifying and fixing one finding: everything an engineer or
 * an agent needs to reproduce it against our own site, decide whether it is a
 * hole, and — if it is — land the fix as a PR. Markdown so it pastes into an
 * issue, a PR body or an agent prompt unchanged.
 */
export function findingBrief(f: Finding): string {
  const lines: string[] = [];
  const where = f.host ? `${f.host} ${f.method ?? ''} ${f.path ?? ''}`.trim() : f.title;
  lines.push(`# Watchdog finding ${f.id}: ${f.attack_type ?? f.rule_id ?? f.module} on ${where}`);
  lines.push('');
  lines.push(`- **Outcome:** ${f.outcome}${outcomeExplainer(f.outcome)}`);
  lines.push(`- **Severity:** ${f.severity} · **hits:** ${f.count} from ${f.source_count} source(s)`);
  lines.push(`- **Seen:** ${f.first_seen} → ${f.last_seen}`);
  const statuses = Object.entries(f.statuses).map(([s, n]) => `${s}×${n}`).join(', ');
  if (statuses) lines.push(`- **Status codes:** ${statuses}`);
  if (f.host) lines.push(`- **Vhost:** ${f.host}`);
  if (f.path) lines.push(`- **Endpoint:** ${f.method ?? ''} ${f.path}`.replace('  ', ' '));
  if (f.rule_id) lines.push(`- **Rule:** ${f.rule_id}`);
  lines.push(`- **Detected by:** ${f.module}`);
  lines.push(`- **Triage:** ${f.triage.status}${f.triage.note ? ` — ${f.triage.note}` : ''}${f.triage.pr ? ` (${f.triage.pr})` : ''}`);
  lines.push('');
  lines.push('## Sample requests');
  lines.push('');
  for (const s of f.samples) {
    lines.push(`- \`${s.at}\` ${s.ip ?? '?'} → ${s.status ?? '—'} \`${(s.method ? `${s.method} ` : '') + (s.url ?? s.message)}\``);
    if (s.ua) lines.push(`  - UA: \`${s.ua}\``);
  }
  const repro = f.samples.map(reproCommand).find(Boolean);
  if (repro) {
    lines.push('');
    lines.push('## Reproduce (against our own site only)');
    lines.push('');
    lines.push('```sh');
    lines.push(repro);
    lines.push('```');
  }
  lines.push('');
  lines.push('## Verify, then fix');
  lines.push('');
  lines.push('1. Find the repo that serves this vhost and the handler for the endpoint above.');
  lines.push('2. Decide whether the request did anything it should not: read the handler, replay the sample against a dev instance, check the response body, not just the status code.');
  lines.push(`3. Not a hole: \`threatcrush watchdog mark ${f.id} fp --note "<why>"\`.`);
  lines.push('4. A hole: write a failing test that sends the sample payload, fix the handler, open a PR with this brief in the body, merge it once checks are green and ship it.');
  lines.push(`5. Record it: \`threatcrush watchdog mark ${f.id} fixed --pr <url>\`.`);
  return lines.join('\n') + '\n';
}

function outcomeExplainer(o: Outcome): string {
  switch (o) {
    case 'answered': return ' — the app served this request (2xx). Verify it did not do what the payload asked.';
    case 'errored': return ' — the app crashed on it (5xx). Input reached code that did not expect it.';
    case 'redirected': return ' — answered with a redirect (3xx); usually auth bouncing it.';
    case 'refused': return ' — refused (4xx). Probably not a hole; kept for the record.';
    default: return ' — not an HTTP request (ssh, network, rule); check the detection itself.';
  }
}
