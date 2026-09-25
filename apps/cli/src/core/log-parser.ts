import type { ParsedLogLine, NginxLogEntry, AuthLogEntry, SyslogEntry, EventSeverity } from '../types/events.js';
import type { DetectionSection } from '../types/config.js';
import { CrsEngine, type CrsAssessment } from './crs/engine.js';

// Nginx combined log format:
// 127.0.0.1 - - [04/Apr/2026:12:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
//
// The leading group is an optional `$host`. Stock `combined` does not record
// which vhost served a request, so on a box with more than one site the log
// cannot say where a hit landed — and neither can we. When the operator adds
// `$host` to the format (see docs/nginx-vhost-logging.md) we pick it up and
// the dashboard starts naming the site. Optional, so both formats parse.
const NGINX_REGEX = /^(?:(\S+) )?(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"/;

// Auth.log, in either timestamp format:
//   Apr  4 12:00:00 host sshd[1234]: Failed password for root from 1.2.3.4 …
//   2026-09-25T09:23:31.141344+00:00 host sshd-session[84073]: Accepted publickey …
//
// The second is what rsyslog has written by default since Debian 12 / Ubuntu
// 24.04. Matching only the first meant ssh-guard parsed *nothing* on a modern
// box: every auth line was dropped, the module sat at zero events, and SSH
// brute force — the single thing it exists to catch — went unseen.
const TIMESTAMP = String.raw`(\w{3}\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)`;
const AUTH_REGEX = new RegExp(`^${TIMESTAMP}\\s+\\S+\\s+(\\S+?)(?:\\[\\d+\\])?:\\s+(.*)`);

// Syslog format: the same shape, same two spellings.
const SYSLOG_REGEX = new RegExp(`^${TIMESTAMP}\\s+\\S+\\s+(\\S+?)(?:\\[\\d+\\])?:\\s+(.*)`);

// Extract IP from auth messages
const IP_REGEX = /(?:from|FROM)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
const INVALID_USER_REGEX = /(?:for\s+invalid\s+user)\s+(\S+?)(?:\s+from|\s*$)/;
const USER_REGEX = /(?:for|user)\s+(\S+?)(?:\s+from|\s*$)/;

export function parseNginxLog(line: string): NginxLogEntry | null {
  const match = line.match(NGINX_REGEX);
  if (!match) return null;

  const fields: Record<string, string> = {
    ip: match[2],
    method: match[4],
    path: match[5],
    protocol: match[6],
    status: match[7],
    size: match[8],
    referer: match[9],
    user_agent: match[10],
  };
  // Only present when the operator added `$host` to the log format.
  if (match[1]) fields.host = match[1];

  return {
    timestamp: parseNginxTimestamp(match[3]),
    raw: line,
    source: 'nginx',
    fields: fields as NginxLogEntry['fields'],
  };
}

export function parseAuthLog(line: string): AuthLogEntry | null {
  const match = line.match(AUTH_REGEX);
  if (!match) return null;

  const ipMatch = match[3].match(IP_REGEX);
  const userMatch = match[3].match(INVALID_USER_REGEX) || match[3].match(USER_REGEX);

  return {
    timestamp: parseSyslogTimestamp(match[1]),
    raw: line,
    source: 'auth',
    fields: {
      process: match[2],
      message: match[3],
      ip: ipMatch?.[1],
      user: userMatch?.[1],
    },
  };
}

export function parseSyslog(line: string): SyslogEntry | null {
  const match = line.match(SYSLOG_REGEX);
  if (!match) return null;

  return {
    timestamp: parseSyslogTimestamp(match[1]),
    raw: line,
    source: 'syslog',
    fields: {
      facility: 'syslog',
      process: match[2],
      message: match[3],
    },
  };
}

// Web attack detection: the OWASP Core Rule Set, paranoia level 1, ported to
// what an access log records (see ./crs). A request is an attack when its
// anomaly score reaches the threshold — by default one CRITICAL rule.
let crsEngine: CrsEngine | undefined;

/** Applies `[detection]` (threshold, rule exclusions); call before the first line. */
export function configureAttackDetection(section: DetectionSection | undefined): void {
  const threshold = section?.anomaly_threshold;
  crsEngine = new CrsEngine({
    threshold: typeof threshold === 'number' && threshold > 0 ? threshold : undefined,
    excludeRuleIds: Array.isArray(section?.exclude_rules) ? section.exclude_rules.map(Number) : undefined,
  });
}

function engine(): CrsEngine {
  crsEngine ??= new CrsEngine();
  return crsEngine;
}

/**
 * nginx writes `"`, `\` and bytes outside printable ASCII as `\xHH`. Undo that
 * so the rules see the request's bytes, one char per byte.
 */
function loggedBytes(field: string): string {
  const bytes = /[^\x00-\x7f]/.test(field) ? Buffer.from(field, 'utf8').toString('latin1') : field;
  return bytes.includes('\\x') ? bytes.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16))) : bytes;
}

/** Scores a logged request: its request line, User-Agent and Referer. */
export function assessNginxRequest(entry: NginxLogEntry): CrsAssessment {
  const { method, path, protocol, user_agent, referer } = entry.fields;
  return engine().assess({
    method,
    uri: loggedBytes(path),
    protocol,
    // nginx logs an absent header as `-`.
    userAgent: user_agent && user_agent !== '-' ? loggedBytes(user_agent) : undefined,
    referer: referer && referer !== '-' ? loggedBytes(referer) : undefined,
  });
}

/**
 * The event severity an assessment earns, or null below the threshold. At the
 * threshold it is `high`, which the default `min_severity` bans on; at twice
 * the threshold (two or more CRITICAL rules) it is `critical`, so an operator
 * who wants more evidence before a ban can set `min_severity = "critical"`.
 */
export function attackSeverity(assessment: CrsAssessment): EventSeverity | null {
  if (assessment.score >= 2 * assessment.threshold) return 'critical';
  if (assessment.score >= assessment.threshold) return 'high';
  return null;
}

/** The attack type of a request path when it reaches the threshold, else null. */
export function detectAttackPattern(path: string): string | null {
  const assessment = engine().assess({ uri: loggedBytes(path) });
  return assessment.score >= assessment.threshold ? assessment.attackType : null;
}

export function autoDetectParser(line: string): ParsedLogLine | null {
  // Try nginx first (most specific format)
  const nginx = parseNginxLog(line);
  if (nginx) return nginx;

  // Try auth log
  const auth = parseAuthLog(line);
  if (auth) return auth;

  // Fall back to generic syslog
  return parseSyslog(line);
}

function parseNginxTimestamp(s: string): Date {
  // "04/Apr/2026:12:00:00 +0000"
  // new Date(<unparseable>) returns an Invalid Date instead of throwing, so the
  // old try/catch never triggered and an Invalid Date leaked into downstream
  // time-window logic. Check getTime() explicitly and fall back to now.
  const cleaned = s.replace(/(\d{2})\/(\w{3})\/(\d{4}):/, '$2 $1, $3 ');
  const d = new Date(cleaned);
  return Number.isNaN(d.getTime()) ? new Date() : d;
}

function parseSyslogTimestamp(s: string): Date {
  // RFC3339 ("2026-09-25T09:23:31.141344+00:00") carries its own year and zone,
  // so it needs none of the guessing below.
  if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
    const iso = new Date(s);
    return Number.isNaN(iso.getTime()) ? new Date() : iso;
  }

  // "Apr  4 12:00:00" — no year. Assume the most recent year that is not in the
  // future, so a December log parsed in early January is dated to the previous
  // year rather than the current one.
  const now = new Date();
  let d = new Date(`${s} ${now.getFullYear()}`);
  if (Number.isNaN(d.getTime())) return now;
  if (d.getTime() > now.getTime()) {
    const prev = new Date(`${s} ${now.getFullYear() - 1}`);
    if (!Number.isNaN(prev.getTime())) d = prev;
  }
  return d;
}
