import { isIP } from 'node:net';
import type { ParsedLogLine, NginxLogEntry, AuthLogEntry, SyslogEntry, EventSeverity } from '../types/events.js';
import type { DetectionSection } from '../types/config.js';
import { CrsEngine, DEFAULT_EXCLUDED_RULE_IDS, type CrsAssessment } from './crs/engine.js';

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
  return parseAuthMessage(match[2], match[3], parseSyslogTimestamp(match[1]), line);
}

/**
 * The address and user in one auth message body, however it arrived: a line
 * of auth.log (via parseAuthLog) or a journald record's MESSAGE, which has no
 * syslog prefix to strip.
 */
export function parseAuthMessage(process: string, message: string, timestamp: Date, raw = message): AuthLogEntry {
  const ipMatch = message.match(IP_REGEX);
  const userMatch = message.match(INVALID_USER_REGEX) || message.match(USER_REGEX);

  return {
    timestamp,
    raw,
    source: 'auth',
    fields: {
      process,
      message,
      ip: ipMatch?.[1],
      user: userMatch?.[1],
    },
  };
}

/** What an SSH auth message means to the rules: its severity, wording and address. */
export interface SshAuthVerdict {
  severity: EventSeverity;
  message: string;
  source_ip?: string;
  /** For an accepted login: who, how, and with which key (SHA256 fingerprint). */
  details?: Record<string, unknown>;
}

const ACCEPTED_REGEX = /Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: [^\s:]+:\s+(\S+)\s+(SHA256:[A-Za-z0-9+/=]+))?/;

/**
 * `Accepted publickey for anthony from 185.129.61.4 port 65366 ssh2: ED25519
 * SHA256:2Iw+...` → user, method, ip, port, key type and fingerprint.
 */
export function parseAcceptedLogin(message: string): {
  user: string; method: string; ip: string; port: number; key_type?: string; fingerprint?: string;
} | null {
  const m = ACCEPTED_REGEX.exec(message);
  if (!m) return null;
  return {
    method: m[1],
    user: m[2],
    ip: m[3],
    port: Number(m[4]),
    ...(m[5] ? { key_type: m[5] } : {}),
    ...(m[6] ? { fingerprint: m[6] } : {}),
  };
}

const SSHD_PROCESS = /^sshd(?:-session|-auth)?$/;

/** Whether a syslog process name is sshd's (sshd, or OpenSSH 9.8+'s sshd-session). */
export function isSshdProcess(process: string | undefined): boolean {
  return !!process && SSHD_PROCESS.test(process);
}

/**
 * The remote address in ANY sshd message, not only failed and accepted
 * logins: "Connection closed by 1.2.3.4 port 5 [preauth]", "Timeout before
 * authentication for connection from 1.2.3.4 to ...", "banner exchange:
 * Connection from 1.2.3.4 port 5: invalid format", "drop connection #0 from
 * [1.2.3.4]:5 on ...", "Disconnected from user x 1.2.3.4 port 5". The first
 * address in the line is the peer in every sshd message that names one; the
 * box's own address only ever appears after it ("... to 23.95.228.174").
 */
export function sshdPeerIp(message: string): string | null {
  const v4 = /(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])/.exec(message);
  const v6 = /(?:from|by|user \S+|for connection from)\s+\[?([0-9a-fA-F]*:[0-9a-fA-F:]+)\]?/.exec(message);
  const cand = [v4 && { at: v4.index, ip: v4[1] }, v6 && { at: v6.index, ip: v6[1] }]
    .filter((c): c is { at: number; ip: string } => !!c && isIP(c.ip) !== 0)
    .sort((a, b) => a.at - b.at);
  return cand[0]?.ip ?? null;
}

/**
 * Classifies an auth message as a failed login, an invalid user or an accepted
 * login, or null for anything else. The SSH rules match this wording, so every
 * source of sshd messages must go through here to be seen by them.
 */
export function classifySshAuth(entry: AuthLogEntry): SshAuthVerdict | null {
  const { ip, user, message } = entry.fields;
  if (/failed password/i.test(message)) {
    return {
      severity: 'high',
      message: `Failed SSH login for ${user || 'unknown'} from ${ip || 'unknown'}`,
      source_ip: ip,
      ...(user ? { details: { user } } : {}),
    };
  }
  if (/invalid user/i.test(message)) {
    return {
      severity: 'high',
      message: `Invalid SSH user: ${user || 'unknown'} from ${ip || 'unknown'}`,
      source_ip: ip,
      ...(user ? { details: { user } } : {}),
    };
  }
  if (/accepted/i.test(message)) {
    const login = parseAcceptedLogin(message);
    const sourceIp = ip ?? (login && isIP(login.ip) ? login.ip : undefined);
    return {
      severity: 'info',
      message: `SSH login accepted for ${login?.user || user || 'unknown'}`,
      source_ip: sourceIp,
      ...(login ? { details: { user: login.user, ssh_user: login.user, auth_method: login.method, port: login.port, ...(login.key_type ? { key_type: login.key_type } : {}), ...(login.fingerprint ? { fingerprint: login.fingerprint } : {}) } } : {}),
    };
  }
  return null;
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
// what an access log records, plus ThreatCrush's own rules (see ./crs). A
// request is an attack when its anomaly score reaches the threshold — by
// default one CRITICAL rule.
let crsEngine: CrsEngine | undefined;

/**
 * Applies `[detection]` (threshold, rule exclusions); call before the first line.
 * Off: the default exclusions, minus `include_rules`, plus `exclude_rules`.
 */
export function configureAttackDetection(section: DetectionSection | undefined): void {
  const threshold = section?.anomaly_threshold;
  const included = Array.isArray(section?.include_rules) ? section.include_rules.map(Number) : [];
  crsEngine = new CrsEngine({
    threshold: typeof threshold === 'number' && threshold > 0 ? threshold : undefined,
    excludeRuleIds: [
      ...DEFAULT_EXCLUDED_RULE_IDS.filter((id) => !included.includes(id)),
      ...(Array.isArray(section?.exclude_rules) ? section.exclude_rules.map(Number) : []),
    ],
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
