import type { ParsedLogLine, NginxLogEntry, AuthLogEntry, SyslogEntry } from '../types/events.js';

// Nginx combined log format:
// 127.0.0.1 - - [04/Apr/2026:12:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
const NGINX_REGEX = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+) "[^"]*" "([^"]*)"/;

// Auth.log format:
// Apr  4 12:00:00 hostname sshd[1234]: Failed password for user from 1.2.3.4 port 22 ssh2
const AUTH_REGEX = /^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)/;

// Syslog format:
// Apr  4 12:00:00 hostname process[pid]: message
const SYSLOG_REGEX = /^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)/;

// Extract IP from auth messages
const IP_REGEX = /(?:from|FROM)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
const INVALID_USER_REGEX = /(?:for\s+invalid\s+user)\s+(\S+?)(?:\s+from|\s*$)/;
const USER_REGEX = /(?:for|user)\s+(\S+?)(?:\s+from|\s*$)/;

// Attack pattern signatures
export const ATTACK_PATTERNS = {
  sqli: [
    /(?:union\s+(?:all\s+)?select)/i,
    /(?:select\s+.*\s+from\s+)/i,
    /(?:insert\s+into\s+)/i,
    /(?:drop\s+(?:table|database))/i,
    /(?:or\s+1\s*=\s*1)/i,
    /(?:'\s*(?:or|and)\s+')/i,
    /(?:--\s*$|;\s*--)/,
    /(?:\/\*.*\*\/)/,
  ],
  xss: [
    /<script[^>]*>/i,
    /javascript\s*:/i,
    /on(?:load|error|click|mouseover)\s*=/i,
    /eval\s*\(/i,
    /document\.(?:cookie|write|location)/i,
  ],
  path_traversal: [
    /\.\.\//,
    /\.\.\\/, 
    /etc\/(?:passwd|shadow|hosts)/,
    /proc\/self/,
    /windows\/system32/i,
  ],
  rfi: [
    /(?:https?|ftp):\/\/.*\?/i,
    /php:\/\/(?:input|filter)/i,
    /data:\/\//i,
  ],
};

export function parseNginxLog(line: string): NginxLogEntry | null {
  const match = line.match(NGINX_REGEX);
  if (!match) return null;

  return {
    timestamp: parseNginxTimestamp(match[2]),
    raw: line,
    source: 'nginx',
    fields: {
      ip: match[1],
      method: match[3],
      path: match[4],
      status: match[5],
      size: match[6],
      user_agent: match[7],
    },
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

export function detectAttackPattern(path: string): string | null {
  // nginx logs the request URI URL-encoded, so raw signatures like `<script`
  // or `or 1=1` never match an encoded payload (e.g. `%3Cscript%3E`,
  // `%27%20OR%201=1`). Test the raw value AND its URL-decoded forms so that
  // single- and double-encoded payloads are still caught. decodeURIComponent
  // throws on a malformed `%` sequence, so guard each decode.
  const candidates = new Set<string>([path]);
  let current = path;
  for (let i = 0; i < 2; i++) {
    let decoded: string | null = null;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      decoded = null;
    }
    if (decoded === null || decoded === current) break;
    candidates.add(decoded);
    current = decoded;
  }

  for (const [type, patterns] of Object.entries(ATTACK_PATTERNS)) {
    for (const pattern of patterns) {
      for (const candidate of candidates) {
        if (pattern.test(candidate)) {
          return type;
        }
      }
    }
  }
  return null;
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
