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
  const userMatch = match[3].match(USER_REGEX);

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
  for (const [type, patterns] of Object.entries(ATTACK_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(path)) {
        return type;
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
  try {
    const cleaned = s.replace(/(\d{2})\/(\w{3})\/(\d{4}):/, '$2 $1, $3 ');
    return new Date(cleaned);
  } catch {
    return new Date();
  }
}

function parseSyslogTimestamp(s: string): Date {
  // "Apr  4 12:00:00" — no year, assume current
  try {
    const withYear = `${s} ${new Date().getFullYear()}`;
    return new Date(withYear);
  } catch {
    return new Date();
  }
}
