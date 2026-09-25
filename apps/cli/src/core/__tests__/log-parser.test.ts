import { describe, it, expect } from 'vitest';
import { detectAttackPattern, parseAuthLog, parseNginxLog } from '../log-parser.js';

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

describe('detectAttackPattern', () => {
  it('still catches real remote file inclusion', () => {
    expect(detectAttackPattern('/index.php?page=http://evil.tld/shell.txt')).toBe('rfi');
    expect(detectAttackPattern('/?f=php://input')).toBe('rfi');
  });

  it('does not call a URL in a query parameter an attack', () => {
    // rssamplifier.com serves exactly this shape to ordinary readers. Flagging
    // it CRITICAL meant auto-defence would ban them.
    expect(
      detectAttackPattern('/noticias8islas-com/read?p=https%3A%2F%2Fnoticias8islas.com%2F%3Fp%3D79855'),
    ).toBeNull();
    expect(detectAttackPattern('/share?url=https://example.com/post?id=1')).toBeNull();
  });

  it('still catches the other families', () => {
    expect(detectAttackPattern('/search?q=1%27+OR+1%3D1')).toBe('sqli');
    expect(detectAttackPattern('/../../etc/passwd')).toBe('path_traversal');
    expect(detectAttackPattern('/x?q=%3Cscript%3Ealert(1)%3C/script%3E')).toBe('xss');
  });

  it('leaves ordinary paths alone', () => {
    expect(detectAttackPattern('/topics/rochester/podcasts.rss')).toBeNull();
    expect(detectAttackPattern('/~anthony/blog/139-post.html')).toBeNull();
  });
});
