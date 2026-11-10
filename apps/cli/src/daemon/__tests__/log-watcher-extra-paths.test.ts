import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { configuredWebSources, DEFAULT_SOURCES } from '../watchers/log-watcher.js';
import { parseNginxLog } from '../../core/log-parser.js';

function dirs() {
  const root = mkdtempSync(join(tmpdir(), 'tc-lw-'));
  const confD = join(root, 'threatcrushd.conf.d');
  mkdirSync(confD);
  return { root, confD, configFile: join(root, 'threatcrushd.conf') };
}

describe('configuredWebSources', () => {
  it('reads [modules.log-watcher] paths from the main config (the documented form)', () => {
    const d = dirs();
    writeFileSync(d.configFile, '[modules.log-watcher]\npaths = ["/var/log/nginx/site.access.log"]\n');
    expect(configuredWebSources(d.configFile, d.confD)).toEqual([
      { path: '/var/log/nginx/site.access.log', module: 'log-watcher', category: 'web' },
    ]);
  });

  it('merges [log-watcher] paths across conf.d drop-ins instead of keeping the last file', () => {
    const d = dirs();
    writeFileSync(join(d.confD, 'a-site.conf'), '[log-watcher]\npaths = ["/srv/a.log"]\n');
    writeFileSync(join(d.confD, 'c0mpute.conf'), '[log-watcher]\npaths = ["/home/u/.local/share/c0mpute/gateway/access.log"]\n');
    const got = configuredWebSources(d.configFile, d.confD).map((s) => s.path);
    expect(got).toEqual(['/srv/a.log', '/home/u/.local/share/c0mpute/gateway/access.log']);
  });

  it('skips defaults, duplicates, relative paths, and malformed files', () => {
    const d = dirs();
    writeFileSync(join(d.confD, 'bad.conf'), '[log-watcher\npaths = [');
    writeFileSync(join(d.confD, 'x.conf'), `[log-watcher]\npaths = ["${DEFAULT_SOURCES[2].path}", "rel.log", "/x.log", "/x.log"]\n`);
    expect(configuredWebSources(d.configFile, d.confD).map((s) => s.path)).toEqual(['/x.log']);
  });

  it('returns nothing when neither exists', () => {
    expect(configuredWebSources('/nonexistent/tc.conf', '/nonexistent/conf.d')).toEqual([]);
  });
});

describe('c0mpute gateway access log lines', () => {
  it('parse as nginx vhost lines (host:port, v4 and v6 clients)', () => {
    const v4 = parseNginxLog(
      'gw.example:7777 45.33.22.11 - - [10/Nov/2026:13:55:36 +0000] "GET /s/53021d6e8d5a0e1aac48/?q=\\x22x\\x22 HTTP/1.1" 402 614 "-" "GPTBot/1.2"',
    );
    expect(v4?.fields.host).toBe('gw.example:7777');
    expect(v4?.fields.ip).toBe('45.33.22.11');
    expect(v4?.fields.status).toBe('402');
    const v6 = parseNginxLog(
      '152.53.47.37:7777 2a0e:97c0:3ea:b8::1 - - [10/Nov/2026:13:55:36 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "curl/8.5.0"',
    );
    expect(v6?.fields.ip).toBe('2a0e:97c0:3ea:b8::1');
  });
});
