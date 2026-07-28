import { describe, expect, it } from 'vitest';
import {
  checkComposeFile,
  checkDebugSettings,
  checkMode,
  checkWebserverConfig,
  parseWebRoots,
  rankFindings,
  sensitiveInWebroot,
} from '../config/index.js';

describe('sensitive files in a web root', () => {
  it('recognises what must never be served, and says what it is', () => {
    // The finding says "environment file", not a rule id — an operator should
    // not have to look anything up.
    expect(sensitiveInWebroot('.env')).toBe('environment file');
    expect(sensitiveInWebroot('.env.production')).toBe('environment file');
    expect(sensitiveInWebroot('.git')).toBe('git directory');
    expect(sensitiveInWebroot('dump.sql')).toBe('database dump');
    expect(sensitiveInWebroot('config.php.bak')).toBe('backup file');
    expect(sensitiveInWebroot('id_rsa')).toBe('private key');
    expect(sensitiveInWebroot('docker-compose.yml')).toBe('compose file');
  });

  it('leaves ordinary web content alone', () => {
    for (const name of ['index.html', 'app.js', 'logo.png', 'styles.css']) {
      expect(sensitiveInWebroot(name), name).toBeNull();
    }
  });
});

describe('web root inference', () => {
  it('reads nginx root directives', () => {
    const conf = ['server {', '  listen 80;', '  root /var/www/html;', '}'].join('\n');
    expect(parseWebRoots(conf)).toEqual(['/var/www/html']);
  });

  it('reads Apache DocumentRoot', () => {
    expect(parseWebRoots('DocumentRoot /srv/www/app')).toEqual(['/srv/www/app']);
  });

  it('ignores commented directives', () => {
    // Getting this wrong invents a web root nobody serves, and then reports
    // confident findings about files that are not reachable.
    expect(parseWebRoots('# root /old/path;\nroot /new/path;')).toEqual(['/new/path']);
  });

  it('strips quotes', () => {
    expect(parseWebRoots('DocumentRoot "/var/www/html"')).toEqual(['/var/www/html']);
  });

  it('returns nothing rather than guessing when there is nothing to read', () => {
    // The caller must then report `unknown`, not "nothing exposed".
    expect(parseWebRoots('server { listen 80; }')).toEqual([]);
  });
});

describe('permissions', () => {
  it('flags a world-writable directory as higher risk than a file', () => {
    const dir = checkMode({ path: '/srv/app', mode: 0o777, isDirectory: true });
    const file = checkMode({ path: '/srv/app/x.js', mode: 0o666, isDirectory: false });
    expect(dir?.severity).toBe('high');
    expect(file?.severity).toBe('medium');
  });

  it('flags world-readable credentials and says to rotate them', () => {
    const finding = checkMode({ path: '/srv/app/.env', mode: 0o644, isDirectory: false });
    expect(finding?.checkId).toBe('credentials-world-readable');
    // Changing the mode is only half of remediation.
    expect(finding?.remediation).toMatch(/rotate/i);
  });

  it('stays quiet on sane modes', () => {
    expect(checkMode({ path: '/srv/app/.env', mode: 0o600, isDirectory: false })).toBeNull();
    expect(checkMode({ path: '/srv/app', mode: 0o755, isDirectory: true })).toBeNull();
  });
});

describe('debug settings', () => {
  it('detects framework debug flags', () => {
    expect(checkDebugSettings('/srv/.env', 'APP_DEBUG=true')[0]?.checkId).toBe('debug-enabled');
    expect(checkDebugSettings('/srv/.env', 'NODE_ENV=development')).toHaveLength(1);
    expect(checkDebugSettings('/srv/.env', 'DEBUG=1')).toHaveLength(1);
  });

  it('stays quiet on production values', () => {
    expect(checkDebugSettings('/srv/.env', 'NODE_ENV=production\nAPP_DEBUG=false')).toHaveLength(0);
  });
});

describe('container configuration', () => {
  it('flags privileged containers as critical', () => {
    const found = checkComposeFile('/srv/docker-compose.yml', 'services:\n  a:\n    privileged: true');
    expect(found[0]?.checkId).toBe('container-privileged');
    expect(found[0]?.severity).toBe('critical');
  });

  it('flags a mounted Docker socket as critical', () => {
    const found = checkComposeFile(
      '/srv/docker-compose.yml',
      'volumes:\n  - /var/run/docker.sock:/var/run/docker.sock',
    );
    expect(found.map((f) => f.checkId)).toContain('docker-socket-mounted');
    // Socket access is root on the host; the text should not undersell it.
    expect(found[0]?.consequence).toMatch(/root/i);
  });

  it('flags host networking and SYS_ADMIN', () => {
    expect(
      checkComposeFile('/c.yml', 'network_mode: host').map((f) => f.checkId),
    ).toContain('container-host-network');
    expect(
      checkComposeFile('/c.yml', 'cap_add:\n  - SYS_ADMIN').map((f) => f.checkId),
    ).toContain('container-sys-admin');
  });

  it('ignores commented-out settings', () => {
    expect(checkComposeFile('/c.yml', '# privileged: true')).toHaveLength(0);
  });

  it('stays quiet on an ordinary compose file', () => {
    const ordinary = ['services:', '  web:', '    image: nginx', '    ports:', '      - "80:80"'].join(
      '\n',
    );
    expect(checkComposeFile('/c.yml', ordinary)).toHaveLength(0);
  });
});

describe('webserver configuration', () => {
  it('flags directory listing', () => {
    expect(checkWebserverConfig('/etc/nginx/nginx.conf', 'autoindex on;')[0]?.checkId).toBe(
      'directory-listing',
    );
  });

  it('only flags CORS when the wildcard is combined with credentials', () => {
    // Each is defensible alone; together any site can make authenticated
    // requests with a visitor's session.
    const wildcardOnly = checkWebserverConfig('/c', "add_header Access-Control-Allow-Origin *;");
    expect(wildcardOnly).toHaveLength(0);

    const both = checkWebserverConfig(
      '/c',
      "add_header Access-Control-Allow-Origin *;\nadd_header Access-Control-Allow-Credentials true;",
    );
    expect(both.map((f) => f.checkId)).toContain('cors-wildcard-with-credentials');
  });

  it('stays quiet on a normal config', () => {
    expect(checkWebserverConfig('/c', 'server { listen 80; autoindex off; }')).toHaveLength(0);
  });
});

describe('ranking', () => {
  it('puts exposed findings above local ones regardless of severity', () => {
    // Reachability sets the deadline: an exposed medium is more urgent than a
    // local critical that needs shell access first.
    const ranked = rankFindings([
      {
        checkId: 'a',
        title: 'local critical',
        subject: '/a',
        reachability: 'local',
        severity: 'critical',
        consequence: '',
        remediation: '',
      },
      {
        checkId: 'b',
        title: 'exposed medium',
        subject: '/b',
        reachability: 'exposed',
        severity: 'medium',
        consequence: '',
        remediation: '',
      },
    ]);
    expect(ranked[0]?.checkId).toBe('b');
  });
});

describe('every finding is actionable', () => {
  it('carries a remediation and a consequence', () => {
    // A rule added without these is the beginning of the compliance-checklist
    // failure mode this subsystem exists to avoid.
    const all = [
      ...checkComposeFile('/c.yml', 'privileged: true\nnetwork_mode: host'),
      ...checkDebugSettings('/srv/.env', 'APP_DEBUG=true'),
      ...checkWebserverConfig('/c', 'autoindex on;'),
      checkMode({ path: '/srv/app', mode: 0o777, isDirectory: true })!,
    ];

    for (const finding of all) {
      expect(finding.remediation.length, finding.checkId).toBeGreaterThan(10);
      expect(finding.consequence.length, finding.checkId).toBeGreaterThan(20);
    }
  });
});
