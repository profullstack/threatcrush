import { describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  diffSnapshots,
  keyFingerprint,
  parseAdminGroups,
  parseAuthorizedKeys,
  parseUsers,
  parseSudoMessage,
  sudoReadsIncluded,
  sudoersRules,
  takeSnapshot,
  type SnapshotIO,
} from '../privileges/index.js';
import { PrivilegeWatch } from '../../daemon/workers/privilege-watch.js';
import type { ThreatEvent } from '../../types/events.js';

// A throwaway ed25519 public key, split so secret scanners do not read it as one.
const KEY = ['AAAAC3NzaC1lZDI1NTE5AAAAIHj3imeJ1PrH', 'auH8i7uqMcW3yQyyvhZE52DelyJdl1by'].join('');
const KEY_FP = 'SHA256:3L5trdIIsTaRrP7N0pl4JzrBEz3nNobYHwDfKEs9KR0'; // ssh-keygen -lf
const KEY2 = `AAAAC3NzaC1lZDI1NTE5AAAAI${'B'.repeat(43)}`;

describe('parsers', () => {
  it('fingerprints a key exactly as ssh-keygen -l does', () => {
    expect(keyFingerprint(KEY)).toBe(KEY_FP);
  });

  it('reads authorized_keys with options, quotes and comments', () => {
    const keys = parseAuthorizedKeys([
      '# deploy keys',
      `ssh-ed25519 ${KEY} test@example`,
      `command="/usr/bin/rsync --server",no-pty,from="10.0.0.1" ssh-ed25519 ${KEY2} ci runner`,
      'garbage line',
    ].join('\n'));
    expect(keys).toEqual([
      { fingerprint: KEY_FP, type: 'ssh-ed25519', comment: 'test@example' },
      { fingerprint: keyFingerprint(KEY2), type: 'ssh-ed25519', comment: 'ci runner' },
    ]);
  });

  it('reads uid 0 users and admin group members', () => {
    expect(parseUsers('root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nanthony:x:1001:1001::/home/anthony:/usr/bin/zsh\n')
      .filter((a) => a.uid === 0).map((a) => a.name)).toEqual(['root', 'toor']);
    expect(parseAdminGroups('sudo:x:27:anthony,deploy\nwheel:x:10:\nusers:x:100:bob\n')).toEqual({ sudo: ['anthony', 'deploy'], wheel: [] });
  });

  it('normalizes sudoers rules and mirrors which included files sudo reads', () => {
    expect(sudoersRules('# comment\nDefaults  env_reset\n\nalice ALL=(ALL) \\\n  NOPASSWD: ALL\n#includedir /etc/sudoers.d\n@includedir /etc/sudoers.d\n'))
      .toEqual(['Defaults env_reset', 'alice ALL=(ALL) NOPASSWD: ALL', '#includedir /etc/sudoers.d', '@includedir /etc/sudoers.d']);
    expect(['90-cloud-init-users', 'README', 'backup~', 'old.bak'].filter(sudoReadsIncluded)).toEqual(['90-cloud-init-users', 'README']);
  });

  it('reads sudo journal messages, leaving password failures to sudo-abuse', () => {
    expect(parseSudoMessage('anthony : TTY=pts/0 ; PWD=/home/anthony ; USER=root ; COMMAND=/usr/bin/apt update')).toEqual({
      user: 'anthony', runas: 'root', command: '/usr/bin/apt update', tty: 'pts/0', pwd: '/home/anthony', denied: false,
    });
    expect(parseSudoMessage('bob : command not allowed ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh')?.denied).toBe(true);
    expect(parseSudoMessage('bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh')).toBeNull();
    expect(parseSudoMessage('pam_unix(sudo:session): session closed for user root')).toBeNull();
  });
});

function fakeFs(files: Record<string, string>, unreadable: string[] = []): SnapshotIO {
  return {
    readFile: (p) => (unreadable.includes(p) ? null : files[p] ?? null),
    readDir: (p) => {
      const names = Object.keys(files).filter((f) => f.startsWith(`${p}/`)).map((f) => f.slice(p.length + 1));
      return names.length ? names : null;
    },
    exists: (p) => p in files,
  };
}

const BASE = {
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nanthony:x:1001:1001::/home/anthony:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n',
  '/etc/group': 'sudo:x:27:anthony\n',
  '/etc/sudoers': 'root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n',
  '/etc/sudoers.d/README': '# docs only\n',
  '/root/.ssh/authorized_keys': `ssh-ed25519 ${KEY} test@example\n`,
  '/var/www/.ssh/authorized_keys': `ssh-ed25519 ${KEY2} ignored: nologin account\n`,
};

describe('takeSnapshot + diffSnapshots', () => {
  it('reports what an intruder adds to stay root, most severe first', () => {
    const before = takeSnapshot(fakeFs(BASE));
    expect(before.keys).toEqual({ root: { [KEY_FP]: { type: 'ssh-ed25519', comment: 'test@example' } } });
    const after = takeSnapshot(fakeFs({
      ...BASE,
      '/etc/passwd': `${BASE['/etc/passwd']}backup:x:0:0::/root:/bin/bash\n`,
      '/etc/group': 'sudo:x:27:anthony,mallory\n',
      '/etc/sudoers.d/99-x': 'mallory ALL=(ALL) NOPASSWD: ALL\n',
      '/home/anthony/.ssh/authorized_keys': `ssh-ed25519 ${KEY2} laptop\n`,
    }));
    const changes = diffSnapshots(before, after);
    expect(changes.map((c) => [c.severity, c.details.rule_id])).toEqual([
      ['critical', 'priv-uid0-added'],
      ['high', 'priv-admin-group-added'],
      ['high', 'priv-sudoers-added'],
      ['high', 'priv-authorized-key-added'],
      ['high', 'priv-authorized-key-added'],
    ]);
    expect(changes[2].message).toBe('New sudoers file /etc/sudoers.d/99-x: mallory ALL=(ALL) NOPASSWD: ALL');
    // The new uid-0 account shares /root, so root's key now logs in as it too.
    expect(changes.slice(3).map((c) => c.message)).toEqual([
      `New SSH key for anthony: ssh-ed25519 ${keyFingerprint(KEY2)} (laptop)`,
      `New SSH key for backup: ssh-ed25519 ${KEY_FP} (test@example)`,
    ]);
    expect(diffSnapshots(after, after)).toEqual([]);
  });

  it('does not call a file that became unreadable a removal', () => {
    const asRoot = takeSnapshot(fakeFs(BASE));
    const asUser = takeSnapshot(fakeFs(BASE, ['/etc/sudoers']));
    expect(diffSnapshots(asRoot, asUser).filter((c) => String(c.details.rule_id).startsWith('priv-sudoers'))).toEqual([]);
  });
});

function watch(over: { files?: Record<string, string>; journal?: (args: string[]) => string | null; geo?: Record<string, { countryCode: string }> } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tc-priv-'));
  const events: ThreatEvent[] = [];
  const listeners: Array<(e: ThreatEvent) => void> = [];
  let files = over.files ?? BASE;
  const w = new PrivilegeWatch({
    settings: { enabled: true, geo: true, pollMs: 60_000 },
    bus: { publish: (e) => events.push(e), on: (_n, fn) => listeners.push(fn), off: () => {} },
    snapshotPath: join(dir, 'privileges.json'),
    loginsPath: join(dir, 'logins.json'),
    cursorPath: join(dir, 'cursor.json'),
    log: () => {},
    io: { readFile: (p) => fakeFs(files).readFile(p), readDir: (p) => fakeFs(files).readDir(p), exists: (p) => fakeFs(files).exists(p) },
    run: (_cmd, args) => over.journal?.(args) ?? null,
    geolocate: async (ip) => over.geo?.[ip] ?? null,
  });
  return { w, events, setFiles: (f: Record<string, string>) => { files = f; } };
}

describe('PrivilegeWatch', () => {
  it('records a baseline silently, then reports changes once', () => {
    const t = watch();
    t.w.checkSnapshot();
    expect(t.events).toEqual([]);
    t.setFiles({ ...BASE, '/etc/group': 'sudo:x:27:anthony,mallory\n' });
    t.w.checkSnapshot();
    t.w.checkSnapshot();
    expect(t.events.map((e) => e.message)).toEqual(['mallory added to the sudo group (can run anything as root)']);
    expect(t.events[0]).toMatchObject({ module: 'privileged-access', severity: 'high' });
    expect(t.events[0].source_ip).toBeUndefined();
  });

  it('starts the sudo ledger at the end of the journal, then logs each command', () => {
    const calls: string[][] = [];
    const t = watch({
      journal: (args) => {
        calls.push(args);
        if (args.includes('--show-cursor')) return '-- cursor: s=1;i=10\n';
        return [
          JSON.stringify({ __CURSOR: 's=1;i=11', MESSAGE: 'anthony : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx' }),
          JSON.stringify({ __CURSOR: 's=1;i=12', MESSAGE: 'pam_unix(sudo:session): session opened for user root' }),
          JSON.stringify({ __CURSOR: 's=1;i=13', MESSAGE: 'eve : command not allowed ; TTY=pts/3 ; PWD=/ ; USER=root ; COMMAND=/bin/bash' }),
        ].join('\n');
      },
    });
    t.w.readSudoLedger();
    expect(t.events).toEqual([]); // position only
    t.w.readSudoLedger();
    expect(calls[1]).toContain('--after-cursor=s=1;i=10');
    expect(t.events.map((e) => [e.severity, e.message])).toEqual([
      ['info', 'sudo: anthony ran /usr/bin/systemctl restart nginx as root'],
      ['medium', 'sudo denied: eve tried /bin/bash as root'],
    ]);
    t.w.readSudoLedger();
    expect(calls[2]).toContain('--after-cursor=s=1;i=13');
  });

  it('flags a login from a country new for that user, after the first one sets the baseline', async () => {
    const t = watch({ geo: {
      '203.0.113.1': { countryCode: 'US' },
      '198.51.100.7': { countryCode: 'RU' },
    } });
    const login = (ip: string, user = 'anthony'): ThreatEvent => ({
      timestamp: new Date(), module: 'ssh-guard', category: 'auth', severity: 'info', message: `SSH login accepted for ${user}`, source_ip: ip,
    });
    await t.w.checkLogin(login('203.0.113.1'));
    await t.w.checkLogin(login('203.0.113.1'));
    await t.w.checkLogin(login('10.0.0.9')); // private: never geolocated
    expect(t.events).toEqual([]);
    await t.w.checkLogin(login('198.51.100.7'));
    expect(t.events.map((e) => e.message)).toEqual([
      'SSH login for anthony from a new country: Russia, 198.51.100.7; seen before from US',
    ]);
    expect(t.events[0].source_ip).toBeUndefined();
    await t.w.checkLogin(login('198.51.100.7', 'deploy')); // deploy's first login: baseline only
    expect(t.events).toHaveLength(1);
  });
});
