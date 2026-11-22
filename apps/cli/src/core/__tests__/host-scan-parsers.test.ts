import { describe, expect, it } from 'vitest';
import {
  expandAuthorizedKeysFiles, groupMembers, isRkhunterRootkitWarning, isUnrestrictedKey, judgeDockerInspect,
  judgeKeyPlacement, judgePackageVerify, judgeSshdConfig, keyFingerprint, keyIsDenied, parseAuthorizedKeys, parseChkrootkit,
  parseDenyList, parseDpkgSearch, parsePackageVerify, parsePasswd, parseProcModules, parseRkhunter, parseSince,
  parseSshdT, parseUnhide, uidZeroNonRoot,
} from '../host-scan/parsers.js';
import { checkLdPreload, checkUidZero } from '../host-scan/checks.js';

const DPKG_VERIFY = `??5?????? c /etc/default/motd-news
?????????   /boot/vmlinuz-7.0.0-43-generic
??5?????? c /etc/login.defs
??5??????   /usr/bin/ps
??5??????   /usr/sbin/sshd
??5??????   /usr/lib/x86_64-linux-gnu/security/pam_unix.so
??5??????   /usr/lib/x86_64-linux-gnu/libprocps.so.8.0.4
??5??????   /usr/lib/python3/dist-packages/foo/bar.py
??5??????   /usr/share/doc/foo/README
missing     /usr/bin/netstat
missing     /etc/fail2ban/action.d (Permission denied)
missing   c /etc/fail2ban/action.d/abuseipdb.conf (Permission denied)
dpkg: warning: something unrelated
`;

const RPM_VA = `S.5....T.  c /etc/ssh/sshd_config
..5....T.    /usr/bin/ls
.......T.    /usr/bin/true
missing     /usr/sbin/ifconfig
`;

describe('dpkg --verify / rpm -Va', () => {
  it('parses attributes, conffile markers and errors', () => {
    const e = parsePackageVerify(DPKG_VERIFY);
    expect(e).toHaveLength(12);
    expect(e[0]).toMatchObject({ path: '/etc/default/motd-news', fileType: 'c', digestChanged: true });
    expect(e[1]).toMatchObject({ path: '/boot/vmlinuz-7.0.0-43-generic', fileType: null, digestChanged: false });
    expect(e[9]).toMatchObject({ path: '/usr/bin/netstat', missing: true, error: null });
    expect(e[10]).toMatchObject({ path: '/etc/fail2ban/action.d', missing: true, error: 'Permission denied' });
  });

  it('fails changed binaries, PAM modules and shared objects; ignores conffiles', () => {
    const v = judgePackageVerify(parsePackageVerify(DPKG_VERIFY));
    expect(v.fail.map((x) => x.path)).toEqual([
      '/usr/bin/ps', '/usr/sbin/sshd', '/usr/lib/x86_64-linux-gnu/security/pam_unix.so', '/usr/lib/x86_64-linux-gnu/libprocps.so.8.0.4',
    ]);
    expect(v.warn.map((x) => x.path)).toEqual(['/usr/lib/python3/dist-packages/foo/bar.py', '/usr/bin/netstat']);
    expect(v.unreadable).toBe(2);
  });

  it('handles rpm -Va output the same way', () => {
    const v = judgePackageVerify(parsePackageVerify(RPM_VA));
    expect(v.fail.map((x) => x.path)).toEqual(['/usr/bin/ls']);
    expect(v.warn.map((x) => x.path)).toEqual(['/usr/sbin/ifconfig']);
  });
});

describe('rkhunter', () => {
  const OUT = `Warning: The command '/usr/bin/lwp-request' has been replaced by a script: /usr/bin/lwp-request: Perl script text executable
Warning: Suspicious file types found in /dev:
         /dev/shm/x: ELF 64-bit LSB executable
         /dev/shm/y: data
Warning: Found possible rootkit files for the Diamorphine LKM: /sys/module/diamorphine
[19:36:16] Warning: Hidden directory found: /etc/.java
`;
  it('collects warnings with continuation lines and log timestamps', () => {
    const w = parseRkhunter(OUT);
    expect(w).toHaveLength(4);
    expect(w[1]).toBe('Suspicious file types found in /dev: /dev/shm/x: ELF 64-bit LSB executable /dev/shm/y: data');
    expect(w[3]).toBe('Hidden directory found: /etc/.java');
  });
  it('treats rootkit warnings as failures', () => {
    const w = parseRkhunter(OUT);
    expect(w.map(isRkhunterRootkitWarning)).toEqual([false, false, true, false]);
  });
});

describe('chkrootkit', () => {
  const OUT = `Checking \`basename'... INFECTED
Checking \`env'... INFECTED
WARNING: The following suspicious files and directories were found:
/usr/lib/modules/7.0.0-43-generic/vdso/.build-id [From Debian package: linux-modules-7.0.0-43-generic]
/usr/lib/.hidden-thing [Not from a Debian package]

WARNING: Possible Linux.Xor.DDoS installed:
/tmp/build-abc/tool [Not from a Debian package]

INFECTED: Possible Malicious Linux.Xor.DDoS installed
eth0: PACKET SNIFFER(/usr/sbin/tcpdump[1234])
`;
  it('splits infected commands, unpackaged warning paths and other lines', () => {
    const r = parseChkrootkit(OUT);
    expect(r.infectedCommands).toEqual(['basename', 'env']);
    expect(r.infectedOther).toEqual(['INFECTED: Possible Malicious Linux.Xor.DDoS installed']);
    expect(r.warnings).toEqual([
      { header: 'The following suspicious files and directories were found', paths: ['/usr/lib/.hidden-thing'] },
      { header: 'Possible Linux.Xor.DDoS installed', paths: ['/tmp/build-abc/tool'] },
    ]);
    expect(r.other).toEqual(['eth0: PACKET SNIFFER(/usr/sbin/tcpdump[1234])']);
  });
  it('drops a warning group whose files are all packaged', () => {
    const r = parseChkrootkit('WARNING: The following suspicious files and directories were found:\n/usr/lib/x/.doc [From Debian package: x]\n');
    expect(r.warnings).toEqual([]);
  });
});

describe('unhide', () => {
  it('reads hidden PIDs and their detail lines', () => {
    const r = parseUnhide('Unhide 20240509\n[*]Searching for Hidden processes through  comparison of results of system calls\n\nFound HIDDEN PID: 4242\n\tCmdline: "/tmp/.x/kworker"\n\tExecutable: "/tmp/.x/kworker"\n\n');
    expect(r).toEqual([{ pid: 4242, detail: ['Cmdline: "/tmp/.x/kworker"', 'Executable: "/tmp/.x/kworker"'] }]);
  });
});

// Throwaway test keys (random bytes, not real credentials).
const BLOB_A = Buffer.from('test-key-a-0123456789').toString('base64');
const BLOB_B = Buffer.from('test-key-b-0123456789').toString('base64');
const BLOB_C = Buffer.from('test-key-c-0123456789').toString('base64');

describe('authorized_keys', () => {
  const FILE = `# comment
ssh-ed25519 ${BLOB_A} alice@laptop
command="/usr/local/bin/backup --only, \\"quoted\\"",no-pty ssh-ed25519 ${BLOB_B} backup
from="10.0.0.0/8,192.168.1.*",restrict ssh-rsa ${BLOB_C} ops key with spaces
restrict ssh-ed25519 ${BLOB_A} alice-again

not a key line
`;
  it('parses options with quoted commas and escaped quotes', () => {
    const k = parseAuthorizedKeys(FILE, '/root/.ssh/authorized_keys');
    expect(k).toHaveLength(4);
    expect(k[0]).toMatchObject({ type: 'ssh-ed25519', blob: BLOB_A, comment: 'alice@laptop', command: null, from: null, line: 2 });
    expect(k[1].command).toBe('/usr/local/bin/backup --only, "quoted"');
    expect(k[1].options.map((o) => o.name)).toEqual(['command', 'no-pty']);
    expect(k[2]).toMatchObject({ from: '10.0.0.0/8,192.168.1.*', restrict: true, comment: 'ops key with spaces' });
    expect(k[3]).toMatchObject({ restrict: true, command: null, from: null });
  });
  it('flags keys with neither command= nor from=', () => {
    expect(parseAuthorizedKeys(FILE).map(isUnrestrictedKey)).toEqual([true, false, false, true]);
  });
  it('fingerprints like ssh-keygen -l (SHA256, unpadded base64)', () => {
    expect(keyFingerprint(BLOB_A)).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });
  it('matches deny list entries by full line, blob or fingerprint', () => {
    const keys = parseAuthorizedKeys(FILE);
    const deny = parseDenyList(`# stolen\nssh-ed25519 ${BLOB_A} whatever\n${keyFingerprint(BLOB_C)}\n`);
    expect(keys.map((k) => keyIsDenied(k, deny))).toEqual([true, false, true, true]);
    expect(keyIsDenied(keys[1], parseDenyList(BLOB_B))).toBe(true);
  });
  it('expands AuthorizedKeysFile tokens', () => {
    expect(expandAuthorizedKeysFiles('.ssh/authorized_keys /etc/ssh/keys/%u', '/home/bob', 'bob'))
      .toEqual(['/home/bob/.ssh/authorized_keys', '/etc/ssh/keys/bob']);
  });
});

describe('authorized_keys placement (planted persistence)', () => {
  const PLANTED = `ssh-ed25519 ${BLOB_A} ci-diag-20261120`;
  const place = (text: string, file: string, user: string) => parseAuthorizedKeys(text, file).map((k) => ({ ...k, user }));

  it('fails a key that authorizes both root and another account', () => {
    const keys = [...place(PLANTED, '/root/.ssh/authorized_keys', 'root'), ...place(PLANTED, '/home/app/.ssh/authorized_keys', 'app')];
    const items = judgeKeyPlacement(keys, new Set());
    const shared = items.filter((i) => i.details?.rule === 'authorized-keys-root-and-user');
    expect(shared).toHaveLength(1);
    expect(shared[0]).toMatchObject({ status: 'fail', path: '/root/.ssh/authorized_keys:1' });
    expect(shared[0].message).toContain('root and app');
  });

  it('fails a dated ci/diag-style comment on an unrestricted key, warns when restricted', () => {
    const unrestricted = judgeKeyPlacement(place(PLANTED, '/home/app/.ssh/authorized_keys', 'app'), new Set());
    expect(unrestricted.filter((i) => i.details?.rule === 'authorized-keys-suspicious-comment').map((i) => i.status)).toEqual(['fail']);
    const restricted = judgeKeyPlacement(place(`restrict,command="/bin/true" ${PLANTED}`, '/home/app/.ssh/authorized_keys', 'app'), new Set());
    expect(restricted.filter((i) => i.details?.rule === 'authorized-keys-suspicious-comment').map((i) => i.status)).toEqual(['warn']);
  });

  it('fails an unrestricted key in a recently changed file only', () => {
    const file = '/home/bob/.ssh/authorized_keys';
    const keys = place(`ssh-ed25519 ${BLOB_B} bob@laptop\nrestrict ssh-ed25519 ${BLOB_C} bob@phone`, file, 'bob');
    expect(judgeKeyPlacement(keys, new Set())).toEqual([]);
    const recent = judgeKeyPlacement(keys, new Set([file]));
    expect(recent.map((i) => [i.details?.rule, i.path])).toEqual([['authorized-keys-recent-unrestricted', `${file}:1`]]);
  });

  it('stays quiet on ordinary keys', () => {
    const keys = [
      ...place(`ssh-ed25519 ${BLOB_A} alice@laptop`, '/home/alice/.ssh/authorized_keys', 'alice'),
      ...place(`restrict,from="192.0.2.1" ssh-ed25519 ${BLOB_B} deploy@ci`, '/root/.ssh/authorized_keys', 'root'),
    ];
    expect(judgeKeyPlacement(keys, new Set())).toEqual([]);
  });
});

describe('sshd -T', () => {
  const OUT = 'port 22\npermitrootlogin without-password\npasswordauthentication yes\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nhostkey /etc/ssh/a\nhostkey /etc/ssh/b\n';
  it('parses repeatable keywords', () => {
    const cfg = parseSshdT(OUT);
    expect(cfg.get('hostkey')).toEqual(['/etc/ssh/a', '/etc/ssh/b']);
    expect(cfg.get('authorizedkeysfile')).toEqual(['.ssh/authorized_keys .ssh/authorized_keys2']);
  });
  it('warns on root login and password auth', () => {
    expect(judgeSshdConfig(parseSshdT(OUT)).map((i) => i.setting)).toEqual(['PermitRootLogin', 'PasswordAuthentication']);
    expect(judgeSshdConfig(parseSshdT('permitrootlogin no\npasswordauthentication no\n'))).toEqual([]);
  });
});

describe('accounts, modules, docker, misc', () => {
  const PASSWD = 'root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:999::/home/bob:/bin/bash\n';
  it('finds uid 0 accounts other than root', () => {
    expect(uidZeroNonRoot(parsePasswd(PASSWD))).toEqual(['toor']);
    expect(checkUidZero(PASSWD).status).toBe('fail');
    expect(checkUidZero('root:x:0:0:root:/root:/bin/bash\n').status).toBe('pass');
  });
  it('lists docker group members including primary-group users', () => {
    expect(groupMembers('docker:x:999:alice\n', parsePasswd(PASSWD), 'docker')).toEqual({ gid: 999, members: ['alice', 'bob'] });
  });
  it('reads /proc/modules names', () => {
    expect(parseProcModules('nf_tables 389120 1 - Live 0x0\next4 1100000 2 - Live 0x0\n')).toEqual(['nf_tables', 'ext4']);
  });
  it('flags privileged, host-PID and dangerous bind mounts', () => {
    const json = JSON.stringify([
      { Id: 'aaaaaaaaaaaaaaaa', Name: '/watchtower', HostConfig: { Privileged: false, PidMode: '', Binds: ['/var/run/docker.sock:/var/run/docker.sock'] }, Mounts: [] },
      { Id: 'bbbbbbbbbbbbbbbb', Name: '/agent', HostConfig: { Privileged: true, PidMode: 'host' }, Mounts: [{ Type: 'bind', Source: '/', Destination: '/host' }] },
      { Id: 'cccccccccccccccc', Name: '/web', HostConfig: { Privileged: false }, Mounts: [{ Type: 'volume', Source: '/var/lib/docker/volumes/x' }] },
    ]);
    expect(judgeDockerInspect(json)).toEqual([
      { name: 'watchtower', id: 'aaaaaaaaaaaa', reasons: ['bind mount of /var/run/docker.sock'] },
      { name: 'agent', id: 'bbbbbbbbbbbb', reasons: ['--privileged', '--pid=host', 'bind mount of /'] },
    ]);
  });
  it('fails when /etc/ld.so.preload exists', () => {
    expect(checkLdPreload(() => null, () => false).status).toBe('pass');
    const r = checkLdPreload(() => '/usr/lib/libhide.so\n', () => true);
    expect(r.status).toBe('fail');
    expect(r.items[0].details).toEqual({ libraries: ['/usr/lib/libhide.so'] });
    expect(checkLdPreload(() => '', () => true).status).toBe('fail');
  });
  it('parses --since durations', () => {
    expect(parseSince('7d')).toBe(7 * 86400e3);
    expect(parseSince('12h')).toBe(12 * 3600e3);
    expect(() => parseSince('soon')).toThrow(/invalid --since/);
  });
  it('reads dpkg -S owners', () => {
    const owned = parseDpkgSearch('passwd: /usr/bin/passwd\nlibutempter0:amd64: /usr/lib/x86_64-linux-gnu/utempter/utempter\nmount, util-linux: /usr/bin/mount\ndiversion by foo from: /usr/bin/x\n');
    expect([...owned]).toEqual(['/usr/bin/passwd', '/usr/lib/x86_64-linux-gnu/utempter/utempter', '/usr/bin/mount']);
  });
});
