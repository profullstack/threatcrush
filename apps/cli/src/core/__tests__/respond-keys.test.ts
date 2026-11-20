import { describe, expect, it } from 'vitest';
import {
  auditFlags, keyRestrictions, keyRows, lastUsedByFingerprint, lockoutCheck, normaliseFingerprint,
  parseAcceptedLogins, resolveKeyTargets, sessionKeyFingerprint,
} from '../respond/keys.js';
import { parseAuthorizedKeys } from '../host-scan/parsers.js';
import type { GatheredKeyFile } from '../respond/types.js';

// Throwaway ed25519 keys made for these tests; fingerprints are what `ssh-keygen -lf` printed.
const KA = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH4VXTW/nXaCmkfpr+YIqCpDOWy/MKogQtU0mQAwXNDX ka@test';
const KA_FP = 'SHA256:mWKNurrn1mjwyNL1Asld6s/ofn341W4Y9kWHXP2f3E8';
const KB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL22FBykmMz1vDvAe+L6DVlsbZ0c7aJs4w0RB3fo94SE kb@test';
const KB_FP = 'SHA256:+Yp/r3+Uk/zsZzhaI63LAnPSg/WcjZ3wANAHeMB/i94';
const KC = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID7PzxUm9siJhNBj3/HZe69MLxxenTBFVAVGKKSflGYr kc@test';
const KC_FP = 'SHA256:Qwa1kZACiktjTXb+3IrhPbE7FJNZTejdX6s/dKaMv2c';

const AUTHORIZED_KEYS = [
  '# fleet keys',
  KA,
  `command="/usr/local/bin/ci-deploy org/repo \\"quoted\\", with comma",no-pty,restrict ${KB}`,
  `from="203.0.113.0/24,!203.0.113.9",no-agent-forwarding ${KC}`,
  '',
  'not a key line',
].join('\n');

describe('authorized_keys option parsing', () => {
  const keys = parseAuthorizedKeys(AUTHORIZED_KEYS, '/home/a/.ssh/authorized_keys');

  it('reads every key and skips comments and junk', () => {
    expect(keys.map((k) => k.comment)).toEqual(['ka@test', 'kb@test', 'kc@test']);
    expect(keys.map((k) => k.line)).toEqual([2, 3, 4]);
  });

  it('keeps quoted commas, spaces and escaped quotes inside command=', () => {
    expect(keys[1].command).toBe('/usr/local/bin/ci-deploy org/repo "quoted", with comma');
    expect(keys[1].restrict).toBe(true);
    expect(keyRestrictions(keys[1])).toEqual([`command="/usr/local/bin/ci-deploy org/repo "quoted", with comma"`, 'restrict']);
  });

  it('reads from= and leaves other flags alone', () => {
    expect(keys[2].from).toBe('203.0.113.0/24,!203.0.113.9');
    expect(keyRestrictions(keys[2])).toEqual(['from="203.0.113.0/24,!203.0.113.9"']);
    expect(keyRestrictions(keys[0])).toEqual([]);
  });

  it('computes the same SHA256 fingerprints as ssh-keygen', () => {
    expect(keys.map((k) => k.fingerprint)).toEqual([KA_FP, KB_FP, KC_FP]);
  });
});

describe('resolveKeyTargets', () => {
  const files: Record<string, string> = {
    '/k/ka.pub': `${KA}\n`,
    '/k/authorized_keys': AUTHORIZED_KEYS,
    // Only the armour line matters here (split so secret scanners do not flag a fake key).
    '/k/id_kd': `-----BEGIN OPENSSH ${'PRIVATE'} KEY-----\nnot-a-real-key\n`,
    '/k/empty': 'nothing here\n',
  };
  const io = {
    readFile: (p: string) => {
      if (!(p in files)) throw new Error('ENOENT');
      return files[p];
    },
    keygenFingerprint: (p: string) => (p === '/k/id_kd' ? 'SHA256:B36F+PNgdJLu2fpdqIhu69LUWfh/gprbGyRNQHYdM/Y' : null),
  };

  it('accepts fingerprints with or without base64 padding', () => {
    expect(resolveKeyTargets([`${KA_FP}=`], io).fingerprints).toEqual([KA_FP]);
    expect(normaliseFingerprint(`${KB_FP}==`)).toBe(KB_FP);
  });

  it('reads public keys and whole authorized_keys files, options and all', () => {
    expect(resolveKeyTargets(['/k/ka.pub'], io).fingerprints).toEqual([KA_FP]);
    expect(resolveKeyTargets(['/k/authorized_keys'], io).fingerprints.sort()).toEqual([KA_FP, KB_FP, KC_FP].sort());
  });

  it('reads a private key through ssh-keygen (never by sending it anywhere)', () => {
    expect(resolveKeyTargets(['/k/id_kd'], io).fingerprints).toEqual(['SHA256:B36F+PNgdJLu2fpdqIhu69LUWfh/gprbGyRNQHYdM/Y']);
  });

  it('reports what it could not use', () => {
    const r = resolveKeyTargets(['SHA256:short', '/k/missing', '/k/empty'], io);
    expect(r.fingerprints).toEqual([]);
    expect(r.errors).toHaveLength(3);
  });
});

function file(user: string, path: string, lines: string[], live = true): GatheredKeyFile {
  return { user, path, live, content: lines.join('\n') };
}

describe('lockout guard', () => {
  const all = (files: GatheredKeyFile[]) => keyRows(files);

  it('refuses when the key is the only one the invoking user has', () => {
    const rows = all([file('anthony', '/home/anthony/.ssh/authorized_keys', [KA])]);
    const v = lockoutCheck(rows, new Set([KA_FP]), 'anthony', null);
    expect(v.lockout).toBe(true);
    expect(v.remaining).toBe(0);
  });

  it('allows it once a replacement shell key is installed', () => {
    const rows = all([file('anthony', '/home/anthony/.ssh/authorized_keys', [KA, KC])]);
    expect(lockoutCheck(rows, new Set([KA_FP]), 'anthony', null).lockout).toBe(false);
  });

  it('does not count command= or restrict keys as a way back in', () => {
    const rows = all([file('anthony', '/home/anthony/.ssh/authorized_keys', [
      KA,
      `command="/bin/deploy" ${KB}`,
      `restrict ${KC}`,
    ])]);
    expect(lockoutCheck(rows, new Set([KA_FP]), 'anthony', null).lockout).toBe(true);
  });

  it('flags the session key and refuses when nothing else is left', () => {
    const rows = all([file('root', '/root/.ssh/authorized_keys', [KA])]);
    const v = lockoutCheck(rows, new Set([KA_FP]), 'root', KA_FP);
    expect(v.sessionKeyRemoved).toBe(true);
    expect(v.lockout).toBe(true);
    expect(v.reason).toContain(KA_FP);
  });

  it('only warns about the session key when another key remains', () => {
    const rows = all([file('root', '/root/.ssh/authorized_keys', [KA, KC])]);
    const v = lockoutCheck(rows, new Set([KA_FP]), 'root', KA_FP);
    expect(v).toMatchObject({ lockout: false, sessionKeyRemoved: true, remaining: 1 });
  });

  it('ignores other users and stale copies for the invoker, but names emptied accounts', () => {
    const rows = all([
      file('anthony', '/home/anthony/.ssh/authorized_keys', [KC]),
      file('deploy', '/home/deploy/.ssh/authorized_keys', [KA]),
      file('anthony', '/home/anthony/.ssh/authorized_keys.bak', [KA], false),
    ]);
    const v = lockoutCheck(rows, new Set([KA_FP]), 'anthony', null);
    expect(v.lockout).toBe(false);
    expect(v.othersEmptied).toEqual(['deploy']);
  });

  it('does not trip for a user who had no keys to begin with', () => {
    const rows = all([file('deploy', '/home/deploy/.ssh/authorized_keys', [KA])]);
    expect(lockoutCheck(rows, new Set([KA_FP]), 'anthony', null).lockout).toBe(false);
  });
});

describe('journal: logins and last use', () => {
  const journal = [
    `1795200000.123456 dev2 sshd-session[100]: Accepted publickey for root from 198.51.100.4 port 50022 ssh2: ED25519 ${KA_FP}`,
    `1795100000.000000 dev2 sshd[99]: Accepted publickey for root from 198.51.100.4 port 40000 ssh2: ED25519 ${KA_FP}`,
    '1795200100.000000 dev2 sshd[101]: Accepted password for anthony from 203.0.113.7 port 1234 ssh2',
    'Nov 20 10:00:00 dev2 sshd[5]: Accepted publickey for anthony from 192.0.2.1 port 22 ssh2: RSA SHA256:abc',
    '2026-11-20T10:00:00.000000+00:00 dev2 sshd[6]: Accepted publickey for anthony from 192.0.2.2 port 23 ssh2: RSA SHA256:def',
  ].join('\n');

  it('parses journalctl short-unix, ISO and syslog timestamps', () => {
    const logins = parseAcceptedLogins(journal, new Date('2026-11-21T00:00:00Z'));
    expect(logins).toHaveLength(5);
    expect(logins[0]).toMatchObject({ user: 'root', ip: '198.51.100.4', port: 50022, method: 'publickey', fingerprint: KA_FP, at: 1795200000123 });
    expect(logins[2]).toMatchObject({ method: 'password', fingerprint: null });
    expect(logins[4].at).toBe(Date.parse('2026-11-20T10:00:00Z'));
  });

  it('finds the newest use of each key and the key of this session', () => {
    const logins = parseAcceptedLogins(journal);
    expect(lastUsedByFingerprint(logins).get(KA_FP)).toBe(1795200000123);
    expect(sessionKeyFingerprint('198.51.100.4 40000 10.0.0.1 22', logins)).toBe(KA_FP);
    expect(sessionKeyFingerprint('198.51.100.4 1 10.0.0.1 22', logins)).toBeNull();
    expect(sessionKeyFingerprint(null, logins)).toBeNull();
  });
});

describe('keys-audit flags', () => {
  const now = Date.parse('2026-11-20T00:00:00Z');
  const rows = keyRows([
    file('root', '/root/.ssh/authorized_keys', [KA, `command="/bin/deploy",restrict ${KB}`]),
    file('anthony', '/home/anthony/.ssh/authorized_keys', [KA, `from="198.51.100.0/24" ${KC}`]),
    file('anthony', '/home/anthony/.ssh/authorized_keys.old', [KC], false),
  ], new Map([[KC_FP, now - 86400000]]));
  const audited = auditFlags(rows, { now, unusedDays: 30, journalAvailable: true });

  it('flags unrestricted keys, duplicates across users and unused keys', () => {
    const rootKa = audited.find((r) => r.user === 'root' && r.fingerprint === KA_FP)!;
    expect(rootKa.flags.join('|')).toMatch(/unrestricted/);
    expect(rootKa.flags.join('|')).toMatch(/duplicate: also authorized for anthony/);
    expect(rootKa.flags.join('|')).toMatch(/unused in 30 days/);
  });

  it('treats command= deploy keys as secrets to rotate', () => {
    const deploy = audited.find((r) => r.fingerprint === KB_FP)!;
    expect(deploy.flags.join('|')).toMatch(/deploy key .*rotate if CI secrets may have leaked/);
    expect(deploy.flags.join('|')).not.toMatch(/unrestricted/);
  });

  it('marks stale copies and keeps recently used keys quiet', () => {
    const live = audited.find((r) => r.fingerprint === KC_FP && r.live)!;
    expect(live.flags).toEqual([]);
    const stale = audited.find((r) => !r.live)!;
    expect(stale.flags.join('|')).toMatch(/stale copy/);
  });

  it('never leaks the raw key blob into a report row', () => {
    for (const r of audited) expect(Object.keys(r)).not.toContain('blob');
  });
});
