import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  checkOrdering, effectiveValues, lockdownDropins, lockdownMismatches, LOCKDOWN_FILE, ROOT_LOCALHOST_FILE, sortDropins,
} from '../respond/sshd.js';
import { applyScript, parseApply } from '../respond/script.js';
import type { Action } from '../respond/types.js';

const UBUNTU_MAIN = [
  'Include /etc/ssh/sshd_config.d/*.conf',
  '#PermitRootLogin prohibit-password',
  'KbdInteractiveAuthentication no',
  'UsePAM yes',
  'Subsystem sftp /usr/lib/openssh/sftp-server',
].join('\n');

describe('lockdown drop-ins', () => {
  it('writes the global settings, and the localhost Match only when asked', () => {
    const plain = lockdownDropins({ allowRootLocalhost: false });
    expect(plain.map((f) => f.name)).toEqual([LOCKDOWN_FILE]);
    expect(plain[0].content).toMatch(/^PermitRootLogin no$/m);
    expect(plain[0].content).toMatch(/^PasswordAuthentication no$/m);
    expect(plain[0].content).toMatch(/^KbdInteractiveAuthentication no$/m);
    expect(plain[0].content).not.toMatch(/Match/);

    const withRoot = lockdownDropins({ allowRootLocalhost: true });
    expect(withRoot.map((f) => f.name)).toEqual([LOCKDOWN_FILE, ROOT_LOCALHOST_FILE]);
    expect(withRoot[1].content).toMatch(/^Match Address 127\.0\.0\.1,::1$/m);
    expect(withRoot[1].content).toMatch(/^\s+PermitRootLogin prohibit-password$/m);
    // Nothing global may follow the Match line.
    const afterMatch = withRoot[1].content.split(/^Match .*$/m)[1];
    expect(afterMatch.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#') && !/^\s/.test(l))).toEqual([]);
  });

  it('sorts first and last among the usual cloud drop-ins', () => {
    const order = sortDropins(['50-cloud-init.conf', ROOT_LOCALHOST_FILE, '60-cloudimg-settings.conf', LOCKDOWN_FILE, '00-cloud.conf', '01-hardening.conf']);
    expect(order[0]).toBe(LOCKDOWN_FILE);
    expect(order[order.length - 1]).toBe(ROOT_LOCALHOST_FILE);
  });
});

describe('ordering checks', () => {
  const base = { mainConfig: UBUNTU_MAIN, dropinDir: '/etc/ssh/sshd_config.d', allowRootLocalhost: false };

  it('passes on a stock Ubuntu layout', () => {
    const r = checkOrdering({ ...base, existing: { '50-cloud-init.conf': 'PasswordAuthentication yes\n' } });
    expect(r.blockers).toEqual([]);
  });

  it('refuses when the drop-in directory is never included', () => {
    const r = checkOrdering({ ...base, mainConfig: 'PermitRootLogin yes\n', existing: {} });
    expect(r.blockers.join()).toMatch(/no "Include/);
  });

  it('refuses when sshd_config sets a conflicting value above its Include', () => {
    const r = checkOrdering({ ...base, mainConfig: `PasswordAuthentication yes\n${UBUNTU_MAIN}`, existing: {} });
    expect(r.blockers.join()).toMatch(/PasswordAuthentication yes above its Include/);
  });

  it('refuses a drop-in that sorts before ours with a conflicting value, not one that agrees', () => {
    const conflict = checkOrdering({ ...base, existing: { '00-0-aaa.conf': 'PermitRootLogin yes\n' } });
    expect(conflict.blockers.join()).toMatch(/00-0-aaa\.conf sorts before .* PermitRootLogin yes/);
    const agrees = checkOrdering({ ...base, existing: { '00-0-aaa.conf': 'PermitRootLogin no\n' } });
    expect(agrees.blockers).toEqual([]);
  });

  it('with the localhost Match, refuses any drop-in that would be swallowed after it', () => {
    const r = checkOrdering({ ...base, allowRootLocalhost: true, existing: { '99-z-late.conf': 'X11Forwarding no\n' } });
    expect(r.blockers.join()).toMatch(/99-z-late\.conf sorts after/);
    expect(r.warnings.join()).toMatch(/directives after its Include line/);
  });
});

describe('effective values', () => {
  const dump = 'port 22\npermitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin yes\n';

  it('takes the first value, as sshd does', () => {
    expect(effectiveValues(dump)).toEqual({ permitrootlogin: 'no', passwordauthentication: 'no', kbdinteractiveauthentication: 'no' });
  });

  it('accepts without-password as prohibit-password for localhost root', () => {
    expect(lockdownMismatches(effectiveValues(dump), { permitrootlogin: 'without-password' })).toEqual([]);
    expect(lockdownMismatches({ permitrootlogin: 'yes' }, { permitrootlogin: 'yes' })).toHaveLength(2);
  });
});

describe('apply script (run against files in a temp dir)', () => {
  let dir = '';
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

  const run = (actions: Action[], env: Record<string, string> = {}) => {
    const res = spawnSync('sh', ['-s'], { input: applyScript(actions), encoding: 'utf-8', env: { ...process.env, ...env } });
    return parseApply(res.stdout);
  };
  const action = (id: string, op: Action['op']): Action => ({ id, kind: op.op, summary: id, status: 'planned', op });

  it('restores the old drop-ins and does not reload when sshd -t fails', () => {
    dir = mkdtempSync(join(tmpdir(), 'tc-respond-'));
    writeFileSync(join(dir, LOCKDOWN_FILE), 'old\n');
    const fakeSshd = join(dir, 'fake-sshd');
    writeFileSync(fakeSshd, '#!/bin/sh\necho "line 3: Bad configuration option: Nope" >&2\nexit 255\n');
    chmodSync(fakeSshd, 0o755);
    const files = lockdownDropins({ allowRootLocalhost: true });
    const out = run([action('s1', {
      op: 'sshd-lockdown',
      dir,
      files,
      restore: [{ name: LOCKDOWN_FILE, content: 'old\n' }, { name: ROOT_LOCALHOST_FILE, content: null }],
    })], { TC_RESPOND_SSHD: fakeSshd });
    expect(out.complete).toBe(true);
    expect(out.results.get('s1')).toMatchObject({ ok: false });
    expect(out.results.get('s1')!.message).toMatch(/sshd -t rejected .*NOT reloaded.*Bad configuration option/s);
    expect(readFileSync(join(dir, LOCKDOWN_FILE), 'utf-8')).toBe('old\n');
    expect(existsSync(join(dir, ROOT_LOCALHOST_FILE))).toBe(false);
  });

  it('strips exactly the matching key lines and keeps the rest', () => {
    dir = mkdtempSync(join(tmpdir(), 'tc-respond-'));
    const ak = join(dir, 'authorized_keys');
    writeFileSync(ak, 'ssh-ed25519 AAAAgood keep@me\ncommand="x" ssh-ed25519 AAAAbad stolen@ci\n# comment AAAAbad-not-a-field\n');
    const out = run([action('k1', { op: 'strip-key', file: ak, blobs: ['AAAAbad'] })]);
    expect(out.results.get('k1')).toMatchObject({ ok: true });
    expect(readFileSync(ak, 'utf-8')).toBe('ssh-ed25519 AAAAgood keep@me\n# comment AAAAbad-not-a-field\n');
  });

  it('refuses to follow a symlink and never kills a non-sshd process', () => {
    dir = mkdtempSync(join(tmpdir(), 'tc-respond-'));
    writeFileSync(join(dir, 'target'), 'keep\n');
    spawnSync('ln', ['-s', join(dir, 'target'), join(dir, 'link')]);
    const out = run([
      action('r1', { op: 'rm', file: join(dir, 'link') }),
      action('p1', { op: 'kill', pids: [process.pid] }),
    ]);
    expect(out.results.get('r1')).toMatchObject({ ok: false });
    expect(existsSync(join(dir, 'link'))).toBe(true);
    expect(out.results.get('p1')!.message).toMatch(/skipped: \d+\(node/);
  });
});
