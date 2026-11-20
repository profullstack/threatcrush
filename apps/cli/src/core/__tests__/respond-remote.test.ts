import { describe, expect, it } from 'vitest';
import {
  parseHosts, remoteArgs, remoteCliCommand, REMOTE_PROBE, REMOTE_SH, runHosts, runLimited, runRemote, type SshExec,
} from '../respond/run.js';
import { parseGather } from '../respond/script.js';
import type { Report } from '../respond/types.js';

const KA = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH4VXTW/nXaCmkfpr+YIqCpDOWy/MKogQtU0mQAwXNDX ka@test';
const KA_FP = 'SHA256:mWKNurrn1mjwyNL1Asld6s/ofn341W4Y9kWHXP2f3E8';
const KC = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID7PzxUm9siJhNBj3/HZe69MLxxenTBFVAVGKKSflGYr kc@test';

const b = (s: string) => Buffer.from(s).toString('base64');

/** What the gather script prints on a box where `ubuntu` has only the stolen key. */
function gatherOutput(opts: { uid?: number; keys?: string[]; user?: string } = {}): string {
  return [
    `META\tuid\t${opts.uid ?? 0}`,
    `META\tuser\t${b(opts.user ?? 'ubuntu')}`,
    `META\thostname\t${b('seed1')}`,
    `META\tssh\t${b('198.51.100.7 40404 10.0.0.5 22')}`,
    `META\tsshd\t${b('/usr/sbin/sshd')}`,
    `META\tjournal\t${b('journalctl')}`,
    `BLOB\tpasswd\t${b('root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n')}`,
    `AK\t${b('ubuntu')}\t${b('/home/ubuntu/.ssh/authorized_keys')}\t${b((opts.keys ?? [KA]).join('\n'))}`,
    `AK\t${b('root')}\t${b('/root/.ssh/authorized_keys')}\t${b(`command="/bin/deploy" ${KA}`)}`,
    `AKX\t${b('/home/ubuntu/.ssh/authorized_keys.bak')}\t${b(KA)}`,
    `PRIV\t${b('/home/ubuntu/.ssh/id_stolen')}\t${KA_FP}`,
    `BLOB\tjournal\t${b('')}`,
    'END',
  ].join('\n');
}

describe('--hosts parsing', () => {
  it('reads a file with comments, or a comma/space list, de-duplicated', () => {
    const file = '# fleet\ndev2\nubuntu@seed1   # seed box\n\ndev2\n';
    expect(parseHosts('fleet.txt', (p) => (p === 'fleet.txt' ? file : null)).hosts).toEqual(['dev2', 'ubuntu@seed1']);
    expect(parseHosts('dev1, dev3 root@[2001:db8::1]', () => null).hosts).toEqual(['dev1', 'dev3', 'root@[2001:db8::1]']);
  });

  it('refuses anything ssh could read as an option or a command', () => {
    const r = parseHosts('-oProxyCommand=touch_x,ok,a;b,$(id)', () => null);
    expect(r.hosts).toEqual(['ok']);
    expect(r.errors).toHaveLength(3);
  });
});

describe('remote argv', () => {
  it('passes fingerprints and flags, never key material', () => {
    expect(remoteArgs({ sub: 'key', apply: true, fingerprints: [KA_FP], allowLockout: true })).toEqual(['key', KA_FP, '--allow-lockout', '--apply', '--json']);
    expect(remoteArgs({ sub: 'sshd', apply: false, lockdown: true, allowRootLocalhost: true })).toEqual(['sshd', '--lockdown', '--allow-root-localhost', '--json']);
  });

  it('refuses a token that could break out of the remote shell', () => {
    expect(() => remoteArgs({ sub: 'ip', apply: false, ips: ["1.2.3.4'; rm -rf /"] })).toThrow(/unsafe argument/);
    expect(() => remoteCliCommand({ sub: 'key', apply: false, searchRoots: ['/srv/$(id)'] })).toThrow(/unsafe/);
  });
});

describe('runLimited', () => {
  it('never runs more than the limit at once and keeps input order', async () => {
    let active = 0;
    let peak = 0;
    const out = await runLimited([1, 2, 3, 4, 5, 6, 7], 3, async (n) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5 + (n % 3) * 3));
      active--;
      return n * 10;
    });
    expect(peak).toBe(3);
    expect(out).toEqual([10, 20, 30, 40, 50, 60, 70]);
  });
});

/** A mock ssh: records every call, answers by host and command. */
function mockSsh(handler: (host: string, cmd: string, stdin?: string) => { code?: number; stdout?: string; stderr?: string }): SshExec & { calls: Array<{ host: string; cmd: string; stdin?: string }> } {
  const calls: Array<{ host: string; cmd: string; stdin?: string }> = [];
  const fn = (async (host: string, cmd: string, stdin?: string) => {
    calls.push({ host, cmd, stdin });
    const r = handler(host, cmd, stdin);
    return { code: r.code ?? 0, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  }) as SshExec & { calls: typeof calls };
  fn.calls = calls;
  return fn;
}

describe('runRemote', () => {
  it('uses the remote threatcrush when it has `respond`, and trusts its JSON', async () => {
    const remote: Report = { host: 'localhost', hostname: 'dev1', sub: 'ip', apply: false, root: true, via: 'local', actions: [], warnings: [], needsRoot: [] };
    const ssh = mockSsh((_h, cmd) => (cmd === REMOTE_PROBE ? { stdout: 'TC_RESPOND_OK\n' } : { stdout: `banner noise\n${JSON.stringify(remote)}` }));
    const r = await runRemote('dev1', { sub: 'ip', apply: false, ips: ['203.0.113.7'] }, ssh);
    expect(r).toMatchObject({ host: 'dev1', hostname: 'dev1', via: 'threatcrush' });
    expect(ssh.calls[1].cmd).toContain('respond ip 203.0.113.7 --json');
    expect(ssh.calls[1].cmd).toContain('sudo -n');
  });

  it('falls back to the streamed script and applies the same analysis', async () => {
    const ssh = mockSsh((_h, cmd, stdin) => {
      if (cmd === REMOTE_PROBE) return { stdout: '' };
      if (stdin?.includes('gather')) return { stdout: gatherOutput({ keys: [KA, KC] }) };
      // apply: report every action done
      const ids = [...(stdin ?? '').matchAll(/RESULT\\t%s\\tok\\t%s\\n' '(a\d+)'/g)].map((m) => m[1]);
      return { stdout: [...new Set(ids)].map((id) => `RESULT\t${id}\tok\t${b('done')}`).join('\n') + '\nEND\n' };
    });
    const r = await runRemote('seed1', { sub: 'key', apply: true, fingerprints: [KA_FP] }, ssh);
    expect(r.via).toBe('script');
    expect(r.error).toBeUndefined();
    // The stolen key is removed even from the command= (deploy) line in root's file.
    expect(r.actions.map((a) => [a.kind, a.status])).toEqual([
      ['strip-key', 'done'], ['strip-key', 'done'], ['rm', 'done'], ['shred', 'done'],
    ]);
    expect(r.keys!.find((k) => k.user === 'root')!.flags.join()).toMatch(/restricted keys are still stolen keys/);
    expect(ssh.calls.map((c) => c.cmd)).toEqual([REMOTE_PROBE, REMOTE_SH, REMOTE_SH]);
    // Scripts go over stdin, not argv.
    expect(ssh.calls[2].stdin).toContain('awk');
    expect(ssh.calls.every((c) => !c.cmd.includes('BEGIN OPENSSH'))).toBe(true);
  });

  it('refuses the removal on a host where it would lock the operator out', async () => {
    const ssh = mockSsh((_h, cmd, stdin) => (cmd === REMOTE_PROBE ? {} : stdin?.includes('gather') ? { stdout: gatherOutput() } : { stdout: 'END\n' }));
    const r = await runRemote('seed1', { sub: 'key', apply: true, fingerprints: [KA_FP] }, ssh);
    const strips = r.actions.filter((a) => a.kind === 'strip-key');
    expect(strips.find((a) => a.summary.includes('/home/ubuntu'))!.status).toBe('refused');
    expect(r.replacementHelp!.join('\n')).toMatch(/ssh-copy-id/);
  });

  it('reads only, without sudo, and lists what needs root', async () => {
    const ssh = mockSsh((_h, cmd) => (cmd === REMOTE_PROBE ? {} : { stdout: gatherOutput({ uid: 1000, keys: [KA, KC] }) }));
    const r = await runRemote('seed1', { sub: 'key', apply: true, fingerprints: [KA_FP] }, ssh);
    expect(r.root).toBe(false);
    expect(r.actions.every((a) => a.status === 'needs-root')).toBe(true);
    expect(ssh.calls).toHaveLength(2); // probe + gather; nothing applied
  });

  it('reports an unreachable host instead of throwing', async () => {
    const ssh = mockSsh(() => ({ code: 255, stderr: 'ssh: connect to host x port 22: Connection refused\n' }));
    const r = await runRemote('x', { sub: 'keys-audit', apply: false }, ssh);
    expect(r.error).toMatch(/Connection refused/);
  });
});

describe('runHosts aggregation', () => {
  it('runs every host, 3 at a time, results in order, one bad host does not stop the rest', async () => {
    let active = 0;
    let peak = 0;
    const ssh: SshExec = async (host, cmd) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      if (host === 'down') return { code: 255, stdout: '', stderr: 'no route' };
      if (cmd === REMOTE_PROBE) return { code: 1, stdout: '', stderr: '' };
      return { code: 0, stdout: gatherOutput(), stderr: '' };
    };
    const reports = await runHosts(['h1', 'h2', 'down', 'h4', 'h5'], { sub: 'keys-audit', apply: false }, ssh);
    expect(reports.map((r) => r.host)).toEqual(['h1', 'h2', 'down', 'h4', 'h5']);
    expect(reports[2].error).toMatch(/no route/);
    expect(reports.filter((r) => !r.error).every((r) => r.keys!.length === 3)).toBe(true);
    expect(peak).toBeLessThanOrEqual(3);
  });
});

describe('parseGather', () => {
  it('attributes stale copies to their home and keeps live files first', () => {
    const snap = parseGather(gatherOutput());
    expect(snap.keyFiles.map((f) => [f.user, f.path, f.live])).toEqual([
      ['ubuntu', '/home/ubuntu/.ssh/authorized_keys', true],
      ['root', '/root/.ssh/authorized_keys', true],
      ['ubuntu', '/home/ubuntu/.ssh/authorized_keys.bak', false],
    ]);
    expect(snap.sshConnection).toBe('198.51.100.7 40404 10.0.0.5 22');
    expect(snap.errors).toEqual([]);
  });

  it('notices output that was cut short', () => {
    expect(parseGather('META\tuid\t0\n').errors.join()).toMatch(/cut short/);
  });
});
