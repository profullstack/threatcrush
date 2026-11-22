import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const {
  WriterContainment,
  containWriterSettings,
  summarizeContainment,
} = await import('../workers/writer-containment.js');
const { FileIntegrityWatch, fileIntegritySettings } = await import('../workers/file-integrity.js');

const O_RDONLY = 0o100000;
const O_WRONLY = 0o100001;
const O_RDWR = 0o100002;

interface FakeProc {
  ppid?: number;
  comm: string;
  exe: string | null;
  start?: number;
  /** fd -> [target, flags] */
  fds: Record<string, [string, number]>;
}

function statLine(pid: number, ppid: number, comm: string, start: number): string {
  return `${pid} (${comm}) S ${ppid} ${pid} ${pid} 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 ${start} 1000 100`;
}

function fakeProcFs(table: Record<number, FakeProc>) {
  const signals: Array<[number, NodeJS.Signals]> = [];
  const fs = {
    signals,
    pids: () => Object.keys(table).map(Number),
    stat: (pid: number) => table[pid] ? statLine(pid, table[pid].ppid ?? 1, table[pid].comm, table[pid].start ?? 5000 + pid) : null,
    exe: (pid: number) => table[pid]?.exe ?? null,
    fds: (pid: number) => table[pid] ? Object.keys(table[pid].fds) : null,
    fdTarget: (pid: number, fd: string) => table[pid]?.fds[fd]?.[0] ?? null,
    fdFlags: (pid: number, fd: string) => table[pid]?.fds[fd]?.[1] ?? null,
    kill: (pid: number, signal: NodeJS.Signals) => { signals.push([pid, signal]); },
  };
  return fs;
}

function make(table: Record<number, FakeProc>, settings: Partial<ReturnType<typeof containWriterSettings>> = {}, extra: Record<string, unknown> = {}) {
  const procfs = fakeProcFs(table);
  const logs: string[] = [];
  const containment = new WriterContainment({
    settings: { mode: 'stop', maxProcesses: 3, neverContain: [], ...settings },
    log: (line) => logs.push(line),
    procfs,
    selfPid: 900,
    parentPid: 899,
    platform: 'linux',
    ...extra,
  });
  return { containment, procfs, logs };
}

const CANARY = '/srv/data/.threatcrush-canary';

describe('containWriterSettings', () => {
  it('is off by default and only accepts stop/kill', () => {
    expect(containWriterSettings(undefined).mode).toBe('off');
    expect(containWriterSettings({ contain_writer: 'yes' }).mode).toBe('off');
    expect(containWriterSettings({ contain_writer: 'stop' }).mode).toBe('stop');
    expect(containWriterSettings({ contain_writer: 'kill' }).mode).toBe('kill');
  });

  it('clamps max processes and keeps only absolute never_contain entries', () => {
    expect(containWriterSettings({}).maxProcesses).toBe(3);
    expect(containWriterSettings({ contain_max_processes: 0 }).maxProcesses).toBe(1);
    expect(containWriterSettings({ contain_max_processes: 500 }).maxProcesses).toBe(20);
    expect(containWriterSettings({ never_contain: ['/usr/bin/rsync', 'relative', 3] }).neverContain).toEqual(['/usr/bin/rsync']);
  });

  it('flows through fileIntegritySettings', () => {
    expect(fileIntegritySettings({ enabled: true }).containment.mode).toBe('off');
    expect(fileIntegritySettings({ enabled: true, contain_writer: 'stop' }).containment.mode).toBe('stop');
  });
});

describe('WriterContainment', () => {
  it('SIGSTOPs the single process holding the canary open for writing', async () => {
    const { containment, procfs, logs } = make({
      1234: { comm: 'locker', exe: '/tmp/.x/locker', fds: { '3': [CANARY, O_RDWR] } },
      2000: { comm: 'bash', exe: '/usr/bin/bash', fds: { '0': ['/dev/pts/0', O_RDWR] } },
    });
    const report = await containment.contain([CANARY]);
    expect(report.action).toBe('contained');
    expect(report.match).toBe('exact');
    expect(report.processes).toEqual([
      expect.objectContaining({ pid: 1234, exe: '/tmp/.x/locker', signal: 'SIGSTOP', result: 'sent', files: [CANARY] }),
    ]);
    expect(procfs.signals).toEqual([[1234, 'SIGSTOP']]);
    expect(logs.join('\n')).toContain('kill -CONT 1234');
    expect(summarizeContainment(report)).toContain('stopped (SIGSTOP)');
  });

  it('uses SIGKILL only in kill mode', async () => {
    const { containment, procfs } = make({ 1234: { comm: 'locker', exe: '/opt/locker', fds: { '3': [CANARY, O_WRONLY] } } }, { mode: 'kill' });
    const report = await containment.contain([CANARY]);
    expect(procfs.signals).toEqual([[1234, 'SIGKILL']]);
    expect(summarizeContainment(report)).toContain('killed (SIGKILL)');
  });

  it('ignores read-only holders', async () => {
    const { containment, procfs } = make({ 1234: { comm: 'backup', exe: '/usr/bin/tar', fds: { '3': [CANARY, O_RDONLY] } } });
    const report = await containment.contain([CANARY]);
    expect(report.action).toBe('no-writer');
    expect(procfs.signals).toEqual([]);
  });

  it('matches a deleted file still held open', async () => {
    const { containment, procfs } = make({ 1234: { comm: 'locker', exe: '/opt/locker', fds: { '4': [`${CANARY} (deleted)`, O_RDWR] } } });
    await containment.contain([CANARY]);
    expect(procfs.signals).toEqual([[1234, 'SIGSTOP']]);
  });

  it('falls back to writers inside the affected directory only when nobody holds the file', async () => {
    const { containment, procfs } = make({
      1234: { comm: 'locker', exe: '/opt/locker', fds: { '5': ['/srv/data/sub/report.pdf.locked', O_WRONLY] } },
    });
    const report = await containment.contain([CANARY]);
    expect(report.match).toBe('directory');
    expect(procfs.signals).toEqual([[1234, 'SIGSTOP']]);
  });

  it('prefers the exact holder over directory writers', async () => {
    const { containment, procfs } = make({
      1234: { comm: 'locker', exe: '/opt/locker', fds: { '3': [CANARY, O_RDWR] } },
      1300: { comm: 'app', exe: '/opt/app', fds: { '7': ['/srv/data/app.db', O_RDWR] } },
    });
    const report = await containment.contain([CANARY]);
    expect(report.match).toBe('exact');
    expect(procfs.signals).toEqual([[1234, 'SIGSTOP']]);
  });

  it('never signals pid 1, itself, its parent, kernel threads, sshd, systemd* or never_contain', async () => {
    const fd: Record<string, [string, number]> = { '3': [CANARY, O_RDWR] };
    const { containment, procfs } = make({
      1: { comm: 'systemd', exe: '/usr/lib/systemd/systemd', ppid: 0, fds: fd },
      900: { comm: 'node', exe: '/usr/bin/node', fds: fd },
      899: { comm: 'sudo', exe: '/usr/bin/sudo', fds: fd },
      50: { comm: 'kworker/0:1', exe: null, ppid: 2, fds: fd },
      700: { comm: 'sshd', exe: '/usr/sbin/sshd', fds: fd },
      701: { comm: 'sshd-session', exe: '/usr/lib/openssh/sshd-session', fds: fd },
      702: { comm: 'systemd-journal', exe: '/usr/lib/systemd/systemd-journald', fds: fd },
      703: { comm: 'rsync', exe: '/usr/bin/rsync', fds: fd },
      704: { comm: 'agent', exe: '/opt/backup/bin/agent', fds: fd },
    }, { neverContain: ['/usr/bin/rsync', '/opt/backup/'] });
    const report = await containment.contain([CANARY]);
    expect(procfs.signals).toEqual([]);
    expect(report.action).toBe('no-writer');
    expect(report.protected_writers.map((p) => p.pid).sort((a, b) => a - b)).toEqual([1, 50, 700, 701, 702, 703, 704, 899, 900]);
  });

  it('alerts only when attribution is ambiguous', async () => {
    const table: Record<number, FakeProc> = {};
    for (const pid of [101, 102, 103, 104]) table[pid] = { comm: 'w', exe: `/opt/w${pid}`, fds: { '3': [CANARY, O_RDWR] } };
    const { containment, procfs } = make(table);
    const report = await containment.contain([CANARY]);
    expect(report.action).toBe('alert-only');
    expect(report.reason).toContain('contain_max_processes');
    expect(report.processes).toHaveLength(4);
    expect(procfs.signals).toEqual([]);
  });

  it('alerts only when the /proc walk runs out of time', async () => {
    let t = 0;
    const { containment, procfs } = make({
      10: { comm: 'a', exe: '/opt/a', fds: { '3': [CANARY, O_RDWR] } },
      11: { comm: 'b', exe: '/opt/b', fds: {} },
    }, {}, { nowMs: () => (t += 1000), budgetMs: 1500 });
    const report = await containment.contain([CANARY]);
    expect(report.incomplete).toBe(true);
    expect(report.action).toBe('alert-only');
    expect(procfs.signals).toEqual([]);
  });

  it('does not signal a pid that was recycled between scan and signal', async () => {
    const table: Record<number, FakeProc> = { 1234: { comm: 'locker', exe: '/opt/locker', fds: { '3': [CANARY, O_RDWR] }, start: 1 } };
    const procfs = fakeProcFs(table);
    let calls = 0;
    const stat = procfs.stat;
    procfs.stat = (pid: number) => {
      calls++;
      if (calls > 1) table[1234].start = 2; // same pid, new process
      return stat(pid);
    };
    const containment = new WriterContainment({
      settings: { mode: 'kill', maxProcesses: 3, neverContain: [] },
      log: () => {}, procfs, selfPid: 900, parentPid: 899, platform: 'linux',
    });
    const report = await containment.contain([CANARY]);
    expect(report.processes[0].result).toBe('gone');
    expect(procfs.signals).toEqual([]);
  });

  it('reports instead of signalling under remediation dry_run', async () => {
    const { containment, procfs } = make({ 1234: { comm: 'locker', exe: '/opt/locker', fds: { '3': [CANARY, O_RDWR] } } }, {}, { dryRun: () => true });
    const report = await containment.contain([CANARY]);
    expect(report.action).toBe('dry-run');
    expect(procfs.signals).toEqual([]);
  });

  it('records a failed signal', async () => {
    const { containment, procfs } = make({ 1234: { comm: 'locker', exe: '/opt/locker', fds: { '3': [CANARY, O_RDWR] } } });
    procfs.kill = () => { throw new Error('EPERM'); };
    const report = await containment.contain([CANARY]);
    expect(report.action).toBe('alert-only');
    expect(report.processes[0]).toMatchObject({ result: 'failed', error: 'EPERM' });
  });

  it('is inert when off or off-Linux', async () => {
    const off = make({ 1234: { comm: 'l', exe: '/opt/l', fds: { '3': [CANARY, O_RDWR] } } }, { mode: 'off' });
    expect(off.containment.enabled).toBe(false);
    expect((await off.containment.contain([CANARY])).action).toBe('alert-only');
    const mac = make({ 1234: { comm: 'l', exe: '/opt/l', fds: { '3': [CANARY, O_RDWR] } } }, {}, { platform: 'darwin' });
    expect(mac.containment.enabled).toBe(false);
    await mac.containment.contain([CANARY]);
    expect(off.procfs.signals.concat(mac.procfs.signals)).toEqual([]);
  });
});

describe('FileIntegrityWatch contain_writer', () => {
  const dirs: string[] = [];
  afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

  async function canaryHit(contain_writer: 'off' | 'stop') {
    const dir = mkdtempSync(join(tmpdir(), 'tc-fim-contain-'));
    dirs.push(dir);
    const canary = join(dir, 'decoy.txt');
    writeFileSync(canary, 'decoy\n');
    const events: ThreatEvent[] = [];
    const procfs = fakeProcFs({ 4321: { comm: 'locker', exe: '/opt/locker', fds: { '3': [canary, O_RDWR] } } });
    const watch = new FileIntegrityWatch({
      bus: { publish: (event) => events.push(event) },
      baselinePath: join(dir, 'state', 'baseline.json'),
      observedPath: join(dir, 'state', 'observed.json'),
      settings: fileIntegritySettings({ enabled: true, canaries: [canary], contain_writer }),
      log: () => {},
      procfs,
    });
    expect((await watch.rebaseline()).ok).toBe(true);
    writeFileSync(canary, 'encrypted garbage\n');
    await (watch as unknown as { scanOnce(): Promise<void> }).scanOnce();
    return { events, procfs };
  }

  it('stops the canary writer and records it in the critical event', async () => {
    const { events, procfs } = await canaryHit('stop');
    expect(procfs.signals).toEqual([[4321, 'SIGSTOP']]);
    const event = events.find((e) => e.details?.rule_id === 'file-integrity-canary')!;
    expect(event.severity).toBe('critical');
    expect(event.message).toContain('pid 4321');
    expect(event.details?.containment).toMatchObject({
      mode: 'stop',
      action: 'contained',
      processes: [expect.objectContaining({ pid: 4321, exe: '/opt/locker', signal: 'SIGSTOP', result: 'sent' })],
    });
  });

  it('only alerts when contain_writer is off', async () => {
    const { events, procfs } = await canaryHit('off');
    expect(procfs.signals).toEqual([]);
    const event = events.find((e) => e.details?.rule_id === 'file-integrity-canary')!;
    expect(event.details?.containment).toBeUndefined();
  });
});
