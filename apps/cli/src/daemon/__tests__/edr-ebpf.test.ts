import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ChildProcess } from 'node:child_process';
import {
  BpftraceSource,
  bpftraceArgs,
  bpftraceScript,
  parseBpftraceLine,
  selectEdrSource,
} from '../workers/edr-ebpf.js';
import { EdrWatch, ebpfEventToRecords, edrSettings, readEdrSourceStatus } from '../workers/edr.js';
import type { ThreatEvent } from '../../types/events.js';

const json = (data: string) => JSON.stringify({ type: 'printf', data });

describe('parseBpftraceLine', () => {
  it('parses a JSON-wrapped exec record', () => {
    expect(parseBpftraceLine(json('TC1\texec\t4242\t1000\t33\t/usr/bin/bash\n'))).toEqual({
      type: 'event',
      event: { kind: 'exec', pid: 4242, ppid: 1000, euid: 33, filename: '/usr/bin/bash', comm: 'bash' },
    });
  });

  it('parses connect and listen records with comm as the last field', () => {
    expect(parseBpftraceLine(json('TC1\tconnect\t7\t1\t0\tbash\n'))).toEqual({
      type: 'event', event: { kind: 'connect', pid: 7, ppid: 1, euid: 0, comm: 'bash' },
    });
    expect(parseBpftraceLine('TC1\tlisten\t8\t1\t33\tnc')).toEqual({
      type: 'event', event: { kind: 'listen', pid: 8, ppid: 1, euid: 33, comm: 'nc' },
    });
  });

  it('keeps tabs and escaped newlines inside the trailing string field', () => {
    const parsed = parseBpftraceLine(json('TC1\texec\t9\t1\t0\t/tmp/a\tb\nc\n'));
    expect(parsed).toMatchObject({ type: 'event', event: { pid: 9, euid: 0, filename: '/tmp/a\tb\nc' } });
  });

  it('truncates exec comm to the kernel 15-byte basename', () => {
    const parsed = parseBpftraceLine(json('TC1\texec\t9\t1\t0\t/opt/averyveryverylongbinaryname\n'));
    expect(parsed).toMatchObject({ event: { comm: 'averyveryverylo' } });
  });

  it('reports bpftrace control messages', () => {
    expect(parseBpftraceLine('{"type": "attached_probes", "data": {"probes": 3}}')).toEqual({ type: 'attached', probes: 3 });
    expect(parseBpftraceLine('{"type": "lost_events", "data": {"events": 12}}')).toEqual({ type: 'lost', count: 12 });
  });

  it('rejects malformed, foreign and forged lines', () => {
    for (const line of [
      '',
      'garbage',
      '{not json',
      json('XX1\texec\t1\t1\t0\t/bin/sh\n'),
      json('TC1\tfork\t1\t1\t0\t/bin/sh\n'),
      json('TC1\texec\t-1\t1\t0\t/bin/sh\n'),
      json('TC1\texec\t0\t1\t0\t/bin/sh\n'),
      json('TC1\texec\t1x\t1\t0\t/bin/sh\n'),
      json('TC1\texec\t1\t1\t0\t\n'),
      json('TC1\texec\t1\t1\t0'),
      '{"type": "printf", "data": 5}',
      '{"type": "map", "data": {}}',
    ]) {
      expect(parseBpftraceLine(line), line).toBeNull();
    }
  });
});

describe('bpftrace program', () => {
  it('traces exec always and TCP connect/listen only when network watching is on', () => {
    const base = bpftraceScript({ network: false });
    expect(base).toContain('tracepoint:sched:sched_process_exec');
    expect(base).not.toContain('inet_sock_set_state');
    const net = bpftraceScript({ network: true });
    expect(net).toContain('args.newstate == 2');
    expect(net).toContain('args.newstate == 10');
    expect(net).not.toMatch(/argv/);
  });

  it('is passed as one argv element with JSON line output', () => {
    const args = bpftraceArgs({ network: false });
    expect(args.slice(0, 6)).toEqual(['-q', '-B', 'line', '-f', 'json', '-e']);
    expect(args).toHaveLength(7);
  });
});

describe('selectEdrSource', () => {
  const ready = { bpftracePath: '/usr/bin/bpftrace', btfPresent: true, isRoot: true, platform: 'linux' as const };

  it('keeps auditd when configured, even on an eBPF-capable host', () => {
    expect(selectEdrSource({ configured: 'auditd', ...ready })).toMatchObject({ source: 'auditd', degraded: false });
  });

  it('auto picks eBPF only when bpftrace, BTF and root are all present', () => {
    expect(selectEdrSource({ configured: 'auto', ...ready }).source).toBe('ebpf');
    expect(selectEdrSource({ configured: 'auto', ...ready, bpftracePath: null })).toMatchObject({ source: 'auditd', degraded: false });
    expect(selectEdrSource({ configured: 'auto', ...ready, btfPresent: false }).source).toBe('auditd');
    expect(selectEdrSource({ configured: 'auto', ...ready, isRoot: false }).reason).toMatch(/not running as root/);
    expect(selectEdrSource({ configured: 'auto', ...ready, platform: 'darwin' }).source).toBe('auditd');
  });

  it('explicit ebpf falls back to auditd and flags the degradation', () => {
    expect(selectEdrSource({ configured: 'ebpf', ...ready }).source).toBe('ebpf');
    expect(selectEdrSource({ configured: 'ebpf', ...ready, bpftracePath: null })).toMatchObject({ source: 'auditd', degraded: true });
  });

  it('parses the config option with auditd as the default', () => {
    expect(edrSettings(undefined).source).toBe('auditd');
    expect(edrSettings({ source: 'auto' }).source).toBe('auto');
    expect(edrSettings({ source: 'ebpf' }).source).toBe('ebpf');
    expect(edrSettings({ source: 'bogus' as never }).source).toBe('auditd');
  });
});

describe('ebpfEventToRecords', () => {
  it('normalizes exec into one candidate record per execution rule key', () => {
    const records = ebpfEventToRecords({ kind: 'exec', pid: 5, ppid: 1, euid: 33, filename: '/bin/sh', comm: 'sh' }, () => '/usr/bin/dash');
    expect(records.map((record) => record.key)).toEqual(['threatcrush_edr_miner', 'threatcrush_edr_web', 'threatcrush_edr_temp']);
    expect(records[0]).toMatchObject({ source: 'ebpf', executable: '/usr/bin/dash', euid: 33, pid: 5, ppid: 1 });
  });

  it('falls back to an absolute filename and drops unresolvable relative ones', () => {
    expect(ebpfEventToRecords({ kind: 'exec', pid: 5, ppid: 1, euid: 0, filename: '/tmp/x', comm: 'x' }, () => null)[0].executable).toBe('/tmp/x');
    expect(ebpfEventToRecords({ kind: 'exec', pid: 5, ppid: 1, euid: 0, filename: './x', comm: 'x' }, () => null)).toEqual([]);
  });

  it('maps connect and listen onto the network rule keys', () => {
    expect(ebpfEventToRecords({ kind: 'connect', pid: 5, ppid: 1, euid: 0, comm: 'bash' }, () => '/usr/bin/bash')[0].key).toBe('threatcrush_edr_connect');
    expect(ebpfEventToRecords({ kind: 'listen', pid: 5, ppid: 1, euid: 0, comm: 'nc' }, () => '/usr/bin/nc')[0].key).toBe('threatcrush_edr_listen');
  });
});

describe('EdrWatch with the eBPF source', () => {
  const dirs: string[] = [];
  afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

  function watch(overrides: Parameters<typeof edrSettings>[0] = {}) {
    const events: ThreatEvent[] = [];
    const logs: string[] = [];
    const dir = mkdtempSync(join(tmpdir(), 'tc-edr-'));
    dirs.push(dir);
    let fatal: ((reason: string) => void) | null = null;
    const started = vi.fn();
    const stopped = vi.fn();
    const edr = new EdrWatch({
      bus: { publish: (event) => events.push(event) },
      settings: { ...edrSettings({ enabled: true, source: 'ebpf', watch_unknown_temp_cpu: false, audit_log_path: join(dir, 'audit.log'), ...overrides }) },
      sourceStatusPath: join(dir, 'edr-source.json'),
      probeHost: (configured) => ({ configured, bpftracePath: '/usr/bin/bpftrace', btfPresent: true, isRoot: true, platform: 'linux' }),
      createBpftrace: (opts) => { fatal = opts.onFatal; return { start: started, stop: stopped }; },
      log: (line) => logs.push(line),
    });
    return { edr, events, logs, dir, started, stopped, fail: (reason: string) => fatal?.(reason) };
  }

  it('starts bpftrace, records the active source and runs the shared rules', () => {
    const { edr, events, dir, started, stopped } = watch({ temp_exec_paths: ['/tmp'] });
    edr.start();
    expect(started).toHaveBeenCalledOnce();
    expect(edr.source).toBe('ebpf');
    expect(readEdrSourceStatus(join(dir, 'edr-source.json'))).toMatchObject({ configured: 'ebpf', active: 'ebpf' });

    const miner = edr.handleEbpfEvent({ kind: 'exec', pid: 10, ppid: 1, euid: 0, filename: '/opt/xmrig', comm: 'xmrig' }, () => '/opt/xmrig');
    expect(miner?.details).toMatchObject({ rule_id: 'edr-known-miner-execution', event_source: 'ebpf', pid: 10 });
    expect(miner?.details).not.toHaveProperty('audit_serial');

    const temp = edr.handleEbpfEvent({ kind: 'exec', pid: 11, ppid: 1, euid: 0, filename: '/tmp/payload', comm: 'payload' }, () => '/tmp/payload');
    expect(temp?.details).toMatchObject({ rule_id: 'edr-writable-path-execution' });

    expect(edr.handleEbpfEvent({ kind: 'exec', pid: 12, ppid: 1, euid: 0, filename: '/usr/bin/ls', comm: 'ls' }, () => '/usr/bin/ls')).toBeNull();
    expect(events).toHaveLength(2);
    edr.stop();
    expect(stopped).toHaveBeenCalledOnce();
  });

  it('ignores network events unless network watching is enabled, then flags shell connects', () => {
    const off = watch();
    off.edr.start();
    expect(off.edr.handleEbpfEvent({ kind: 'connect', pid: 3, ppid: 1, euid: 33, comm: 'bash' }, () => '/usr/bin/bash')).toBeNull();
    off.edr.stop();

    const on = watch({ watch_network_syscalls: true });
    on.edr.start();
    const shell = on.edr.handleEbpfEvent({ kind: 'connect', pid: 3, ppid: 1, euid: 33, comm: 'bash' }, () => '/usr/bin/bash');
    expect(shell?.details).toMatchObject({ rule_id: 'edr-shell-network-connect' });
    const listen = on.edr.handleEbpfEvent({ kind: 'listen', pid: 4, ppid: 1, euid: 0, comm: 'nc' }, () => '/usr/bin/nc');
    expect(listen?.details).toMatchObject({ rule_id: 'edr-process-listener' });
    on.edr.stop();
  });

  it('falls back to auditd when bpftrace cannot be started', () => {
    const { edr, dir, fail, logs } = watch();
    writeFileSync(join(dir, 'audit.log'), '');
    edr.start();
    fail('bpftrace failed to start 3 time(s): ERROR: permission denied');
    expect(edr.source).toBe('auditd');
    expect(readEdrSourceStatus(join(dir, 'edr-source.json'))?.reason).toMatch(/eBPF failed/);
    expect(logs.some((line) => line.includes('falling back to auditd'))).toBe(true);
    edr.stop();
  });

  it('does not probe or spawn bpftrace when source is auditd', () => {
    const { edr, started } = watch({ source: 'auditd' });
    edr.start();
    expect(started).not.toHaveBeenCalled();
    expect(edr.source).toBe('none'); // no audit log in the temp dir
    edr.stop();
  });
});

class FakeChild extends EventEmitter {
  stdout = new PassThrough();
  stderr = new PassThrough();
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  kill = vi.fn((signal?: NodeJS.Signals) => {
    this.signalCode = signal ?? 'SIGTERM';
    this.emit('exit', null, this.signalCode);
    return true;
  });
  exit(code: number) {
    this.exitCode = code;
    this.emit('exit', code, null);
  }
}

describe('BpftraceSource lifecycle', () => {
  afterEach(() => { vi.useRealTimers(); });

  function source(extra: Partial<ConstructorParameters<typeof BpftraceSource>[0]> = {}) {
    const children: FakeChild[] = [];
    const calls: Array<{ command: string; args: string[]; shell: unknown }> = [];
    const events: unknown[] = [];
    const fatal = vi.fn();
    const logs: string[] = [];
    const src = new BpftraceSource({
      bpftracePath: '/usr/bin/bpftrace',
      network: true,
      onEvent: (event) => events.push(event),
      onFatal: fatal,
      log: (line) => logs.push(line),
      minBackoffMs: 1000,
      maxBackoffMs: 4000,
      maxFailedStarts: 3,
      maxLineBytes: 256,
      spawn: (command, args, options) => {
        calls.push({ command, args, shell: options.shell });
        const child = new FakeChild();
        children.push(child);
        return child as unknown as ChildProcess;
      },
      ...extra,
    });
    return { src, children, calls, events, fatal, logs };
  }

  it('spawns with an argv array and no shell, and parses stdout lines', async () => {
    const { src, children, calls, events } = source();
    src.start();
    expect(calls).toHaveLength(1);
    expect(calls[0].command).toBe('/usr/bin/bpftrace');
    expect(calls[0].shell).toBe(false);
    // The second record arrives split across two chunks.
    const second = json('TC1\tconnect\t2\t1\t0\tcurl');
    children[0].stdout.write(`${json('TC1\texec\t1\t0\t0\t/bin/true\n')}\n${second.slice(0, 20)}`);
    children[0].stdout.write(`${second.slice(20)}\n`);
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({ kind: 'connect', comm: 'curl' });
    src.stop();
  });

  it('kills the child on stop and does not restart it', () => {
    vi.useFakeTimers();
    const { src, children, calls } = source();
    src.start();
    src.stop();
    expect(children[0].kill).toHaveBeenCalledWith('SIGTERM');
    vi.advanceTimersByTime(10_000);
    expect(calls).toHaveLength(1);
  });

  it('restarts with exponential backoff after a healthy run exits', () => {
    vi.useFakeTimers();
    const { src, children, calls, fatal } = source();
    src.start();
    src.ingest('{"type": "attached_probes", "data": {"probes": 3}}\n');
    children[0].exit(1);
    vi.advanceTimersByTime(999);
    expect(calls).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(calls).toHaveLength(2);
    children[1].exit(1); // never healthy: 1st failed start, backoff now 2s
    vi.advanceTimersByTime(2000);
    expect(calls).toHaveLength(3);
    expect(fatal).not.toHaveBeenCalled();
    src.stop();
  });

  it('gives up and reports fatal after repeated failed starts', () => {
    vi.useFakeTimers();
    const { src, children, calls, fatal } = source();
    src.start();
    children[0].stderr.write('ERROR: Could not resolve symbol\n');
    children[0].exit(1);
    vi.advanceTimersByTime(1000);
    children[1].exit(1);
    vi.advanceTimersByTime(2000);
    children[2].exit(1);
    expect(fatal).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(60_000);
    expect(calls).toHaveLength(3);
  });

  it('reports fatal when the binary cannot be spawned at all', () => {
    vi.useFakeTimers();
    const { src, children, fatal } = source({ maxFailedStarts: 1 });
    src.start();
    children[0].emit('error', new Error('spawn /usr/bin/bpftrace ENOENT'));
    expect(fatal).toHaveBeenCalledWith(expect.stringContaining('ENOENT'));
  });

  it('bounds the line buffer and drops an oversized unterminated line', () => {
    const { src, events, logs } = source();
    src.ingest('x'.repeat(300));
    expect(logs.some((line) => line.includes('oversized'))).toBe(true);
    src.ingest(`${json('TC1\texec\t1\t0\t0\t/bin/true\n')}\n`);
    expect(events).toHaveLength(1);
  });
});
