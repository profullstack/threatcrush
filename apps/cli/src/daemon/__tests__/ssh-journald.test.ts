import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setImmediate as nextTurn } from 'node:timers/promises';
import type { ThreatEvent } from '../../types/events.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { RuleEngine } from '../rules/engine.js';

/**
 * A stand-in for journalctl: every spawned `journalctl -f` is a child whose
 * stdout receives the records its arguments would select — `--user` gets the
 * user's journal, bare `FIELD=value` matches filter the system journal (same
 * field ORed, different fields ANDed), no matches means everything.
 */
const journal = vi.hoisted(() => ({
  children: [] as Array<{ args: string[]; stdout: PassThrough }>,
  authLog: '',
  dir: '',
}));

// The factory runs when module-host first loads child_process, after the
// static imports above have been evaluated.
vi.mock('node:child_process', () => ({
  spawn: (_cmd: string, args: string[]) => {
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), kill: () => true });
    journal.children.push({ args, stdout: child.stdout });
    return child;
  },
  // Probes: journalctl is present and the system journal holds a root record.
  spawnSync: () => ({ status: 0, stdout: 'systemd[1]: Started Journal Service.\n', stderr: '' }),
}));
vi.mock('../../core/state.js', () => ({
  insertEvent: () => {},
  getModuleState: () => undefined,
  setModuleState: () => {},
}));
vi.mock('../paths.js', () => ({
  PATHS: {
    configDir: join(tmpdir(), 'tc-ssh-journald-no-config'),
    get moduleDir() { return join(journal.dir, 'modules'); },
    get confD() { return join(journal.dir, 'conf.d'); },
  },
}));
vi.mock('../../modules/network-monitor/index.js', () => ({
  NetworkMonitor: class { start() { return false; } stop() {} },
}));
vi.mock('../../modules/dns-monitor/index.js', () => ({
  DnsMonitor: class { start() { return false; } stop() {} },
}));
// The daemon's auth log, at a path the test owns.
vi.mock('../watchers/log-watcher.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../watchers/log-watcher.js')>();
  return {
    ...orig,
    LogWatcher: class extends orig.LogWatcher {
      constructor(bus: ConstructorParameters<typeof orig.LogWatcher>[0]) {
        super(bus, [{ path: journal.authLog, module: 'ssh-guard', category: 'auth' }]);
      }
    },
  };
});

const { EventBus } = await import('../event-bus.js');
const { ModuleHost } = await import('../module-host.js');
const { LogWatcher } = await import('../watchers/log-watcher.js');
const { sshEventFromJournal } = await import('../watchers/journal-watcher.js');

type JournalRecord = { [field: string]: string };

function sshdRecord(comm: string, message: string, uid = '0'): JournalRecord {
  return {
    __REALTIME_TIMESTAMP: String(Date.now() * 1000),
    _UID: uid,
    _COMM: comm,
    SYSLOG_IDENTIFIER: comm,
    _SYSTEMD_UNIT: 'ssh.service',
    PRIORITY: '6',
    MESSAGE: message,
  };
}

function selects(args: string[], record: JournalRecord): boolean {
  if (args.includes('--user')) return record._UID !== '0';
  const matches = new Map<string, string[]>();
  for (const arg of args) {
    const m = arg.match(/^([A-Z_]+)=(.*)$/);
    if (m) matches.set(m[1], [...(matches.get(m[1]) ?? []), m[2]]);
  }
  return [...matches].every(([field, values]) => values.includes(record[field]));
}

/** journald receives one record; every follower that selects it sees it. */
function journalLogs(record: JournalRecord): void {
  for (const child of journal.children) {
    if (selects(child.args, record)) child.stdout.write(`${JSON.stringify(record)}\n`);
  }
}

/** Starts the daemon's module host, collecting what reaches the rule engine. */
async function daemon() {
  const bus = new EventBus();
  const events: ThreatEvent[] = [];
  const fired: Array<{ rule_id: string; source_ip?: string }> = [];
  const engine = new RuleEngine((d) => fired.push(d));
  engine.loadRules(DEFAULT_RULES);
  bus.on('event', (e: ThreatEvent) => {
    events.push(e);
    engine.evaluate(e);
  });
  const host = new ModuleHost(bus);
  await host.start();
  return { host, events, fired, ssh: () => events.filter((e) => e.module === 'ssh-guard') };
}

beforeEach(() => {
  journal.dir = mkdtempSync(join(tmpdir(), 'tc-ssh-journald-'));
  journal.authLog = join(journal.dir, 'auth.log');
  journal.children = [];
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(journal.dir, { recursive: true, force: true });
});

describe.each([
  ['sshd', 'user'],
  ['sshd-session', 'user'],
  ['sshd', 'root'],
  ['sshd-session', 'root'],
])('journald-only host, %s logging, daemon as %s', (comm, mode) => {
  beforeEach(() => {
    if (mode === 'root') vi.spyOn(process as Required<NodeJS.Process>, 'getuid').mockReturnValue(0);
  });

  it('fires ssh-brute-force on the fifth failed login, not before', async () => {
    const { host, fired, ssh } = await daemon();
    try {
      for (let i = 1; i <= 5; i++) {
        journalLogs(sshdRecord(comm, `Failed password for root from 198.51.100.23 port ${40000 + i} ssh2`));
        await nextTurn();
        const bruteForce = fired.filter((d) => d.rule_id === 'ssh-brute-force');
        expect(bruteForce.length, `after ${i} failures`).toBe(i < 5 ? 0 : 1);
      }
      expect(fired.find((d) => d.rule_id === 'ssh-brute-force')?.source_ip).toBe('198.51.100.23');
      // One event per record, however many journal followers carried it.
      expect(ssh()).toHaveLength(5);
    } finally {
      await host.stop();
    }
  });
});

describe.each(['user', 'root'])('auth log present and tailed, daemon as %s', (mode) => {
  beforeEach(() => {
    if (mode === 'root') vi.spyOn(process as Required<NodeJS.Process>, 'getuid').mockReturnValue(0);
    writeFileSync(journal.authLog, '');
    // log-watcher polls the file on an interval; step it by hand.
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
  });

  afterEach(() => vi.useRealTimers());

  it('counts a failed login that is in both auth.log and the journal once', async () => {
    const { host, fired, ssh } = await daemon();
    try {
      // Four attempts: under the threshold of 5 — but eight if double counted.
      for (let i = 1; i <= 4; i++) {
        const message = `Failed password for root from 198.51.100.23 port ${40000 + i} ssh2`;
        appendFileSync(journal.authLog, `2026-09-25T09:23:3${i}.141344+00:00 host sshd-session[8407${i}]: ${message}\n`);
        journalLogs(sshdRecord('sshd-session', message));
      }
      // A last line only the file has: once it arrives, log-watcher has read
      // everything before it, and the journal followers have long delivered.
      appendFileSync(journal.authLog, '2026-09-25T09:23:39.000000+00:00 host sshd-session[84079]: Accepted publickey for sentinel from 192.0.2.99 port 51234 ssh2\n');
      vi.advanceTimersToNextTimer();
      await vi.waitFor(() => expect(ssh().some((e) => e.message.includes('sentinel'))).toBe(true));

      expect(ssh().filter((e) => e.message.startsWith('Failed SSH login'))).toHaveLength(4);
      expect(fired.filter((d) => d.rule_id === 'ssh-brute-force')).toEqual([]);
    } finally {
      await host.stop();
    }
  });
});

describe('sshEventFromJournal', () => {
  /** What log-watcher publishes for one auth.log line. */
  function fromAuthLog(line: string): ThreatEvent | undefined {
    let published: ThreatEvent | undefined;
    const bus = { publish: (e: ThreatEvent) => { published = e; } } as never;
    const watcher = new LogWatcher(bus) as unknown as {
      process(line: string, src: { path: string; module: string; category: string }): void;
    };
    watcher.process(line, { path: '/var/log/auth.log', module: 'ssh-guard', category: 'auth' });
    return published;
  }

  it.each([
    'Failed password for invalid user admin from 203.0.113.4 port 50154 ssh2',
    'Invalid user gateway from 114.12.17.98 port 33654',
    'Accepted publickey for anthony from 192.0.2.10 port 51234 ssh2: ED25519 SHA256:abc',
  ])('makes the event log-watcher makes of the same auth.log line: %s', (message) => {
    const { timestamp: _a, ...fromJournal } = sshEventFromJournal(sshdRecord('sshd-session', message))!;
    const { timestamp: _b, ...fromFile } = fromAuthLog(`Sep 25 16:47:29 dev sshd-session[4111430]: ${message}`)!;
    expect(fromJournal).toEqual(fromFile);
  });

  it('ignores a record a local user forged with `logger -t sshd`', () => {
    const forged = { ...sshdRecord('logger', 'Failed password for root from 198.51.100.23 port 22 ssh2', '1000'), SYSLOG_IDENTIFIER: 'sshd' };
    expect(sshEventFromJournal(forged)).toBeNull();
    expect(sshEventFromJournal({ ...forged, _COMM: 'sshd' })).toBeNull();
  });

  it('ignores sshd lines that are not a login outcome', () => {
    expect(sshEventFromJournal(sshdRecord('sshd', 'Connection closed by 93.123.109.6 port 30900'))).toBeNull();
  });
});
