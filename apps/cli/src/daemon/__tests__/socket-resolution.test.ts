import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The recovery this file exists for.
 *
 * `threatcrush restart`, run as a normal user while a root daemon was running,
 * printed "No running daemon found" and started a SECOND, user-mode daemon.
 * From then on every `blocklist` and `unblock` went to that one — which
 * answered cheerfully with an empty list while the root daemon's nftables
 * table kept dropping three hosts. Nothing anybody ran reached the daemon that
 * was doing the blocking.
 *
 * Two causes: socket resolution preferred the user socket whenever the FILE
 * existed (a stale file from a dead daemon shadowed just as well), and `start`
 * had no idea a system daemon existed because it only checks its own pid file.
 */
const PATHS_SRC = readFileSync(join(__dirname, '..', 'paths.ts'), 'utf-8');
const DAEMON_SRC = readFileSync(join(__dirname, '..', '..', 'commands', 'daemon.ts'), 'utf-8');
const WORKFLOW = readFileSync(
  join(__dirname, '..', '..', '..', '..', '..', '.github', 'workflows', 'unban-dev2.yml'),
  'utf-8',
);

describe('socket resolution', () => {
  it('honours an explicit THREATCRUSH_SOCKET override first', () => {
    expect(PATHS_SRC).toMatch(/process\.env\.THREATCRUSH_SOCKET/);
    const fn = PATHS_SRC.slice(PATHS_SRC.indexOf('export function resolveClientSocket'));
    // The override is checked before either default.
    expect(fn.indexOf('THREATCRUSH_SOCKET')).toBeLessThan(fn.indexOf('SYSTEM_PATHS.socket'));
  });

  it('prefers the system socket over the user one', () => {
    const fn = PATHS_SRC.slice(PATHS_SRC.indexOf('export function resolveClientSocket'));
    expect(fn.indexOf('SYSTEM_PATHS.socket')).toBeLessThan(fn.indexOf('USER_PATHS.socket'));
  });
});

describe('a non-root start does not shadow the system daemon', () => {
  it('checks for a system daemon, not just its own pid file', () => {
    expect(PATHS_SRC).toMatch(/export function systemDaemonPresent/);
    expect(DAEMON_SRC).toMatch(/systemDaemonPresent\(\)/);
  });

  it('points at systemctl and the socket override instead of starting one', () => {
    expect(DAEMON_SRC).toMatch(/systemctl restart threatcrushd/);
    expect(DAEMON_SRC).toMatch(/THREATCRUSH_SOCKET=/);
  });
});

describe('the break-glass workflow', () => {
  it('addresses the system socket explicitly', () => {
    // It must never reach a user-mode daemon: that is what made the last
    // recovery attempt report success while changing nothing.
    expect(WORKFLOW).toMatch(/THREATCRUSH_SOCKET=\/var\/run\/threatcrush\/threatcrushd\.sock/);
  });

  it('restarts the daemon after editing the config', () => {
    // The daemon reads its config once, at startup.
    expect(WORKFLOW).toMatch(/threatcrush restart/);
  });
});
