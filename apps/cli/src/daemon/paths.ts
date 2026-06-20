import { existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

function isRoot(): boolean {
  return (
    process.platform === 'linux' &&
    typeof process.getuid === 'function' &&
    process.getuid() === 0
  );
}

const userBase = join(homedir(), '.threatcrush');

const SYSTEM_PATHS = {
  mode: 'system' as const,
  configDir: '/etc/threatcrush',
  configFile: '/etc/threatcrush/threatcrushd.conf',
  confD: '/etc/threatcrush/threatcrushd.conf.d',
  moduleDir: '/etc/threatcrush/modules',
  logDir: '/var/log/threatcrush',
  logFile: '/var/log/threatcrush/threatcrushd.log',
  stateDir: '/var/lib/threatcrush',
  stateDb: '/var/lib/threatcrush/state.db',
  runDir: '/var/run/threatcrush',
  pidFile: '/var/run/threatcrush/threatcrushd.pid',
  socket: '/var/run/threatcrush/threatcrushd.sock',
};

const USER_PATHS = {
  mode: 'user' as const,
  configDir: userBase,
  configFile: join(userBase, 'threatcrushd.conf'),
  confD: join(userBase, 'threatcrushd.conf.d'),
  moduleDir: join(userBase, 'modules'),
  logDir: join(userBase, 'logs'),
  logFile: join(userBase, 'logs', 'threatcrushd.log'),
  stateDir: join(userBase, 'state'),
  stateDb: join(userBase, 'state', 'state.db'),
  runDir: join(userBase, 'run'),
  pidFile: join(userBase, 'run', 'threatcrushd.pid'),
  socket: join(userBase, 'run', 'threatcrushd.sock'),
};

// System paths (config/log/state/run under /etc and /var) are root-owned, so we
// only run in system mode when actually root. Choosing system mode because
// /etc/threatcrush happened to be writable, or because a stale system socket
// existed, made `threatcrush start` as a normal user crash with EACCES trying
// to open /var/log/threatcrush/threatcrushd.log. A non-root user always runs a
// self-contained daemon under ~/.threatcrush instead.
export const PATHS = isRoot() ? SYSTEM_PATHS : USER_PATHS;

// A non-root client command (status/stop/logs/tail) should still be able to
// reach a daemon that root started. Prefer this process's own socket, but fall
// back to the other mode's socket when only that one is present.
export function resolveClientSocket(): string {
  if (existsSync(PATHS.socket)) return PATHS.socket;
  const other = PATHS.mode === 'system' ? USER_PATHS.socket : SYSTEM_PATHS.socket;
  if (existsSync(other)) return other;
  return PATHS.socket;
}

export function ensureRuntimeDirs(): void {
  for (const dir of [PATHS.configDir, PATHS.confD, PATHS.moduleDir, PATHS.logDir, PATHS.stateDir, PATHS.runDir]) {
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
      // best-effort
    }
  }
}
