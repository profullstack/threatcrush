import { existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

function canWriteSystemPaths(): boolean {
  if (process.platform !== 'linux') return false;
  if (process.getuid && process.getuid() === 0) return true;
  try {
    if (!existsSync('/etc/threatcrush')) return false;
    mkdirSync('/etc/threatcrush/.probe', { recursive: true });
    return true;
  } catch {
    return false;
  }
}

const systemMode = canWriteSystemPaths();
const userBase = join(homedir(), '.threatcrush');

export const PATHS = systemMode
  ? {
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
    }
  : {
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

export function ensureRuntimeDirs(): void {
  for (const dir of [PATHS.configDir, PATHS.confD, PATHS.moduleDir, PATHS.logDir, PATHS.stateDir, PATHS.runDir]) {
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
      // best-effort
    }
  }
}
