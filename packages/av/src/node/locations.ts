import { existsSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

export interface ScanTarget {
  path: string;
  /** How many directory levels to descend; Infinity for all. */
  depth: number;
}

type Env = Record<string, string | undefined>;

/**
 * Where malware actually lands on a home computer: downloads, the desktop,
 * temp folders and the places programs register to start at login. A quick
 * scan covers these in a minute or two instead of walking the whole disk.
 */
export function quickScanTargets(platform: NodeJS.Platform = process.platform, env: Env = process.env, home = homedir()): ScanTarget[] {
  const t: ScanTarget[] = [
    { path: join(home, 'Downloads'), depth: 3 },
    { path: join(home, 'Desktop'), depth: 2 },
  ];
  if (platform === 'win32') {
    const appData = env.APPDATA ?? join(home, 'AppData', 'Roaming');
    const local = env.LOCALAPPDATA ?? join(home, 'AppData', 'Local');
    const programData = env.ProgramData ?? env.PROGRAMDATA ?? 'C:\\ProgramData';
    t.push(
      { path: env.TEMP ?? join(local, 'Temp'), depth: 2 },
      { path: join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), depth: 1 },
      { path: join(programData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp'), depth: 1 },
      // Droppers love %APPDATA%\<random>\payload.exe; two levels catches that without crawling every app's cache.
      { path: appData, depth: 2 },
      { path: local, depth: 1 },
      { path: join(env.PUBLIC ?? 'C:\\Users\\Public'), depth: 2 },
    );
  } else if (platform === 'darwin') {
    t.push(
      { path: join(home, 'Library', 'LaunchAgents'), depth: 1 },
      { path: '/Library/LaunchAgents', depth: 1 },
      { path: '/Library/LaunchDaemons', depth: 1 },
      { path: '/Users/Shared', depth: 2 },
      { path: '/tmp', depth: 2 },
      { path: tmpdir(), depth: 2 },
    );
  } else {
    t.push(
      { path: '/tmp', depth: 2 },
      { path: '/var/tmp', depth: 2 },
      { path: '/dev/shm', depth: 2 },
      { path: join(home, '.config', 'autostart'), depth: 1 },
      { path: join(home, '.config', 'systemd', 'user'), depth: 1 },
      { path: join(home, '.local', 'bin'), depth: 1 },
      { path: '/etc/cron.d', depth: 1 },
      { path: '/etc/systemd/system', depth: 1 },
    );
  }
  const seen = new Set<string>();
  return t.filter((x) => !seen.has(x.path) && (seen.add(x.path), existsSync(x.path)));
}

/** A full scan: the whole home folder, plus the quick-scan system locations. */
export function fullScanTargets(platform: NodeJS.Platform = process.platform, env: Env = process.env, home = homedir()): ScanTarget[] {
  const quick = quickScanTargets(platform, env, home).filter((x) => !x.path.startsWith(home));
  const extra: ScanTarget[] = platform === 'linux' ? [{ path: '/opt', depth: Infinity }, { path: '/usr/local/bin', depth: 1 }] : [];
  return [{ path: home, depth: Infinity }, ...quick, ...extra.filter((x) => existsSync(x.path))];
}
