/**
 * Small process / file helpers shared by the network-exposure and
 * secrets-on-disk host checks. Kept apart from checks.ts so those checks can
 * be read (and tested) on their own.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';

export interface RunOut { code: number | null; stdout: string; stderr: string; missing: boolean; timedOut: boolean }

export function sysRun(cmd: string, args: string[], timeoutMs = 60_000, extra: { uid?: number; gid?: number; cwd?: string } = {}): RunOut {
  const r = spawnSync(cmd, args, {
    encoding: 'utf-8', timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, ...extra,
    env: { ...process.env, LC_ALL: 'C', LANG: 'C', PATH: `${process.env.PATH ?? ''}:/usr/local/sbin:/usr/sbin:/sbin` },
  });
  const err = r.error as NodeJS.ErrnoException | undefined;
  return {
    code: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    missing: err?.code === 'ENOENT',
    timedOut: err?.code === 'ETIMEDOUT' || r.signal === 'SIGTERM',
  };
}

export function sysWhich(cmd: string): string | null {
  for (const dir of `${process.env.PATH ?? ''}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.split(':')) {
    if (!dir) continue;
    const p = `${dir}/${cmd}`;
    try { if (statSync(p).isFile()) return p; } catch { /* next */ }
  }
  return null;
}

export function sysRead(path: string): string | null {
  try { return readFileSync(path, 'utf-8'); } catch { return null; }
}
