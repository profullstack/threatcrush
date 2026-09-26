import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { PATHS, ensureRuntimeDirs } from './paths.js';

export function writePidFile(): void {
  ensureRuntimeDirs();
  writeFileSync(PATHS.pidFile, String(process.pid), 'utf-8');
}

export function readPidFile(): number | null {
  if (!existsSync(PATHS.pidFile)) return null;
  const raw = readFileSync(PATHS.pidFile, 'utf-8').trim();
  const pid = parseInt(raw, 10);
  return Number.isFinite(pid) ? pid : null;
}

export function removePidFile(): void {
  try {
    if (existsSync(PATHS.pidFile)) unlinkSync(PATHS.pidFile);
  } catch {
    // ignore
  }
}

/**
 * The state letter from a `/proc/<pid>/stat` line (`R`, `S`, `Z`, …). The
 * command name in parentheses may itself contain spaces or `)`, so the state is
 * read after the *last* `)`.
 */
export function procStatState(stat: string): string | null {
  const close = stat.lastIndexOf(')');
  if (close === -1) return null;
  return stat.slice(close + 1).trim().charAt(0) || null;
}

/**
 * Has this process exited, leaving only an unreaped process-table entry?
 *
 * A zombie still answers `kill(pid, 0)`, but it is gone for every purpose here.
 * In a container whose PID 1 does not reap orphans (plain `docker run` without
 * `--init`), a daemon that shut down cleanly stays a zombie forever, and `stop`
 * used to wait on it, SIGKILL it to no effect, and report it "still running".
 */
function isZombie(pid: number): boolean {
  let stat: string;
  try {
    stat = readFileSync(`/proc/${pid}/stat`, 'utf-8');
  } catch {
    // No procfs (macOS), or the entry vanished between calls.
    return false;
  }
  const state = procStatState(stat);
  return state === 'Z' || state === 'X';
}

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (err) {
    // EPERM means the process exists but the current user can't signal it
    // (common: a non-root client checking on a system-mode daemon running as
    // root). Only ESRCH means the process is actually gone.
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'EPERM') return false;
  }
  return !isZombie(pid);
}

export function findRunningDaemon(): number | null {
  const pid = readPidFile();
  if (pid && isProcessAlive(pid)) return pid;
  if (pid) removePidFile();
  return null;
}
