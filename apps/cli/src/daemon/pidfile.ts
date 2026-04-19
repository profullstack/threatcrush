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

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function findRunningDaemon(): number | null {
  const pid = readPidFile();
  if (pid && isProcessAlive(pid)) return pid;
  if (pid) removePidFile();
  return null;
}
