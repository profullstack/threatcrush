import { randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PATHS } from './paths.js';

/**
 * TC-33: the IPC socket is 0660 root:adm so log-reading users can query the
 * daemon without sudo. That is the intended boundary for *reads* — but it also
 * let any adm member send {"method":"shutdown"} and kill the security daemon.
 *
 * Control methods now need a token the daemon writes at startup, 0600 and
 * root-owned, inside a runtime directory that is no longer group-writable. Read
 * methods are unchanged, so the convenience the group buys is preserved.
 *
 * In user mode everything under ~/.threatcrush already belongs to the user
 * running the daemon, so the token is theirs to read — which is correct.
 */

export const CONTROL_TOKEN_FILE = join(PATHS.runDir, 'control.token');

/** Called by the daemon at startup. Rotates on every start. */
export function issueControlToken(): string {
  const token = randomBytes(32).toString('hex');
  writeFileSync(CONTROL_TOKEN_FILE, token, { mode: 0o600 });
  try {
    chmodSync(CONTROL_TOKEN_FILE, 0o600);
  } catch {
    // best-effort
  }
  return token;
}

/** Called by the CLI. Returns null when the caller cannot read the file. */
export function readControlToken(): string | null {
  if (!existsSync(CONTROL_TOKEN_FILE)) return null;
  try {
    const token = readFileSync(CONTROL_TOKEN_FILE, 'utf-8').trim();
    return token || null;
  } catch {
    // EACCES: the caller is not privileged enough to control the daemon.
    return null;
  }
}

export function tokensMatch(expected: string, provided: unknown): boolean {
  if (typeof provided !== 'string' || !provided) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  return a.length === b.length && timingSafeEqual(a, b);
}
