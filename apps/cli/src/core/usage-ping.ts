import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { apiUrl, CLI_CONFIG_DIR } from './cli-config.js';
import type { Severity } from './run-result.js';
import { PKG_VERSION } from './version.js';

// One anonymous usage ping per ai-scan run, so threatcrush.com can count how
// often the scanner is used. ai-scan runs on the user's machine and otherwise
// sends nothing home. (Error reporting is a separate thing: core/telemetry.ts.)
//
// What is sent: the command, CLI version, OS, Node version, whether it ran in
// CI, a random per-machine install id, and counts (probes, findings by
// severity, scans in a .mosh script, duration). What is never sent: the target
// URL, headers, prompts, responses or finding text.
//
// Off with THREATCRUSH_TELEMETRY=0 (or off/false/no) or DO_NOT_TRACK=1. The
// first run prints a one-line notice saying so.

const STATE_FILE = 'usage-ping.json';

export interface UsagePing {
  event: 'ai-scan' | 'ai-scan-run';
  probes?: number;
  scans?: number;
  findings: number;
  severity?: Partial<Record<Severity, number>>;
  duration_ms: number;
  failed?: boolean;
}

export function usagePingDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env.THREATCRUSH_TELEMETRY ?? '').trim().toLowerCase();
  if (['0', 'off', 'false', 'no'].includes(v)) return true;
  const dnt = (env.DO_NOT_TRACK ?? '').trim().toLowerCase();
  return dnt !== '' && dnt !== '0' && dnt !== 'false';
}

/** The random install id, created on first use; `fresh` is true that once (for the notice). */
export function installId(dir = CLI_CONFIG_DIR): { id: string; fresh: boolean } {
  const file = join(dir, STATE_FILE);
  try {
    const j = JSON.parse(readFileSync(file, 'utf-8')) as { install_id?: string };
    if (j.install_id) return { id: j.install_id, fresh: false };
  } catch {}
  const id = randomUUID();
  try {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(file, JSON.stringify({ install_id: id, created_at: new Date().toISOString() }) + '\n');
  } catch {}
  return { id, fresh: true };
}

export function pingBody(p: UsagePing, id: string, env: NodeJS.ProcessEnv = process.env) {
  return {
    ...p,
    version: PKG_VERSION,
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    ci: Boolean(env.CI || env.GITHUB_ACTIONS),
    install_id: id,
  };
}

/** Best effort: never throws, gives up after `timeoutMs` so it cannot hold the CLI open. */
export async function sendUsagePing(
  p: UsagePing,
  opts: { fetchImpl?: typeof fetch; dir?: string; timeoutMs?: number; notice?: (s: string) => void; env?: NodeJS.ProcessEnv } = {},
): Promise<boolean> {
  const env = opts.env ?? process.env;
  if (usagePingDisabled(env)) return false;
  try {
    const { id, fresh } = installId(opts.dir);
    if (fresh) {
      (opts.notice ?? ((s) => process.stderr.write(s + '\n')))(
        'threatcrush: sends an anonymous usage count per ai-scan run (no targets, no findings text). Turn off with THREATCRUSH_TELEMETRY=0.',
      );
    }
    const res = await (opts.fetchImpl ?? fetch)(`${apiUrl()}/api/telemetry`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(pingBody(p, id, env)),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 2_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
