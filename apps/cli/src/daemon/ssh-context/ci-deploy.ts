import { execFile } from 'node:child_process';
import type { CiDeployContext } from '@threatcrush/event-detail';

/**
 * What a forced-command CI key actually ran. Deploy keys pinned to
 * `command="ci-deploy owner/repo"` log one journal line per login under the
 * `ci-deploy` syslog identifier:
 *
 *   ALLOW (deploy app 5addb4f2) repo=owner/app from=192.0.2.10 cmd=/srv/deploy-app.sh 5addb4f2
 *   DENY (not on the allowlist) repo=owner/app from=192.0.2.10 cmd=rm -rf /
 *
 * The line from the login's address within a few seconds of it is the
 * session's verdict. Secret-looking `name=value` pairs in the command are
 * redacted before anything leaves the box.
 */

export interface CiDeployLine extends CiDeployContext {
  from?: string;
  atMs?: number;
}

const SECRETISH = /\b([A-Za-z_]*(?:token|secret|password|passwd|apikey|api_key|key|auth)[A-Za-z_]*)=("[^"]*"|'[^']*'|\S+)/gi;

export function redactCommand(cmd: string): string {
  return cmd.replace(SECRETISH, '$1=[redacted]').slice(0, 300);
}

/** One ci-deploy message (no syslog prefix), or null. */
export function parseCiDeployMessage(message: string): CiDeployLine | null {
  const m = /^\s*(ALLOW|DENY|DENIED|REJECT(?:ED)?)\b\s*(?:\(([^)]*)\))?(.*)$/i.exec(message);
  if (!m) return null;
  const rest = m[3] ?? '';
  const repo = /\brepo=(\S+)/.exec(rest)?.[1];
  const from = /\bfrom=(\S+)/.exec(rest)?.[1];
  const cmd = /\bcmd=(.*)$/.exec(rest)?.[1]?.trim();
  return {
    decision: m[1].toUpperCase().startsWith('ALLOW') ? 'ALLOW' : 'DENY',
    ...(m[2] ? { action: m[2].trim().slice(0, 200) } : {}),
    ...(repo ? { repo: repo.slice(0, 200) } : {}),
    ...(from ? { from } : {}),
    ...(cmd ? { command: redactCommand(cmd) } : {}),
  };
}

/** `journalctl -o short-unix` output -> parsed lines with their time. */
export function parseCiDeployJournal(text: string, tag = 'ci-deploy'): CiDeployLine[] {
  const out: CiDeployLine[] = [];
  const esc = tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`^(\\d+(?:\\.\\d+)?)\\s+\\S+\\s+${esc}(?:\\[\\d+\\])?:\\s(.*)$`);
  for (const line of text.split('\n')) {
    const m = re.exec(line);
    if (!m) continue;
    const parsed = parseCiDeployMessage(m[2]);
    if (!parsed) continue;
    const atMs = Math.round(Number(m[1]) * 1000);
    out.push({ ...parsed, atMs, at: new Date(atMs).toISOString() });
  }
  return out;
}

/** The ci-deploy line for a login from `ip` at `atMs`: same address, closest within -5s..+60s. */
export function pickCiDeploy(lines: CiDeployLine[], ip: string, atMs: number): CiDeployContext | null {
  const near = lines
    .filter((l) => l.from === ip && l.atMs !== undefined && l.atMs >= atMs - 5_000 && l.atMs <= atMs + 60_000)
    .sort((a, b) => Math.abs(a.atMs! - atMs) - Math.abs(b.atMs! - atMs));
  if (!near.length) return null;
  const { from: _from, atMs: _at, ...ctx } = near[0];
  return ctx;
}

export type JournalRunner = (args: string[]) => Promise<string | null>;

export const realJournal: JournalRunner = (args) => new Promise((resolve) => {
  execFile('journalctl', args, { timeout: 4000, maxBuffer: 1024 * 1024, encoding: 'utf-8' }, (err, stdout) => resolve(err ? null : stdout));
});

export async function findCiDeploy(ip: string, atMs: number, tag = 'ci-deploy', run: JournalRunner = realJournal): Promise<CiDeployContext | null> {
  const s = Math.floor(atMs / 1000);
  const out = await run(['-t', tag, `--since=@${s - 5}`, `--until=@${s + 60}`, '-o', 'short-unix', '--no-pager', '-q']);
  return out ? pickCiDeploy(parseCiDeployJournal(out, tag), ip, atMs) : null;
}
