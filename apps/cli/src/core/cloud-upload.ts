import { execFileSync } from 'node:child_process';
import { hostname } from 'node:os';
import { resolve } from 'node:path';
import chalk from 'chalk';
import { cloudFetch, hasSession, readCliConfig } from './cli-config.js';
import { workerId, type RunResult } from './run-result.js';

// Signed in? Then every `scan`, `pentest` and `ai-scan` result goes to the
// current org on threatcrush.com, where its findings are tracked across runs
// (new / still open / fixed) and triaged from the web app, desktop app and
// `threatcrush findings`. Not signed in, `--no-upload`, THREATCRUSH_UPLOAD=0:
// nothing leaves the machine. An upload never changes the command's exit code.

export type UploadSource = 'scan' | 'pentest' | 'ai-scan';

export interface UploadOptions {
  source: UploadSource;
  target: string;
  kind: 'repo' | 'url' | 'api';
  scope?: string;
  /** commander's --no-upload sets this false */
  upload?: boolean;
  /** stdout carries json/sarif: say things on stderr */
  machineReadable?: boolean;
  env?: NodeJS.ProcessEnv;
}

export interface UploadOutcome {
  uploaded: boolean;
  reason?: 'disabled' | 'signed-out' | 'no-org' | 'error';
  sync?: { new: number; seen: number; reopened: number; fixed: number };
  propertyName?: string;
}

export function uploadDisabled(upload: boolean | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  if (upload === false) return true;
  const v = (env.THREATCRUSH_UPLOAD ?? '').trim().toLowerCase();
  return ['0', 'off', 'false', 'no'].includes(v);
}

/** A URL target without credentials, query or fragment (they can hold tokens). */
export function cleanUrl(raw: string): string {
  try {
    const u = new URL(raw);
    u.username = '';
    u.password = '';
    u.search = '';
    u.hash = '';
    return u.toString();
  } catch {
    return raw.split(/[?#]/)[0];
  }
}

/**
 * The property a local scan belongs to: the repo's origin remote (credentials
 * stripped) when there is one, so every clone of a repo shares its findings,
 * else this machine's path. scope = where in the repo, so scanning a subfolder
 * never marks the rest of the repo's findings fixed.
 */
export function repoTarget(path: string, run = (args: string[]) => execFileSync('git', args, { cwd: resolve(path), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5_000 }).trim()): { target: string; root: string; sub: string } {
  const abs = resolve(path);
  try {
    const root = run(['rev-parse', '--show-toplevel']);
    const sub = abs === root ? '.' : abs.slice(root.length + 1);
    let remote = '';
    try { remote = run(['remote', 'get-url', 'origin']); } catch {}
    if (remote) {
      // git@github.com:org/repo.git and https://user:tok@github.com/org/repo.git -> github.com/org/repo
      const m = /^(?:[a-z+]+:\/\/)?(?:[^@/]+@)?([^/:]+)[:/](.+?)(?:\.git)?\/?$/i.exec(remote);
      if (m) return { target: `${m[1]}/${m[2]}`, root, sub };
    }
    return { target: `${hostname()}:${root}`, root, sub };
  } catch {
    return { target: `${hostname()}:${abs}`, root: abs, sub: '.' };
  }
}

export async function uploadResult(result: RunResult, opts: UploadOptions): Promise<UploadOutcome> {
  const say = (line: string) => (opts.machineReadable ? process.stderr : process.stdout).write(`${line}\n`);
  if (uploadDisabled(opts.upload, opts.env)) return { uploaded: false, reason: 'disabled' };
  if (!hasSession()) {
    if (!opts.machineReadable && process.stdout.isTTY) {
      say(chalk.dim(`  Sign in with ${chalk.white('threatcrush login')} to track these findings in the cloud and triage them anywhere.\n`));
    }
    return { uploaded: false, reason: 'signed-out' };
  }
  const cfg = readCliConfig();
  if (!cfg.current_org_id) {
    say(chalk.yellow(`  Not saved to the cloud: no current org. Pick one with ${chalk.white('threatcrush orgs use <slug>')}.\n`));
    return { uploaded: false, reason: 'no-org' };
  }
  try {
    const res = await cloudFetch(`/api/orgs/${cfg.current_org_id}/scan-findings/report`, {
      method: 'POST',
      timeoutMs: 30_000,
      body: JSON.stringify({
        source: opts.source,
        target: opts.target,
        kind: opts.kind,
        scope: opts.scope ?? '',
        worker_id: workerId(),
        result: {
          // ai-scan and pentest put the target URL in each finding's location:
          // clean it like the target, or a ?key= in the URL reaches the cloud.
          findings: result.findings.map((f) => (f.location && /^https?:\/\//i.test(f.location) ? { ...f, location: cleanUrl(f.location) } : f)),
          severity_summary: result.severity_summary,
          summary: result.summary,
          error: result.error,
        },
      }),
    });
    const data = await res.json().catch(() => ({})) as { sync?: UploadOutcome['sync']; property_name?: string; error?: string };
    if (!res.ok || !data.sync) {
      say(chalk.yellow(`  Not saved to the cloud: ${data.error || `HTTP ${res.status}`}.\n`));
      return { uploaded: false, reason: 'error' };
    }
    const s = data.sync;
    const org = cfg.current_org_slug || 'your org';
    const parts = [`${s.new} new`, `${s.seen + s.reopened} still open${s.reopened ? ` (${s.reopened} back after a fix)` : ''}`, `${s.fixed} fixed`];
    say(chalk.cyan(`  ☁ Saved to ${org}: ${parts.join(' · ')}. Triage with ${chalk.white('threatcrush findings')} or on threatcrush.com/org/${org}/findings\n`));
    return { uploaded: true, sync: s, propertyName: data.property_name };
  } catch (err) {
    say(chalk.yellow(`  Not saved to the cloud: ${(err as Error).message}.\n`));
    return { uploaded: false, reason: 'error' };
  }
}
