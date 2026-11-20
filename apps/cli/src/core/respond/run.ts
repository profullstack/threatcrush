import { spawn } from 'node:child_process';
import { applyScript, gatherScript, parseApply, parseGather } from './script.js';
import { planRespond, recordResults } from './plan.js';
import type { Report, RespondRequest } from './types.js';

/** Run a shell script (as stdin of `sh -s`) and return its stdout. */
export type ScriptRunner = (script: string) => Promise<string>;

/** Ban through the local daemon. null when no daemon answers (the script's firewall fallback is used). */
export type DaemonBan = (ip: string, ttl: string) => Promise<{ ok: boolean; message: string } | null>;

export const MAX_PARALLEL_HOSTS = 3;

async function execute(report: Report, run: ScriptRunner, ban?: DaemonBan): Promise<void> {
  const results = new Map<string, { ok: boolean; message: string }>();
  const scripted = [];
  // Bans go first (the plan already orders them first), so a killed session
  // cannot reconnect between the kill and the ban.
  for (const a of report.actions) {
    if (a.status !== 'planned') continue;
    if (a.op.op === 'ban' && ban) {
      const r = await ban(a.op.ip, a.op.ttl);
      if (r) { results.set(a.id, r); continue; }
    }
    scripted.push(a);
  }
  let effective: { remote: string; local: string } | null = null;
  if (scripted.length) {
    const out = parseApply(await run(applyScript(scripted)));
    for (const [id, r] of out.results) results.set(id, r);
    effective = out.effective;
  }
  recordResults(report, results, effective);
}

/** `respond` on this machine. */
export async function runLocal(req: RespondRequest, deps: { run: ScriptRunner; ban?: DaemonBan; allowlist?: string[] }): Promise<Report> {
  const snap = parseGather(await deps.run(gatherScript(req)));
  const report = planRespond(snap, req, { host: 'localhost', via: 'local', allowlist: deps.allowlist });
  if (req.apply && report.root) await execute(report, deps.run, deps.ban);
  return report;
}

// ─── remote hosts ───

export type SshExec = (host: string, remoteCommand: string, stdin?: string) => Promise<{ code: number; stdout: string; stderr: string }>;

const HOST_RE = /^(?:[A-Za-z0-9._-]+@)?(?:[A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])$/;

export function validHost(host: string): boolean {
  return !host.startsWith('-') && HOST_RE.test(host);
}

/** `--hosts`: a file with one host per line (# comments), or a comma/space separated list. */
export function parseHosts(spec: string, readFile: (path: string) => string | null): { hosts: string[]; errors: string[] } {
  const text = readFile(spec);
  const raw = text !== null
    ? text.split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean).map((l) => l.split(/\s+/)[0])
    : spec.split(/[\s,]+/).filter(Boolean);
  const hosts: string[] = [];
  const errors: string[] = [];
  for (const h of raw) {
    if (!validHost(h)) errors.push(`refusing unsafe host ${JSON.stringify(h)}`);
    else if (!hosts.includes(h)) hosts.push(h);
  }
  return { hosts, errors };
}

/** Run `fn` over `items`, at most `limit` at a time, results in input order. */
export async function runLimited<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

const TOKEN_RE = /^[A-Za-z0-9+/:._=,-]+$/;
const PATH_RE = /^\/[A-Za-z0-9._/-]+$/;

/** argv for `threatcrush respond` on a remote host. Every token is validated: no quoting games. */
export function remoteArgs(req: RespondRequest): string[] {
  const args: string[] = [req.sub];
  if (req.sub === 'ip') args.push(...(req.ips ?? []));
  if (req.sub === 'key') args.push(...(req.fingerprints ?? []));
  if (req.sub === 'sshd' && req.lockdown) args.push('--lockdown');
  if (req.allowRootLocalhost) args.push('--allow-root-localhost');
  if (req.allowLockout) args.push('--allow-lockout');
  if (req.ttl) args.push('--ttl', req.ttl);
  for (const r of req.searchRoots ?? []) args.push('--search', r);
  if (req.apply) args.push('--apply');
  args.push('--json');
  for (const a of args) {
    if (!TOKEN_RE.test(a) && !PATH_RE.test(a)) throw new Error(`refusing to send unsafe argument ${JSON.stringify(a)} to a remote host`);
  }
  return args;
}

/**
 * Become root when sudo allows it without a password, else run as the login
 * user (read-only). SSH_CONNECTION is handed through so the lockout guard can
 * find this session's key; sudo would otherwise drop it. Wrapped in `sh -c`
 * so a fish or csh login shell does not matter.
 */
export const REMOTE_SH = `sh -c 'if sudo -n true 2>/dev/null; then exec sudo -n env TC_SSH_CONNECTION="$SSH_CONNECTION" sh -s; else exec env TC_SSH_CONNECTION="$SSH_CONNECTION" sh -s; fi'`;
// Grep the help for a subcommand: an older CLI without `respond` would run its
// default action and still exit 0.
export const REMOTE_PROBE = `sh -c 'command -v threatcrush >/dev/null 2>&1 && threatcrush respond --help 2>/dev/null </dev/null | grep -q keys-audit && echo TC_RESPOND_OK'`;

export function remoteCliCommand(req: RespondRequest): string {
  const args = remoteArgs(req).join(' ');
  return `sh -c 'TC=$(command -v threatcrush); if sudo -n true 2>/dev/null; then exec sudo -n env PATH="$PATH" TC_SSH_CONNECTION="$SSH_CONNECTION" "$TC" respond ${args}; else exec env TC_SSH_CONNECTION="$SSH_CONNECTION" "$TC" respond ${args}; fi'`;
}

function extractReport(stdout: string): Report | null {
  const start = stdout.indexOf('{');
  if (start === -1) return null;
  try {
    const parsed = JSON.parse(stdout.slice(start)) as Report | { hosts?: Report[] };
    if ('hosts' in parsed && Array.isArray(parsed.hosts)) return parsed.hosts[0] ?? null;
    return 'actions' in parsed ? (parsed as Report) : null;
  } catch {
    return null;
  }
}

function errorReport(host: string, req: RespondRequest, error: string): Report {
  return { host, hostname: '', sub: req.sub, apply: req.apply, root: false, via: 'script', actions: [], warnings: [], needsRoot: [], error };
}

/** `respond` on one remote host: its own threatcrush when it has one, else the streamed scripts. */
export async function runRemote(host: string, req: RespondRequest, ssh: SshExec): Promise<Report> {
  const notes: string[] = [];
  try {
    const probe = await ssh(host, REMOTE_PROBE);
    if (probe.code === 255) return errorReport(host, req, `ssh failed: ${probe.stderr.trim().split('\n').pop() ?? 'exit 255'}`);
    if (probe.stdout.includes('TC_RESPOND_OK')) {
      const res = await ssh(host, remoteCliCommand(req));
      const report = extractReport(res.stdout);
      if (report) return { ...report, host, via: 'threatcrush' };
      notes.push(`remote threatcrush gave no JSON (exit ${res.code}: ${res.stderr.trim().slice(0, 200)}); used the streamed script instead`);
    }

    const gathered = await ssh(host, REMOTE_SH, gatherScript(req));
    if (gathered.code === 255) return errorReport(host, req, `ssh failed: ${gathered.stderr.trim().split('\n').pop() ?? 'exit 255'}`);
    const report = planRespond(parseGather(gathered.stdout), req, { host, via: 'script' });
    report.warnings.unshift(...notes);
    if (req.apply && report.root) {
      await execute(report, async (script) => {
        const res = await ssh(host, REMOTE_SH, script);
        return res.stdout;
      });
    }
    return report;
  } catch (err) {
    return errorReport(host, req, (err as Error).message);
  }
}

export async function runHosts(hosts: string[], req: RespondRequest, ssh: SshExec, limit = MAX_PARALLEL_HOSTS): Promise<Report[]> {
  return runLimited(hosts, limit, (h) => runRemote(h, req, ssh));
}

/** The real ssh: batch mode (never prompts), script on stdin, never secrets on argv. */
export const sshExec: SshExec = (host, remoteCommand, stdin) => new Promise((resolve) => {
  const child = spawn('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '--', host, remoteCommand], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  const timer = setTimeout(() => child.kill('SIGTERM'), 300_000);
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  child.on('error', (err) => { clearTimeout(timer); resolve({ code: 255, stdout, stderr: err.message }); });
  child.on('close', (code) => { clearTimeout(timer); resolve({ code: code ?? 255, stdout, stderr }); });
  child.stdin.on('error', () => { /* remote closed early; the exit code tells */ });
  child.stdin.end(stdin ?? '');
});

/** The local runner: `sh -s` with the script on stdin. */
export const localSh: ScriptRunner = (script) => new Promise((resolve, reject) => {
  const child = spawn('sh', ['-s'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', () => { /* each record reports its own errors */ });
  child.on('error', reject);
  child.on('close', () => resolve(stdout));
  child.stdin.end(script);
});
