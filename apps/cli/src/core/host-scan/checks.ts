/**
 * Host integrity / rootkit checks for `threatcrush scan --host`.
 *
 * Each check returns pass / warn / fail / skip with a one-line reason and the
 * items behind it. Checks never change the system: missing tools are reported
 * with their install command, never installed.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readdirSync, readFileSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import os from 'node:os';
import {
  expandAuthorizedKeysFiles, groupMembers, isRkhunterRootkitWarning, isUnrestrictedKey, judgeDockerInspect,
  judgePackageVerify, judgeSshdConfig, keyIsDenied, parseAuthorizedKeys, parseChkrootkit, parseDenyList,
  parseDpkgSearch, parsePackageVerify, parsePasswd, parseProcModules, parseRkhunter, parseSshdT, parseUnhide,
  uidZeroNonRoot, type AuthorizedKey, type PasswdEntry,
} from './parsers.js';
import { checkNetworkExposure } from './exposure.js';
import { checkSecretsOnDisk } from './secrets.js';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'skip';

export interface CheckItem {
  status: Exclude<CheckStatus, 'pass' | 'skip'>;
  message: string;
  path?: string;
  details?: Record<string, unknown>;
}

export interface CheckResult {
  id: string;
  title: string;
  status: CheckStatus;
  reason: string;
  items: CheckItem[];
  /** Ran, but without root some of what it looks at was unreadable. */
  partial?: boolean;
  /** Command to install a missing tool (never run for you). */
  install?: string;
  duration_ms?: number;
}

export interface HostScanOptions {
  sinceMs: number;
  denyKeysFile?: string;
  /** secrets-on-disk: also search each git repo's history for committed private keys. */
  deep?: boolean;
  /** secrets-on-disk time budget (default 120 s); results past it are partial. */
  secretsTimeoutMs?: number;
  log?: (line: string) => void;
}

export interface CheckDef {
  id: string;
  title: string;
  /** Does the check need root to say anything at all? */
  needsRoot: boolean;
  run: (ctx: HostContext) => Omit<CheckResult, 'id' | 'title'>;
}

export interface HostContext {
  root: boolean;
  opts: HostScanOptions;
  passwd: PasswdEntry[];
  pkg: 'dpkg' | 'rpm' | null;
}

interface RunOut { code: number | null; stdout: string; stderr: string; missing: boolean; timedOut: boolean }

function run(cmd: string, args: string[], timeoutMs = 120_000, input?: string): RunOut {
  const r = spawnSync(cmd, args, {
    encoding: 'utf-8', timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024, input,
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

function which(cmd: string): string | null {
  for (const dir of `${process.env.PATH ?? ''}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.split(':')) {
    if (!dir) continue;
    const p = `${dir}/${cmd}`;
    try { if (statSync(p).isFile()) return p; } catch { /* next */ }
  }
  return null;
}

function read(path: string): string | null {
  try { return readFileSync(path, 'utf-8'); } catch { return null; }
}

function installHint(tool: string, pkg: HostContext['pkg']): string {
  return pkg === 'rpm' ? `sudo dnf install -y ${tool}   # EPEL on RHEL` : `sudo apt-get install -y ${tool}`;
}

function summarizeItems(items: CheckItem[], passReason: string): Pick<CheckResult, 'status' | 'reason'> {
  const fails = items.filter((i) => i.status === 'fail').length;
  const warns = items.filter((i) => i.status === 'warn').length;
  if (fails) return { status: 'fail', reason: `${fails} failing${warns ? `, ${warns} warning` : ''} item(s)` };
  if (warns) return { status: 'warn', reason: `${warns} item(s) to review` };
  return { status: 'pass', reason: passReason };
}

// ─── 1. package file integrity ───

function checkPackageIntegrity(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  let out: RunOut;
  if (ctx.pkg === 'dpkg') out = run('dpkg', ['--verify'], 30 * 60_000);
  else if (ctx.pkg === 'rpm') out = run('rpm', ['-Va', '--nomtime'], 30 * 60_000);
  else return { status: 'skip', reason: 'no dpkg or rpm package database on this host', items: [] };
  if (out.timedOut) return { status: 'warn', reason: `${ctx.pkg} verify timed out`, items: [] };
  const verdict = judgePackageVerify(parsePackageVerify(out.stdout));
  const items: CheckItem[] = [
    ...verdict.fail.map((e) => ({ status: 'fail' as const, message: `contents differ from the package (${e.attrs})`, path: e.path })),
    ...verdict.warn.map((e) => ({ status: 'warn' as const, message: e.missing ? 'packaged file is missing' : `contents differ from the package (${e.attrs})`, path: e.path })),
  ];
  const s = summarizeItems(items, `every packaged binary, PAM module and library matches ${ctx.pkg}`);
  if (verdict.unreadable) s.reason += ` (${verdict.unreadable} path(s) unreadable)`;
  return { ...s, items, partial: !ctx.root && verdict.unreadable > 0 };
}

// ─── 2. rkhunter / chkrootkit ───

function checkRkhunter(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  if (!which('rkhunter')) return { status: 'warn', reason: 'rkhunter is not installed', items: [], install: installHint('rkhunter', ctx.pkg) };
  const out = run('rkhunter', ['--check', '--sk', '--nocolors', '--rwo', '--noappend-log'], 30 * 60_000);
  if (out.timedOut) return { status: 'warn', reason: 'rkhunter timed out after 30 minutes', items: [] };
  const warnings = parseRkhunter(`${out.stdout}\n${out.stderr}`);
  const items: CheckItem[] = warnings.map((w) => ({ status: isRkhunterRootkitWarning(w) ? 'fail' : 'warn', message: w }));
  return { ...summarizeItems(items, 'rkhunter reported no warnings'), items };
}

/** Is the binary behind `cmd` byte-identical to its package? Used to clear chkrootkit false positives (e.g. rust-coreutils). */
function commandMatchesPackage(cmd: string, ctx: HostContext): string | null {
  if (ctx.pkg !== 'dpkg') return null;
  const bin = which(cmd);
  if (!bin) return null;
  let real = bin;
  try { real = realpathSync(bin); } catch { /* keep */ }
  const owner = run('dpkg', ['-S', real]);
  const pkg = owner.code === 0 ? owner.stdout.split(':')[0].split(',')[0].trim() : '';
  if (!pkg) return null;
  const verify = run('dpkg', ['--verify', pkg]);
  const changed = judgePackageVerify(parsePackageVerify(verify.stdout)).fail;
  return verify.code === 0 && changed.length === 0 ? pkg : null;
}

function checkChkrootkit(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  if (!which('chkrootkit')) return { status: 'warn', reason: 'chkrootkit is not installed', items: [], install: installHint('chkrootkit', ctx.pkg) };
  const out = run('chkrootkit', ['-q'], 30 * 60_000);
  if (out.timedOut) return { status: 'warn', reason: 'chkrootkit timed out after 30 minutes', items: [] };
  const res = parseChkrootkit(out.stdout);
  const items: CheckItem[] = [];
  for (const cmd of res.infectedCommands) {
    const pkg = commandMatchesPackage(cmd, ctx);
    items.push(pkg
      ? { status: 'warn', message: `chkrootkit flags \`${cmd}' INFECTED, but it matches package ${pkg} (known false positive)`, details: { command: cmd, package: pkg } }
      : { status: 'fail', message: `chkrootkit: \`${cmd}' INFECTED`, details: { command: cmd } });
  }
  for (const l of res.infectedOther) items.push({ status: 'fail', message: l });
  for (const g of res.warnings) for (const p of g.paths) items.push({ status: 'warn', message: g.header, path: p });
  for (const l of res.other) items.push({ status: 'warn', message: l });
  return { ...summarizeItems(items, 'chkrootkit reported nothing'), items };
}

// ─── 3. hidden processes ───

function procPids(): Set<number> {
  const s = new Set<number>();
  try { for (const d of readdirSync('/proc')) if (/^\d+$/.test(d)) s.add(Number(d)); } catch { /* none */ }
  return s;
}

function tgidOf(pid: number): number | null {
  const st = read(`/proc/${pid}/status`);
  const m = st && /^Tgid:\s*(\d+)/m.exec(st);
  return m ? Number(m[1]) : null;
}

const UNHIDE_BUDGET_MS = 5 * 60_000;

function checkHiddenProcesses(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  // Built-in, always: PIDs that answer stat() but are missing from the /proc
  // listing (readdir hooking), and /proc PIDs missing from `ps` (trojaned ps).
  const listed = procPids();
  const pidMax = Math.min(Number(read('/proc/sys/kernel/pid_max')?.trim()) || 32768, 4_194_304);
  const suspects: number[] = [];
  for (let pid = 1; pid <= pidMax; pid++) {
    if (listed.has(pid)) continue;
    if (!statSync(`/proc/${pid}`, { throwIfNoEntry: false })) continue;
    if (tgidOf(pid) === pid) suspects.push(pid); // threads answer stat() too; only thread-group leaders count
  }
  const relisted = procPids();
  const items: CheckItem[] = suspects
    .filter((pid) => !relisted.has(pid) && existsSync(`/proc/${pid}`))
    .map((pid) => ({ status: 'fail', message: `PID ${pid} exists but is hidden from the /proc listing`, details: { pid, comm: read(`/proc/${pid}/comm`)?.trim() } }));

  const ps = run('ps', ['-e', '-o', 'pid=']);
  if (ps.code === 0) {
    const psPids = new Set(ps.stdout.split('\n').map((l) => Number(l.trim())).filter((n) => n > 0));
    const after = procPids();
    for (const pid of listed) {
      if (psPids.has(pid) || !after.has(pid)) continue;
      // Process could have started after ps ran; ask ps about it directly.
      const ps2 = run('ps', ['-p', String(pid), '-o', 'pid=']);
      if (ps2.stdout.trim() || !existsSync(`/proc/${pid}`)) continue;
      items.push({ status: 'fail', message: `PID ${pid} is in /proc but not in ps output`, details: { pid, comm: read(`/proc/${pid}/comm`)?.trim() } });
    }
  }

  // unhide, when installed, compares more syscalls but walks all of pid_max
  // several times, which takes tens of minutes on a 4M pid_max; give it a budget.
  let unhideNote = 'install unhide for deeper checks';
  const unhide = which('unhide');
  if (unhide && ctx.root) {
    const out = run('unhide', ['quick'], UNHIDE_BUDGET_MS);
    if (out.timedOut) {
      unhideNote = `unhide quick did not finish in ${UNHIDE_BUDGET_MS / 60_000} min (pid_max ${pidMax}); built-in sweep only`;
    } else {
      unhideNote = 'unhide quick also run';
      const now = procPids();
      for (const f of parseUnhide(out.stdout)) {
        // Short-lived processes race unhide; only report PIDs still alive and still unlisted.
        if (!existsSync(`/proc/${f.pid}`) || now.has(f.pid) || items.some((i) => i.details?.pid === f.pid)) continue;
        items.push({ status: 'fail', message: `unhide: hidden PID ${f.pid}`, details: { pid: f.pid, detail: f.detail } });
      }
    }
  } else if (unhide) {
    unhideNote = 'unhide needs root';
  }
  const res = summarizeItems(items, `no hidden processes (sweep of ${pidMax} PIDs)`);
  res.reason += `; ${unhideNote}`;
  return { ...res, items, partial: !ctx.root, install: unhide ? undefined : installHint('unhide', ctx.pkg) };
}

// ─── 4. kernel modules ───

function checkKernelModules(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const procModules = read('/proc/modules');
  if (procModules === null) return { status: 'skip', reason: '/proc/modules is not readable', items: [] };
  const loaded = new Set(parseProcModules(procModules));
  const items: CheckItem[] = [];
  let sysModules: string[] = [];
  try { sysModules = readdirSync('/sys/module'); } catch { /* none */ }
  const suspects = sysModules.filter((m) => !loaded.has(m) && read(`/sys/module/${m}/initstate`) !== null);
  // Re-read /proc/modules once so a module loading mid-scan is not reported as hidden.
  const reloaded = suspects.length ? new Set(parseProcModules(read('/proc/modules') ?? '')) : loaded;
  for (const m of suspects) {
    // Only loadable (non built-in) modules have an initstate.
    const init = read(`/sys/module/${m}/initstate`);
    if (init === null) continue;
    if (!reloaded.has(m)) {
      items.push({ status: 'fail', message: `module ${m} is in /sys/module (${init.trim()}) but hidden from /proc/modules`, details: { module: m } });
    }
  }
  const release = os.release();
  const trees = [`/lib/modules/${release}/`, `/usr/lib/modules/${release}/`];
  if (which('modinfo')) {
    for (const m of loaded) {
      const r = run('modinfo', ['-n', m], 10_000);
      const file = r.stdout.trim();
      if (r.code !== 0 || !file) {
        items.push({ status: 'fail', message: `loaded module ${m} has no file in /lib/modules/${release}`, details: { module: m } });
      } else if (file !== '(builtin)' && !trees.some((t) => file.startsWith(t))) {
        items.push({ status: 'fail', message: `loaded module ${m} comes from outside the running kernel's tree`, path: file, details: { module: m } });
      }
    }
  }
  const taint = Number(read('/proc/sys/kernel/tainted')?.trim() ?? '0');
  const res = summarizeItems(items, `${loaded.size} loaded modules, all listed and from /lib/modules/${release}`);
  if (taint) res.reason += ` (kernel taint flags ${taint})`;
  return { ...res, items };
}

// ─── 5. ld.so.preload ───

export function checkLdPreload(readFile: (p: string) => string | null = read, exists: (p: string) => boolean = existsSync): Omit<CheckResult, 'id' | 'title'> {
  const path = '/etc/ld.so.preload';
  if (!exists(path)) return { status: 'pass', reason: `${path} does not exist`, items: [] };
  const body = readFile(path);
  const libs = (body ?? '').split(/\s+/).filter(Boolean);
  return {
    status: 'fail',
    reason: libs.length ? `${path} preloads ${libs.length} librar${libs.length === 1 ? 'y' : 'ies'} into every process` : `${path} exists`,
    items: [{ status: 'fail', message: body === null ? 'exists (unreadable)' : libs.length ? `preloads ${libs.join(', ')}` : 'exists (empty)', path, details: { libraries: libs } }],
  };
}

// ─── 6. processes running from deleted / temp executables ───

function checkSuspiciousExe(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const items: CheckItem[] = [];
  let unreadable = 0;
  for (const pid of procPids()) {
    let exe: string;
    try { exe = readlinkSync(`/proc/${pid}/exe`); } catch { unreadable++; continue; }
    const deleted = exe.endsWith(' (deleted)');
    const temp = /^\/(?:tmp|dev\/shm|var\/tmp)\//.test(exe);
    if (!deleted && !temp) continue;
    if (tgidOf(pid) !== pid) continue;
    const cmdline = (read(`/proc/${pid}/cmdline`) ?? '').replace(/\0/g, ' ').trim().slice(0, 160);
    let user = '';
    try { const uid = statSync(`/proc/${pid}`).uid; user = ctx.passwd.find((p) => p.uid === uid)?.name ?? String(uid); } catch { /* gone */ }
    items.push({
      status: 'warn',
      message: `${deleted ? 'deleted executable' : 'runs from a temp dir'}: pid ${pid}${user ? ` (${user})` : ''} ${cmdline}`,
      path: exe,
      details: { pid, user, cmdline },
    });
  }
  const res = summarizeItems(items, 'no process runs a deleted or /tmp, /dev/shm, /var/tmp executable');
  if (!ctx.root && unreadable) res.reason += ` (${unreadable} processes not readable without root)`;
  return { ...res, items, partial: !ctx.root };
}

// ─── 7. SSH keys + sshd config ───

let sshdCache: Map<string, string[]> | null | undefined;
function sshdConfig(): Map<string, string[]> | null {
  if (sshdCache !== undefined) return sshdCache;
  const bin = which('sshd') ?? (existsSync('/usr/sbin/sshd') ? '/usr/sbin/sshd' : null);
  if (!bin) return (sshdCache = null);
  const out = run(bin, ['-T']);
  sshdCache = out.code === 0 && out.stdout.trim() ? parseSshdT(out.stdout) : null;
  return sshdCache;
}

function accountHomes(passwd: PasswdEntry[]): Array<{ user: string; home: string }> {
  const seen = new Map<string, string>();
  for (const p of passwd) if (p.home && p.home !== '/' && p.home !== '/nonexistent') seen.set(p.home, p.name);
  seen.set('/root', seen.get('/root') ?? 'root');
  try { for (const d of readdirSync('/home')) if (!seen.has(`/home/${d}`)) seen.set(`/home/${d}`, d); } catch { /* none */ }
  return [...seen].map(([home, user]) => ({ home, user }));
}

function checkSshKeys(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const cfg = sshdConfig();
  const spec = cfg?.get('authorizedkeysfile')?.[0] ?? '.ssh/authorized_keys .ssh/authorized_keys2';
  let deny = { blobs: new Set<string>(), fingerprints: new Set<string>() };
  const items: CheckItem[] = [];
  if (ctx.opts.denyKeysFile) {
    const text = read(ctx.opts.denyKeysFile);
    if (text === null) items.push({ status: 'fail', message: `deny list ${ctx.opts.denyKeysFile} is not readable` });
    else deny = parseDenyList(text);
  }
  const keys: Array<AuthorizedKey & { user: string }> = [];
  let unreadable = 0;
  const files = new Set<string>();
  for (const { home, user } of accountHomes(ctx.passwd)) {
    for (const file of expandAuthorizedKeysFiles(spec, home, user)) {
      if (files.has(file)) continue;
      files.add(file);
      let text: string | null = null;
      try { if (!lstatSync(file).isFile()) continue; text = readFileSync(file, 'utf-8'); } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'EACCES') unreadable++;
        continue;
      }
      for (const k of parseAuthorizedKeys(text, file)) keys.push({ ...k, user });
    }
  }
  const byBlob = new Map<string, Array<AuthorizedKey & { user: string }>>();
  for (const k of keys) byBlob.set(k.blob, [...(byBlob.get(k.blob) ?? []), k]);
  for (const k of keys) {
    const where = `${k.file}:${k.line}`;
    const label = `${k.fingerprint ?? k.type} ${k.comment || '(no comment)'}`;
    if (keyIsDenied(k, deny)) items.push({ status: 'fail', message: `deny-listed key for ${k.user}: ${label}`, path: where, details: { fingerprint: k.fingerprint } });
    if (isUnrestrictedKey(k)) items.push({ status: 'warn', message: `unrestricted key (no command= or from=) for ${k.user}: ${label}`, path: where, details: { fingerprint: k.fingerprint, restrict: k.restrict } });
  }
  for (const [, dupes] of byBlob) {
    if (dupes.length < 2) continue;
    items.push({ status: 'warn', message: `same key appears ${dupes.length} times: ${dupes[0].fingerprint} (${dupes.map((d) => `${d.file}:${d.line}`).join(', ')})`, details: { fingerprint: dupes[0].fingerprint } });
  }
  const res = summarizeItems(items, `${keys.length} key(s) in ${files.size} candidate file(s), all restricted`);
  res.reason = `${keys.length} key(s); ${res.reason}`;
  if (unreadable) res.reason += ` (${unreadable} file(s) unreadable without root)`;
  return { ...res, items, partial: !ctx.root };
}

function checkSshdConfig(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const cfg = sshdConfig();
  if (!cfg) {
    if (!which('sshd') && !existsSync('/usr/sbin/sshd')) return { status: 'skip', reason: 'sshd is not installed', items: [] };
    return { status: 'skip', reason: ctx.root ? '`sshd -T` failed' : '`sshd -T` needs root', items: [] };
  }
  const items: CheckItem[] = judgeSshdConfig(cfg).map((i) => ({ status: 'warn', message: `${i.setting} ${i.value}: ${i.reason}` }));
  return { ...summarizeItems(items, 'PermitRootLogin no and PasswordAuthentication no'), items };
}

// ─── 8. Docker ───

function checkDockerContainers(): Omit<CheckResult, 'id' | 'title'> {
  if (!which('docker')) return { status: 'skip', reason: 'docker is not installed', items: [] };
  const ps = run('docker', ['ps', '-q', '--no-trunc'], 60_000);
  if (ps.code !== 0) return { status: 'skip', reason: `docker ps failed: ${(ps.stderr.trim().split('\n')[0] || 'no access').slice(0, 120)}`, items: [] };
  const ids = ps.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
  if (!ids.length) return { status: 'pass', reason: 'no running containers', items: [] };
  const inspect = run('docker', ['inspect', ...ids], 120_000);
  const risks = judgeDockerInspect(inspect.stdout);
  const items: CheckItem[] = risks.map((r) => ({ status: 'warn', message: `${r.name || r.id}: ${r.reasons.join(', ')} (root on the host)`, details: { ...r } }));
  return { ...summarizeItems(items, `${ids.length} running container(s), none privileged, host-PID or mounting / or the Docker socket`), items };
}

function checkDockerGroup(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const group = read('/etc/group') ?? '';
  const { gid, members } = groupMembers(group, ctx.passwd, 'docker');
  if (gid === null) return { status: 'pass', reason: 'no docker group', items: [] };
  const items: CheckItem[] = members.map((m) => ({ status: 'warn', message: `${m} is in the docker group (equivalent to root)` }));
  return { ...summarizeItems(items, 'docker group is empty'), items };
}

// ─── 9. persistence + uid 0 ───

const PERSISTENCE_ROOTS = [
  '/etc/crontab', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly', '/etc/anacrontab',
  '/var/spool/cron', '/etc/systemd/system', '/etc/pam.d', '/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d', '/etc/sudoers', '/etc/sudoers.d',
  '/etc/ld.so.preload', '/etc/rc.local', '/etc/profile.d', '/etc/udev/rules.d', '/etc/init.d', '/etc/update-motd.d',
];

function walk(path: string, out: Array<{ path: string; mtime: number }>, depth = 0): number {
  let unreadable = 0;
  let st;
  try { st = lstatSync(path); } catch (e) { return (e as NodeJS.ErrnoException).code === 'EACCES' ? 1 : 0; }
  if (st.isSymbolicLink() || st.isFile()) { out.push({ path, mtime: Math.max(st.mtimeMs, st.ctimeMs) }); return 0; }
  if (!st.isDirectory() || depth > 8) return 0;
  let entries: string[];
  try { entries = readdirSync(path); } catch { return 1; }
  for (const e of entries) unreadable += walk(`${path}/${e}`, out, depth + 1);
  return unreadable;
}

function checkPersistence(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const roots = [...PERSISTENCE_ROOTS];
  for (const { home } of accountHomes(ctx.passwd)) {
    roots.push(`${home}/.config/systemd`, `${home}/.ssh/authorized_keys`, `${home}/.ssh/authorized_keys2`);
  }
  const files: Array<{ path: string; mtime: number }> = [];
  let unreadable = 0;
  for (const r of new Set(roots)) unreadable += walk(r, files);
  const cutoff = Date.now() - ctx.opts.sinceMs;
  const recent = files.filter((f) => f.mtime >= cutoff).sort((a, b) => b.mtime - a.mtime);
  const items: CheckItem[] = recent.map((f) => ({ status: 'warn', message: `changed ${new Date(f.mtime).toISOString().slice(0, 16).replace('T', ' ')}Z`, path: f.path }));
  const res = summarizeItems(items, `no cron, systemd, PAM, sshd, sudoers or key file changed in the window (${files.length} files)`);
  if (unreadable) res.reason += ` (${unreadable} path(s) unreadable)`;
  return { ...res, items, partial: !ctx.root && unreadable > 0 };
}

export function checkUidZero(passwdText: string | null): Omit<CheckResult, 'id' | 'title'> {
  if (passwdText === null) return { status: 'skip', reason: '/etc/passwd is not readable', items: [] };
  const extra = uidZeroNonRoot(parsePasswd(passwdText));
  const items: CheckItem[] = extra.map((n) => ({ status: 'fail', message: `account ${n} has uid 0` }));
  return { ...summarizeItems(items, 'root is the only uid 0 account'), items };
}

// ─── 10. SUID/SGID outside the package database ───

const SUID_PRUNE = ['/proc', '/sys', '/dev', '/run', '/var/lib/docker', '/var/lib/containerd', '/var/lib/containers', '/snap', '/var/snap', '/var/lib/lxd'];

function checkSuid(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  if (!ctx.pkg) return { status: 'skip', reason: 'no package database to compare against', items: [] };
  const prune = SUID_PRUNE.flatMap((p, i) => [...(i ? ['-o'] : []), '-path', p]);
  const find = run('find', ['/', '-xdev', '(', ...prune, ')', '-prune', '-o', '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print'], 20 * 60_000);
  const paths = find.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
  const owned = new Set<string>();
  if (ctx.pkg === 'dpkg') {
    // usrmerge: dpkg may record /bin/x for what is now /usr/bin/x, so ask about both spellings.
    const alt = (p: string) => (p.startsWith('/usr/') && /^\/usr\/(s?bin|lib)/.test(p) ? p.slice(4) : /^\/(s?bin|lib)\//.test(p) ? `/usr${p}` : null);
    const queries = [...new Set(paths.flatMap((p) => [p, alt(p)].filter((x): x is string => !!x)))];
    for (let i = 0; i < queries.length; i += 200) {
      const r = run('dpkg', ['-S', ...queries.slice(i, i + 200)]);
      for (const p of parseDpkgSearch(r.stdout)) owned.add(p);
    }
    for (const p of paths) { const a = alt(p); if (a && owned.has(a)) owned.add(p); }
  } else {
    for (const p of paths) if (run('rpm', ['-qf', p]).code === 0) owned.add(p);
  }
  const items: CheckItem[] = paths.filter((p) => !owned.has(p)).map((p) => {
    let mode = '';
    try { mode = (statSync(p).mode & 0o7777).toString(8); } catch { /* gone */ }
    return { status: 'warn', message: `setuid/setgid binary not owned by any package${mode ? ` (mode ${mode})` : ''}`, path: p };
  });
  const res = summarizeItems(items, `${paths.length} setuid/setgid file(s), all from packages`);
  return { ...res, items, partial: !ctx.root };
}

// ─── registry ───

export const HOST_CHECKS: CheckDef[] = [
  { id: 'package-integrity', title: 'Package file integrity', needsRoot: false, run: checkPackageIntegrity },
  { id: 'rkhunter', title: 'rkhunter', needsRoot: true, run: checkRkhunter },
  { id: 'chkrootkit', title: 'chkrootkit', needsRoot: true, run: checkChkrootkit },
  { id: 'hidden-processes', title: 'Hidden processes', needsRoot: false, run: checkHiddenProcesses },
  { id: 'kernel-modules', title: 'Kernel modules', needsRoot: false, run: checkKernelModules },
  { id: 'ld-preload', title: '/etc/ld.so.preload', needsRoot: false, run: () => checkLdPreload() },
  { id: 'suspicious-exe', title: 'Deleted / temp-dir executables', needsRoot: false, run: checkSuspiciousExe },
  { id: 'ssh-keys', title: 'SSH authorized_keys', needsRoot: false, run: checkSshKeys },
  { id: 'sshd-config', title: 'sshd configuration', needsRoot: true, run: checkSshdConfig },
  { id: 'docker-containers', title: 'Docker containers', needsRoot: false, run: () => checkDockerContainers() },
  { id: 'docker-group', title: 'Docker group members', needsRoot: false, run: checkDockerGroup },
  { id: 'persistence', title: 'Persistence changed recently', needsRoot: false, run: checkPersistence },
  { id: 'uid0-accounts', title: 'uid 0 accounts', needsRoot: false, run: () => checkUidZero(read('/etc/passwd')) },
  { id: 'suid-sgid', title: 'SUID/SGID outside packages', needsRoot: false, run: checkSuid },
  { id: 'network-exposure', title: 'Datastore ports exposed to the internet', needsRoot: false, run: checkNetworkExposure },
  { id: 'secrets-on-disk', title: 'Plaintext secrets on disk', needsRoot: false, run: checkSecretsOnDisk },
];

export function detectPackageManager(): HostContext['pkg'] {
  if (which('dpkg') && existsSync('/var/lib/dpkg/status')) return 'dpkg';
  if (which('rpm') && (existsSync('/var/lib/rpm') || existsSync('/usr/lib/sysimage/rpm'))) return 'rpm';
  return null;
}

export interface HostScanReport {
  host: string;
  kernel: string;
  root: boolean;
  started_at: string;
  duration_ms: number;
  since_ms: number;
  summary: Record<CheckStatus, number>;
  skipped: Array<{ id: string; reason: string }>;
  checks: CheckResult[];
}

export function runHostScan(opts: HostScanOptions, select?: { only?: string[]; skip?: string[] }): HostScanReport {
  const started = Date.now();
  sshdCache = undefined;
  const root = typeof process.getuid === 'function' ? process.getuid() === 0 : false;
  const ctx: HostContext = { root, opts, passwd: parsePasswd(read('/etc/passwd') ?? ''), pkg: detectPackageManager() };
  const checks: CheckResult[] = [];
  for (const def of HOST_CHECKS) {
    if (select?.only?.length && !select.only.includes(def.id)) continue;
    if (select?.skip?.includes(def.id)) continue;
    if (def.needsRoot && !root) {
      checks.push({ id: def.id, title: def.title, status: 'skip', reason: 'needs root (run with sudo)', items: [] });
      continue;
    }
    opts.log?.(`running ${def.id}...`);
    const t = Date.now();
    let res: Omit<CheckResult, 'id' | 'title'>;
    try { res = def.run(ctx); } catch (e) { res = { status: 'warn', reason: `check errored: ${(e as Error).message}`, items: [] }; }
    checks.push({ id: def.id, title: def.title, ...res, duration_ms: Date.now() - t });
  }
  const summary: Record<CheckStatus, number> = { pass: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of checks) summary[c.status]++;
  return {
    host: os.hostname(),
    kernel: os.release(),
    root,
    started_at: new Date(started).toISOString(),
    duration_ms: Date.now() - started,
    since_ms: opts.sinceMs,
    summary,
    skipped: checks.filter((c) => c.status === 'skip').map((c) => ({ id: c.id, reason: c.reason })),
    checks,
  };
}
