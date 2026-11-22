/**
 * `secrets-on-disk` host check: an inventory of credentials an intruder would
 * harvest in one sweep (unencrypted private keys, CLI tokens, cloud creds,
 * .env files, password-manager exports).
 *
 * Never prints or stores a secret value: each finding is path, type, owner,
 * mode, size and age, plus counts or variable NAMES for .env files.
 *
 * Severity: every item is a warning (it may well be needed), except a secret
 * other users can read (world-readable, or group-readable by a shared group)
 * and a private key committed to a git history, which fail.
 */
import { closeSync, lstatSync, openSync, readdirSync, readSync, statSync } from 'node:fs';
import type { CheckItem, CheckResult, HostContext } from './checks.js';
import { sysRead, sysRun, sysWhich } from './sys.js';

export type SecretType =
  | 'private-key' | 'gh-token' | 'npm-token' | 'pypi-password' | 'docker-auth' | 'aws-credentials'
  | 'gcloud-credentials' | 'kubeconfig' | 'git-credentials' | 'netrc' | 'vault-token' | 'terraform-token'
  | 'env-secrets' | 'json-secret' | 'password-export';

export interface SecretFinding {
  type: SecretType;
  label: string;
  /** Number of secret-looking variables / registries / entries, when meaningful. */
  count?: number;
  /** Variable names (never values) for .env files. */
  names?: string[];
}

// ─── private keys ───

const PEM_PRIVATE = /-----BEGIN ((?:OPENSSH|RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY-----([\s\S]*?)-----END/;

/** Detect a PEM / OpenSSH private key and whether it is passphrase-protected. */
export function classifyPrivateKey(text: string): { kind: string; encrypted: boolean } | null {
  const m = PEM_PRIVATE.exec(text);
  if (!m) return null;
  const kind = (m[1] ?? 'PKCS8 ').trim();
  const body = m[2];
  if (kind === 'ENCRYPTED') return { kind: 'PKCS8', encrypted: true };
  if (kind === 'OPENSSH') {
    const b64 = body.replace(/[^A-Za-z0-9+/=]/g, '');
    const buf = Buffer.from(b64, 'base64');
    const magic = 'openssh-key-v1\0';
    if (buf.length < magic.length + 4 || buf.subarray(0, magic.length).toString('latin1') !== magic) return { kind, encrypted: false };
    const len = buf.readUInt32BE(magic.length);
    const cipher = buf.subarray(magic.length + 4, magic.length + 4 + len).toString('latin1');
    return { kind, encrypted: cipher !== 'none' };
  }
  // PKCS#1 / SEC1 PEM: legacy encryption is announced in headers.
  return { kind, encrypted: /Proc-Type:\s*4,ENCRYPTED/.test(body) };
}

// ─── .env files ───

const SECRET_NAME = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|PRIVATE|CREDENTIAL|AUTH|SEED|MNEMONIC)/i;
const PLACEHOLDER = /^(|changeme|change_me|xxx+|\*+|\.\.\.|todo|none|null|undefined|false|true|0|example|placeholder|your[-_].*|<.*>|\$\{.*\}|\$[A-Z_]+)$/i;

/** Names (never values) of secret-looking variables with a real-looking value. */
export function envSecretNames(text: string): string[] {
  const names: string[] = [];
  for (const raw of text.split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(raw);
    if (!m) continue;
    const [, name, rawVal] = m;
    const val = rawVal.trim().replace(/^(['"])(.*)\1$/, '$2').replace(/\s+#.*$/, '').trim();
    if (PLACEHOLDER.test(val)) continue;
    const isSecretName = SECRET_NAME.test(name) && !/PUBLIC|_PUB(_|$)|_ID$|_PATH$|_FILE$|_URL$|_HOST$|_TTL$|_EXPIR/i.test(name);
    const urlWithPassword = /^[a-z][a-z0-9+.-]*:\/\/[^:/@\s]+:[^@\s]+@/i.test(val);
    if (isSecretName || urlWithPassword) names.push(name);
  }
  return names;
}

function isEnvFile(base: string): boolean {
  // Backups (`app.env.bak`, `prod.env.old.2`) hold the same secrets and are
  // never rotated with the original: attack-vectors/unrotated-github-app-keys.md.
  if (/^[\w.-]*\.env\.(?:bak|old|orig|save|backup|prev)(?:[.~_-][\w.~-]*)?$/i.test(base)) return true;
  if (/^\.env(\..+)?$/.test(base) || /^[\w.-]+\.env$/.test(base)) {
    return !/(example|sample|template|dist|defaults?|schema|test)$/i.test(base.replace(/\.env$/, ''));
  }
  return false;
}

// ─── password exports ───

const EXPORT_NAME = /(bitwarden|lastpass|1password|keepass|dashlane|nordpass|passwords?|logins?).*\.(csv|json|1pif|1pux)$|export.*\.csv$/i;

export function isPasswordExportHeader(firstLine: string): boolean {
  const cols = firstLine.toLowerCase().split(/[,;\t]/).map((c) => c.trim().replace(/^"|"$/g, ''));
  const hasPass = cols.some((c) => c === 'password' || c === 'login_password' || c === 'pass');
  const hasUser = cols.some((c) => /^(username|login_username|user|email|login|url|login_uri|website|name|title)$/.test(c));
  return hasPass && hasUser;
}

// ─── which files to read at all ───

/** Should this file be opened? `rel` is relative to the home (or absolute under /etc). */
export function isCandidate(rel: string, base: string): boolean {
  if (base.endsWith('.pub')) return false;
  if (/^id_[\w-]+$/.test(base) || /\.(pem|key|p8)$/i.test(base) || /_(rsa|dsa|ecdsa|ed25519)$/.test(base)) return true;
  if (/(^|\/)\.ssh\/[^/]+$/.test(rel) && !/^(known_hosts.*|config|authorized_keys2?|environment|rc)$/.test(base)) return true;
  if (['.npmrc', '.pypirc', '.git-credentials', '.netrc', '.vault-token', 'credentials.tfrc.json'].includes(base)) return true;
  if (/(^|\/)\.config\/gh\/hosts\.yml$/.test(rel) || /(^|\/)\.aws\/credentials$/.test(rel) || /(^|\/)\.kube\/config$/.test(rel) || /(^|\/)\.docker\/config\.json$/.test(rel)) return true;
  if (/(^|\/)\.config\/gcloud\/(application_default_credentials\.json|credentials\.db|access_tokens\.db|legacy_credentials\/.+\/adc\.json)$/.test(rel)) return true;
  if (isEnvFile(base)) return true;
  if (/^(identity|.*credentials?|.*service[-_]?account.*|.*keyfile|.*wallet|.*keystore)\.json$/i.test(base)) return true;
  if (/\.json$/.test(base) && /(^|\/)\.[^/]+\//.test(rel)) return true; // json in a dot-dir: content-checked
  if (EXPORT_NAME.test(base) || /\.csv$/i.test(base)) return true;
  return false;
}

const JSON_SECRET_KEY = /"(private_?key|privateKey|secret_?key|secretKey|client_secret|mnemonic|seed_?phrase|seedPhrase|refresh_token|access_token|api_?key|apiKey|token)"\s*:\s*"([^"\s]{16,})"/g;

/** A JSON secret field whose value is not an env-var name or template placeholder. */
function hasJsonSecret(text: string): boolean {
  for (const m of text.matchAll(JSON_SECRET_KEY)) {
    const v = m[2];
    if (/^[A-Z][A-Z0-9_]+$/.test(v) || /^(\$\{|\{\{|<|%)/.test(v)) continue;
    return true;
  }
  return false;
}

/** Classify a candidate file's contents. Returns null when it holds nothing secret. */
export function classifySecretFile(rel: string, base: string, text: string): SecretFinding | null {
  const key = classifyPrivateKey(text);
  if (key) return key.encrypted ? null : { type: 'private-key', label: `unencrypted ${key.kind === 'PKCS8' ? 'PKCS#8' : key.kind} private key` };

  if (/(^|\/)\.config\/gh\/hosts\.yml$/.test(rel)) {
    const n = (text.match(/^\s*oauth_token:\s*\S+/gm) ?? []).length;
    return n ? { type: 'gh-token', label: `GitHub CLI OAuth token${n > 1 ? `s (${n})` : ''} in plaintext`, count: n } : null;
  }
  if (base === '.npmrc') {
    const n = (text.match(/^[^#;\n]*(_authToken|_auth|_password)\s*=\s*\S+/gm) ?? []).length;
    return n ? { type: 'npm-token', label: `npm registry token${n > 1 ? `s (${n})` : ''}`, count: n } : null;
  }
  if (base === '.pypirc') return /^\s*password\s*[=:]\s*\S+/m.test(text) ? { type: 'pypi-password', label: 'PyPI password / token' } : null;
  if (base === '.git-credentials') {
    const n = (text.match(/^[a-z][a-z0-9+.-]*:\/\/[^:\s/]+:[^@\s]+@/gim) ?? []).length;
    return n ? { type: 'git-credentials', label: `git credential store (${n} entr${n === 1 ? 'y' : 'ies'})`, count: n } : null;
  }
  if (base === '.netrc') return /\bpassword\s+\S+/.test(text) ? { type: 'netrc', label: '.netrc password(s)' } : null;
  if (base === '.vault-token') return text.trim().length >= 8 ? { type: 'vault-token', label: 'HashiCorp Vault token' } : null;
  if (base === 'credentials.tfrc.json') return /"token"\s*:\s*"/.test(text) ? { type: 'terraform-token', label: 'Terraform Cloud token' } : null;
  if (/(^|\/)\.aws\/credentials$/.test(rel)) {
    const n = (text.match(/^\s*aws_secret_access_key\s*=\s*\S+/gm) ?? []).length;
    return n ? { type: 'aws-credentials', label: `AWS secret access key${n > 1 ? `s (${n} profiles)` : ''}`, count: n } : null;
  }
  if (/(^|\/)\.kube\/config$/.test(rel)) {
    return /^\s*(token|client-key-data|password):\s*\S+/m.test(text) ? { type: 'kubeconfig', label: 'kubeconfig with embedded credentials' } : null;
  }
  if (/(^|\/)\.docker\/config\.json$/.test(rel)) {
    try {
      const auths = (JSON.parse(text) as { auths?: Record<string, { auth?: string; identitytoken?: string }> }).auths ?? {};
      const regs = Object.entries(auths).filter(([, v]) => v && (v.auth || v.identitytoken)).map(([k]) => k);
      return regs.length ? { type: 'docker-auth', label: `Docker registry login stored in plaintext (${regs.join(', ')})`, count: regs.length } : null;
    } catch { return null; }
  }
  if (/(^|\/)\.config\/gcloud\//.test(rel)) return { type: 'gcloud-credentials', label: 'Google Cloud credentials' };

  if (isEnvFile(base)) {
    const names = envSecretNames(text);
    return names.length ? { type: 'env-secrets', label: `env file with ${names.length} secret-looking variable(s)`, count: names.length, names } : null;
  }
  if (/\.(1pif|1pux)$/i.test(base)) return { type: 'password-export', label: '1Password export' };
  if (/\.csv$/i.test(base)) {
    const first = text.split('\n', 1)[0] ?? '';
    return isPasswordExportHeader(first) ? { type: 'password-export', label: 'plaintext password export (CSV)' } : null;
  }
  if (/\.json$/i.test(base)) {
    if (EXPORT_NAME.test(base) || /"items"\s*:/.test(text)) {
      if (/"encrypted"\s*:\s*true/.test(text)) return null;
      if (/"login"\s*:\s*\{[^}]*"password"\s*:\s*"[^"]+"/.test(text) || (EXPORT_NAME.test(base) && /"password"\s*:\s*"[^"]+"/.test(text))) {
        return { type: 'password-export', label: 'plaintext password export (JSON)' };
      }
    }
    if (/"type"\s*:\s*"service_account"/.test(text) && /"private_key"/.test(text)) return { type: 'json-secret', label: 'cloud service-account key (JSON)' };
    if (hasJsonSecret(text)) return { type: 'json-secret', label: 'JSON file holding a private key / secret / token' };
  }
  return null;
}

// ─── permissions ───

export interface GroupInfo { name: string; members: string[] }

export function parseGroupFile(text: string): Map<number, GroupInfo> {
  const out = new Map<number, GroupInfo>();
  for (const line of text.split('\n')) {
    const f = line.split(':');
    if (f.length < 4 || !/^\d+$/.test(f[2])) continue;
    out.set(Number(f[2]), { name: f[0], members: f[3].trim() ? f[3].trim().split(',') : [] });
  }
  return out;
}

/**
 * Can someone other than the owner read the file? World-read always counts;
 * group-read counts unless the group is the owner's private group (same name,
 * no other members), which Debian/Ubuntu create for every user.
 */
export function exposedTo(mode: number, ownerName: string, gid: number, groups: Map<number, GroupInfo>, primaryGidUsers: string[] = []): 'world' | 'group' | null {
  if (mode & 0o004) return 'world';
  if (mode & 0o040) {
    const g = groups.get(gid);
    const others = [...(g?.members ?? []), ...primaryGidUsers].filter((u) => u !== ownerName);
    if (g && g.name === ownerName && others.length === 0) return null;
    return 'group';
  }
  return null;
}

// ─── walker ───

const SKIP_DIRS = new Set([
  'node_modules', '.cache', '.npm', '.pnpm-store', '.yarn', '.cargo', '.rustup', '.nvm', '.bun', '.deno', 'go', '.gradle', '.m2',
  '.vscode-server', '.cursor-server', '.vscode', 'snap', 'venv', '.venv', '__pycache__', 'site-packages', 'target', '.next',
  '.nuxt', '.svelte-kit', '.turbo', '.Trash', 'Trash', '.nimble', '.gem', '.pub-cache', '.cpan', '.opam', '.stack', '.ghcup', '.julia', '.conda', 'miniconda3', 'anaconda3', '.mozilla', '.thunderbird', '.wine', 'proc', '.ollama', '.docker-data',
]);
/** Bulky trees under a home that hold packages, not credentials. */
const REL_SKIP = new Set(['.local/lib', '.local/share/pnpm', '.local/share/Trash', '.local/share/containers', '.local/share/docker',
  '.local/share/virtualenvs', '.local/share/mise', '.local/share/fnm', '.local/share/nvim', '.local/state', '.config/Code', '.config/google-chrome', '.config/chromium']);
const ETC_SKIP = new Set(['/etc/ssl/certs', '/etc/alternatives', '/etc/fonts', '/etc/X11', '/etc/apparmor.d', '/etc/brltty', '/etc/ca-certificates', '/etc/pki/ca-trust']);

export interface SecretItemData {
  path: string;
  type: SecretType | 'git-history-key';
  label: string;
  owner: string;
  mode: string;
  size: number;
  age_days: number;
  exposed: 'world' | 'group' | null;
  count?: number;
  names?: string[];
  /** Path looks like a test fixture or example (still listed, never failed). */
  fixture?: boolean;
  /** Other repos (worktrees, copies) sharing the same leaked commit. */
  also?: string[];
}

const FIXTURE_PATH = /\/(tests?|__tests__|spec|specs|fixtures?|testdata|test-data|examples?|samples?|mocks?)\//i;

export function looksLikeFixture(path: string): boolean {
  return FIXTURE_PATH.test(path);
}

interface WalkState {
  deadline: number;
  visited: number;
  unreadable: number;
  timedOut: boolean;
  findings: SecretItemData[];
  repos: Array<{ path: string; uid: number; gid: number }>;
  seen: Set<string>;
}

const MAX_FILE = 1024 * 1024;
const MAX_ENTRIES = 2_000_000;

function readHead(path: string, bytes: number): string | null {
  let fd: number | null = null;
  try {
    fd = openSync(path, 'r');
    const buf = Buffer.alloc(bytes);
    const n = readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, n).toString('utf-8');
  } catch { return null; } finally { if (fd !== null) try { closeSync(fd); } catch { /* */ } }
}

interface WalkEnv {
  userName: (uid: number) => string;
  groups: Map<number, GroupInfo>;
  primaryUsers: Map<number, string[]>;
  /** /etc mode: only report what other users can read. */
  etc: boolean;
}

function walkSecrets(root: string, relBase: string, depth: number, maxDepth: number, st: WalkState, env: WalkEnv): void {
  if (Date.now() > st.deadline || st.visited > MAX_ENTRIES) { st.timedOut = true; return; }
  let entries: string[];
  try { entries = readdirSync(root); } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EACCES') st.unreadable++;
    return;
  }
  if (!env.etc && entries.includes('.git')) {
    try { const s = lstatSync(root); st.repos.push({ path: root, uid: s.uid, gid: s.gid }); } catch { /* */ }
  }
  for (const name of entries) {
    if ((++st.visited & 1023) === 0 && Date.now() > st.deadline) { st.timedOut = true; return; }
    const path = `${root}/${name}`;
    const rel = relBase ? `${relBase}/${name}` : name;
    let s;
    try { s = lstatSync(path); } catch { continue; }
    if (s.isSymbolicLink()) continue;
    if (s.isDirectory()) {
      if (name === '.git') continue;
      if (env.etc ? ETC_SKIP.has(path) : (SKIP_DIRS.has(name) || REL_SKIP.has(rel))) continue;
      if (depth < maxDepth) walkSecrets(path, rel, depth + 1, maxDepth, st, env);
      continue;
    }
    if (!s.isFile() || s.size === 0) continue;
    const isCsv = /\.csv$/i.test(name);
    if (s.size > MAX_FILE && !isCsv) continue;
    if (!isCandidate(env.etc ? path : rel, name)) continue;
    const id = `${s.dev}:${s.ino}`;
    if (st.seen.has(id)) continue;
    st.seen.add(id);
    const text = readHead(path, isCsv ? 4096 : Math.min(s.size, 256 * 1024));
    if (text === null) { st.unreadable++; continue; }
    const f = classifySecretFile(env.etc ? path : rel, name, text);
    if (!f) continue;
    const owner = env.userName(s.uid);
    const exposed = exposedTo(s.mode, owner, s.gid, env.groups, env.primaryUsers.get(s.gid));
    if (env.etc && exposed !== 'world') continue;
    st.findings.push({
      path, type: f.type, label: f.label, owner, mode: (s.mode & 0o7777).toString(8).padStart(3, '0'), size: s.size,
      age_days: Math.floor((Date.now() - s.mtimeMs) / 86_400_000), exposed, count: f.count, names: f.names,
      fixture: looksLikeFixture(path) || undefined,
    });
  }
}

/** Does every directory above `path` let "other" traverse it? (A world-readable file in a 0700 home is not reachable.) */
function othersCanReach(path: string, cache: Map<string, boolean>): boolean {
  const parts = path.split('/').slice(0, -1);
  let dir = '';
  for (const p of parts) {
    dir = dir ? `${dir}/${p}` : (p || '/');
    if (dir === '/') continue;
    let ok = cache.get(dir);
    if (ok === undefined) {
      try { ok = (statSync(dir).mode & 0o001) !== 0; } catch { ok = false; }
      cache.set(dir, ok);
    }
    if (!ok) return false;
  }
  return true;
}

export function secretItem(d: SecretItemData, reachable = true): CheckItem {
  const meta = `owner ${d.owner}, mode ${d.mode}, ${d.size} B, ${d.age_days}d old`;
  if (d.type === 'git-history-key') {
    const also = d.also?.length ? ` (also in ${d.also.length} other checkout(s))` : '';
    return { status: 'fail', message: `${d.label}${also}`, path: d.path, details: { ...d } };
  }
  const fx = d.fixture ? ' [test fixture path]' : '';
  const names = d.names?.length ? `: ${d.names.slice(0, 6).join(', ')}${d.names.length > 6 ? `, +${d.names.length - 6}` : ''}` : '';
  if (d.exposed && reachable && !d.fixture) {
    return { status: 'fail', message: `${d.label}${names}, readable by ${d.exposed === 'world' ? 'every user' : 'its group'} (${meta})`, path: d.path, details: { ...d } };
  }
  const note = d.exposed && !reachable ? ' [world-readable, but a parent directory is closed]' : '';
  const open = d.exposed && reachable ? ` [readable by ${d.exposed === 'world' ? 'every user' : 'its group'}]` : '';
  return { status: 'warn', message: `${d.label}${names} (${meta})${note}${open}${fx}`, path: d.path, details: { ...d } };
}

// ─── orchestrator ───

export const DEFAULT_SECRETS_BUDGET_MS = 120_000;

function homeRoots(): string[] {
  const out = ['/root'];
  try { for (const d of readdirSync('/home')) out.push(`/home/${d}`); } catch { /* none */ }
  return out;
}

function gitHistoryKey(repo: { path: string; uid: number; gid: number }, root: boolean, timeoutMs: number): { hash: string | null; timedOut: boolean } {
  // Run as the repo's owner when we are root: git reads repo-local config, and a
  // hostile repo must not get to run anything (textconv, fsmonitor) as root.
  const asOwner = root && repo.uid !== 0 ? { uid: repo.uid, gid: repo.gid } : {};
  const r = sysRun('git', [
    '-c', 'core.fsmonitor=false', '-c', `safe.directory=${repo.path}`, '-C', repo.path, '--no-pager', 'log', '--all',
    '--no-textconv', '--no-ext-diff', '--pickaxe-regex', '-S', '-----BEGIN [A-Z ]*PRIVATE KEY-----', '--format=%H', '-n1',
  ], timeoutMs, asOwner);
  if (r.timedOut) return { hash: null, timedOut: true };
  const hash = r.code === 0 ? r.stdout.trim().split('\n')[0] : '';
  return { hash: hash || null, timedOut: false };
}

export function checkSecretsOnDisk(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const started = Date.now();
  const budget = ctx.opts.secretsTimeoutMs ?? DEFAULT_SECRETS_BUDGET_MS;
  const deadline = started + budget;
  const walkDeadline = ctx.opts.deep ? started + Math.floor(budget * 0.7) : deadline;
  const groups = parseGroupFile(sysRead('/etc/group') ?? '');
  const primaryUsers = new Map<number, string[]>();
  for (const p of ctx.passwd) primaryUsers.set(p.gid, [...(primaryUsers.get(p.gid) ?? []), p.name]);
  const userName = (uid: number) => ctx.passwd.find((p) => p.uid === uid)?.name ?? String(uid);
  const st: WalkState = { deadline: walkDeadline, visited: 0, unreadable: 0, timedOut: false, findings: [], repos: [], seen: new Set() };

  for (const home of homeRoots()) walkSecrets(home, '', 0, 7, st, { userName, groups, primaryUsers, etc: false });
  const homeTimedOut = st.timedOut;
  st.timedOut = false;
  walkSecrets('/etc', '', 0, 4, st, { userName, groups, primaryUsers, etc: true });
  const timedOut = homeTimedOut || st.timedOut;

  let gitNote = '';
  let gitPartial = false;
  if (ctx.opts.deep) {
    if (!sysWhich('git')) gitNote = '; --deep: git not installed';
    else {
      let scanned = 0; let slow = 0;
      const byCommit = new Map<string, SecretItemData>();
      for (const repo of st.repos) {
        const left = deadline - Date.now();
        if (left < 1000) break;
        const r = gitHistoryKey(repo, ctx.root, Math.min(left, 30_000));
        scanned++;
        if (r.timedOut) { slow++; continue; }
        if (r.hash) {
          const prev = byCommit.get(r.hash);
          if (prev) { prev.also = [...(prev.also ?? []), repo.path]; continue; }
          const item: SecretItemData = { path: repo.path, type: 'git-history-key', label: `private key in git history (commit ${r.hash.slice(0, 12)}): rewriting history does not un-leak it, rotate the key`, owner: userName(repo.uid), mode: '', size: 0, age_days: 0, exposed: null };
          byCommit.set(r.hash, item);
          st.findings.push(item);
        }
      }
      gitPartial = scanned < st.repos.length || slow > 0;
      gitNote = `; --deep: ${scanned}/${st.repos.length} repo histories searched${slow ? ` (${slow} timed out)` : ''}`;
    }
  }

  const reach = new Map<string, boolean>();
  const items = st.findings.map((d) => secretItem(d, d.exposed !== 'world' || othersCanReach(d.path, reach)));
  items.sort((a, b) => (a.status === b.status ? 0 : a.status === 'fail' ? -1 : 1));
  const fails = items.filter((i) => i.status === 'fail').length;
  const warns = items.length - fails;
  const status: CheckResult['status'] = fails ? 'fail' : warns ? 'warn' : 'pass';
  let reason = fails ? `${fails} secret(s) readable by other users or in git history, ${warns} more to review`
    : warns ? `${warns} plaintext secret(s) on disk to review` : 'no plaintext keys, tokens or credential files found';
  reason += ` (${st.visited} entries in ${((Date.now() - started) / 1000).toFixed(0)}s${timedOut ? `, stopped at the ${Math.round(budget / 1000)}s budget: partial` : ''})`;
  if (st.unreadable && !ctx.root) reason += `; ${st.unreadable} path(s) unreadable without root`;
  reason += gitNote;
  return { status, reason, items, partial: timedOut || gitPartial || (!ctx.root && st.unreadable > 0) };
}
