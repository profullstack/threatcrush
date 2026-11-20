/**
 * Pure parsers for `threatcrush scan --host`. Every function here takes the
 * text a system tool printed (or a file's contents) and returns structured
 * data, so the tests can feed fixture text without a live box.
 */
import { createHash } from 'node:crypto';

// ─── dpkg --verify / rpm -Va ───

export interface PackageVerifyEntry {
  path: string;
  /** The 9-character attribute field, or "missing". */
  attrs: string;
  /** dpkg marks conffiles `c`; rpm uses c/d/g/l/r for config, doc, ghost, licence, readme. */
  fileType: string | null;
  missing: boolean;
  /** Digest differs from the package database (the '5' in the third column). */
  digestChanged: boolean;
  /** Text dpkg appended in parentheses, e.g. "Permission denied". */
  error: string | null;
}

const VERIFY_LINE = /^(missing|[?.A-Za-z0-9]{9})\s+(?:([cdglr])\s+)?(\/.*?)(?:\s+\(([^)]*)\))?\s*$/;

/** Parse `dpkg --verify` or `rpm -Va` output. Unrecognised lines (warnings) are skipped. */
export function parsePackageVerify(text: string): PackageVerifyEntry[] {
  const out: PackageVerifyEntry[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    const m = VERIFY_LINE.exec(line);
    if (!m) continue;
    const attrs = m[1];
    out.push({
      path: m[3],
      attrs,
      fileType: m[2] ?? null,
      missing: attrs === 'missing',
      digestChanged: attrs !== 'missing' && attrs[2] === '5',
      error: m[4] ?? null,
    });
  }
  return out;
}

const BIN_DIR = /^\/(?:usr\/)?s?bin\//;
const PAM_DIR = /^\/(?:usr\/)?lib(?:32|64|x32)?\/(?:[^/]+\/)?security\//;
const LIB_DIR = /^\/(?:usr\/)?lib(?:32|64|x32|exec)?\//;

export type IntegrityClass = 'binary' | 'pam' | 'library' | 'other';

export function classifyPackagePath(path: string): IntegrityClass {
  if (BIN_DIR.test(path)) return 'binary';
  if (PAM_DIR.test(path)) return 'pam';
  if (LIB_DIR.test(path)) return 'library';
  return 'other';
}

export interface IntegrityVerdict {
  /** Digest changed on a binary, PAM module or shared object. */
  fail: PackageVerifyEntry[];
  /** Digest changed elsewhere under /usr/lib, or a packaged binary is missing. */
  warn: PackageVerifyEntry[];
  /** Conffiles and paths outside the watched trees. */
  ignored: number;
  /** Entries dpkg could not check (permission denied). */
  unreadable: number;
}

/** Decide which verify entries matter: conffiles never do, binaries and PAM modules always do. */
export function judgePackageVerify(entries: PackageVerifyEntry[]): IntegrityVerdict {
  const verdict: IntegrityVerdict = { fail: [], warn: [], ignored: 0, unreadable: 0 };
  for (const e of entries) {
    if (e.error) { verdict.unreadable++; continue; }
    if (e.fileType) { verdict.ignored++; continue; }
    const cls = classifyPackagePath(e.path);
    if (cls === 'other') { verdict.ignored++; continue; }
    if (e.digestChanged) {
      if (cls === 'binary' || cls === 'pam' || /\.so(?:\.[0-9.]+)?$/.test(e.path)) verdict.fail.push(e);
      else verdict.warn.push(e);
    } else if (e.missing) {
      verdict.warn.push(e);
    } else {
      verdict.ignored++;
    }
  }
  return verdict;
}

// ─── rkhunter ───

const ANSI = /\x1b\[[0-9;]*m/g;
const LOG_STAMP = /^\[\d{2}:\d{2}:\d{2}\]\s?/;

/**
 * Parse `rkhunter --check --rwo` output (or its log): each `Warning:` line
 * starts a warning and indented lines after it continue it.
 */
export function parseRkhunter(text: string): string[] {
  const warnings: string[] = [];
  let current: string | null = null;
  for (const raw of text.split('\n')) {
    const line = raw.replace(ANSI, '').replace(LOG_STAMP, '').replace(/\r$/, '');
    const m = /^Warning:\s*(.*)$/.exec(line);
    if (m) {
      if (current !== null) warnings.push(current);
      current = m[1].trim();
      continue;
    }
    if (current !== null && /^\s+\S/.test(line)) {
      current += ` ${line.trim()}`;
      continue;
    }
    if (current !== null) { warnings.push(current); current = null; }
  }
  if (current !== null) warnings.push(current);
  return warnings;
}

/** rkhunter warnings that name a rootkit are failures; the rest (hidden dotfiles, scripts) are warnings. */
export function isRkhunterRootkitWarning(warning: string): boolean {
  return /rootkit|infected|trojan|backdoor/i.test(warning);
}

// ─── chkrootkit ───

export interface ChkrootkitResult {
  /** `Checking \`X'... INFECTED` — the command name. */
  infectedCommands: string[];
  /** Other INFECTED lines, verbatim. */
  infectedOther: string[];
  /** WARNING groups with the unpackaged paths under them. */
  warnings: Array<{ header: string; paths: string[] }>;
  /** Anything else chkrootkit -q printed. */
  other: string[];
}

export function parseChkrootkit(text: string): ChkrootkitResult {
  const res: ChkrootkitResult = { infectedCommands: [], infectedOther: [], warnings: [], other: [] };
  let group: { header: string; paths: string[] } | null = null;
  const closeGroup = () => {
    if (group && group.paths.length) res.warnings.push(group);
    group = null;
  };
  for (const raw of text.split('\n')) {
    const line = raw.replace(ANSI, '').replace(/\r$/, '').trimEnd();
    if (!line.trim()) { closeGroup(); continue; }
    const cmd = /^Checking `([^']+)'\.\.\.\s*INFECTED/.exec(line);
    if (cmd) { closeGroup(); res.infectedCommands.push(cmd[1]); continue; }
    if (/INFECTED/.test(line)) { closeGroup(); res.infectedOther.push(line.trim()); continue; }
    const warn = /^WARNING:\s*(.*?):?\s*$/.exec(line);
    if (warn) { closeGroup(); group = { header: warn[1], paths: [] }; continue; }
    if (group) {
      // Packaged files are expected (dotfiles shipped by Debian packages).
      if (/\[From (?:Debian|RPM) package:[^\]]*\]\s*$/.test(line)) continue;
      group.paths.push(line.replace(/\s*\[Not from a (?:Debian|RPM) package\]\s*$/, '').trim());
      continue;
    }
    res.other.push(line.trim());
  }
  closeGroup();
  return res;
}

// ─── unhide ───

export function parseUnhide(text: string): Array<{ pid: number; detail: string[] }> {
  const out: Array<{ pid: number; detail: string[] }> = [];
  let cur: { pid: number; detail: string[] } | null = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const m = /Found HIDDEN PID:\s*(\d+)/i.exec(line);
    if (m) { cur = { pid: Number(m[1]), detail: [] }; out.push(cur); continue; }
    if (!line) { cur = null; continue; }
    if (cur && /^(Cmdline|Executable|Command|\$?USER|\$?PWD)\b/i.test(line)) cur.detail.push(line);
  }
  return out;
}

// ─── authorized_keys ───

const KEY_TYPE = /^(?:ssh-(?:rsa|dss|ed25519|xmss)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)(?:-cert-v0[01]@openssh\.com)?$/;

export interface AuthorizedKey {
  file: string;
  line: number;
  type: string;
  blob: string;
  comment: string;
  /** Option names (lower case) with their values (null for flags). */
  options: Array<{ name: string; value: string | null }>;
  command: string | null;
  from: string | null;
  restrict: boolean;
  fingerprint: string | null;
}

/** Split the options prefix of an authorized_keys line, honouring double quotes and \" escapes. */
function splitOptionsPrefix(line: string): { options: string; rest: string } {
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '\\' && inQuote) { i++; continue; }
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (!inQuote && (ch === ' ' || ch === '\t')) return { options: line.slice(0, i), rest: line.slice(i).trimStart() };
  }
  return { options: line, rest: '' };
}

function parseOptionList(options: string): Array<{ name: string; value: string | null }> {
  const out: Array<{ name: string; value: string | null }> = [];
  let i = 0;
  while (i < options.length) {
    let name = '';
    while (i < options.length && options[i] !== '=' && options[i] !== ',') name += options[i++];
    let value: string | null = null;
    if (options[i] === '=') {
      i++;
      if (options[i] === '"') {
        i++;
        value = '';
        while (i < options.length && options[i] !== '"') {
          if (options[i] === '\\' && options[i + 1] === '"') { value += '"'; i += 2; continue; }
          value += options[i++];
        }
        i++; // closing quote
      } else {
        value = '';
        while (i < options.length && options[i] !== ',') value += options[i++];
      }
    }
    if (options[i] === ',') i++;
    if (name.trim()) out.push({ name: name.trim().toLowerCase(), value });
  }
  return out;
}

/** OpenSSH-style SHA256 fingerprint of a base64 key blob. */
export function keyFingerprint(blob: string): string | null {
  try {
    const buf = Buffer.from(blob, 'base64');
    if (!buf.length) return null;
    return `SHA256:${createHash('sha256').update(buf).digest('base64').replace(/=+$/, '')}`;
  } catch {
    return null;
  }
}

export function parseAuthorizedKeys(text: string, file = 'authorized_keys'): AuthorizedKey[] {
  const keys: AuthorizedKey[] = [];
  text.split('\n').forEach((raw, idx) => {
    const line = raw.replace(/\r$/, '').trim();
    if (!line || line.startsWith('#')) return;
    let optionText = '';
    let rest = line;
    const first = line.split(/\s+/, 1)[0];
    if (!KEY_TYPE.test(first)) {
      const split = splitOptionsPrefix(line);
      optionText = split.options;
      rest = split.rest;
    }
    const parts = rest.split(/\s+/);
    const type = parts[0] ?? '';
    const blob = parts[1] ?? '';
    if (!KEY_TYPE.test(type) || !blob) return;
    const options = optionText ? parseOptionList(optionText) : [];
    const get = (n: string) => options.find((o) => o.name === n)?.value ?? null;
    keys.push({
      file,
      line: idx + 1,
      type,
      blob,
      comment: parts.slice(2).join(' '),
      options,
      command: get('command'),
      from: get('from'),
      restrict: options.some((o) => o.name === 'restrict'),
      fingerprint: keyFingerprint(blob),
    });
  });
  return keys;
}

/** A key with neither command= nor from= can log in from anywhere and run anything. */
export function isUnrestrictedKey(key: AuthorizedKey): boolean {
  return key.command === null && key.from === null;
}

/**
 * Deny-list file: one entry per line, each a full public key line, a bare
 * base64 blob, or a `SHA256:` fingerprint. `#` comments and blanks ignored.
 */
export function parseDenyList(text: string): { blobs: Set<string>; fingerprints: Set<string> } {
  const blobs = new Set<string>();
  const fingerprints = new Set<string>();
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    if (/^SHA256:/.test(line)) { fingerprints.add(line.split(/\s+/)[0].replace(/=+$/, '')); continue; }
    const parsed = parseAuthorizedKeys(line);
    if (parsed.length) { blobs.add(parsed[0].blob); continue; }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(line)) blobs.add(line);
  }
  return { blobs, fingerprints };
}

export function keyIsDenied(key: AuthorizedKey, deny: { blobs: Set<string>; fingerprints: Set<string> }): boolean {
  return deny.blobs.has(key.blob) || (key.fingerprint !== null && deny.fingerprints.has(key.fingerprint));
}

// ─── sshd -T ───

/** `sshd -T` prints `keyword value...` lines with lower-case keywords; repeatable keywords appear several times. */
export function parseSshdT(text: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(\S+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const list = out.get(key) ?? [];
    list.push(m[2]);
    out.set(key, list);
  }
  return out;
}

export function judgeSshdConfig(cfg: Map<string, string[]>): Array<{ setting: string; value: string; reason: string }> {
  const issues: Array<{ setting: string; value: string; reason: string }> = [];
  const root = cfg.get('permitrootlogin')?.[0];
  if (root !== undefined && root.toLowerCase() !== 'no') {
    issues.push({ setting: 'PermitRootLogin', value: root, reason: 'root can log in over SSH (set PermitRootLogin no)' });
  }
  const pw = cfg.get('passwordauthentication')?.[0];
  if (pw !== undefined && pw.toLowerCase() === 'yes') {
    issues.push({ setting: 'PasswordAuthentication', value: pw, reason: 'password logins are accepted (set PasswordAuthentication no)' });
  }
  return issues;
}

/** Expand the AuthorizedKeysFile tokens (%h, %u, %%) for one account. */
export function expandAuthorizedKeysFiles(spec: string, home: string, user: string): string[] {
  return spec.split(/\s+/).filter((s) => s && s.toLowerCase() !== 'none').map((p) => {
    const expanded = p.replace(/%%|%h|%u|%U/g, (t) => (t === '%%' ? '%' : t === '%h' ? home : t === '%u' ? user : ''));
    return expanded.startsWith('/') ? expanded : `${home.replace(/\/$/, '')}/${expanded}`;
  });
}

// ─── accounts, modules, docker ───

export interface PasswdEntry { name: string; uid: number; gid: number; home: string; shell: string }

export function parsePasswd(text: string): PasswdEntry[] {
  const out: PasswdEntry[] = [];
  for (const raw of text.split('\n')) {
    const f = raw.trim().split(':');
    if (f.length < 7 || raw.startsWith('#')) continue;
    out.push({ name: f[0], uid: Number(f[2]), gid: Number(f[3]), home: f[5], shell: f[6] });
  }
  return out;
}

export function uidZeroNonRoot(passwd: PasswdEntry[]): string[] {
  return passwd.filter((p) => p.uid === 0 && p.name !== 'root').map((p) => p.name);
}

/** Members of a group: listed in /etc/group plus accounts whose primary gid is that group. */
export function groupMembers(groupText: string, passwd: PasswdEntry[], group: string): { gid: number | null; members: string[] } {
  for (const raw of groupText.split('\n')) {
    const f = raw.trim().split(':');
    if (f.length < 4 || f[0] !== group) continue;
    const gid = Number(f[2]);
    const listed = f[3].split(',').map((s) => s.trim()).filter(Boolean);
    const primary = passwd.filter((p) => p.gid === gid).map((p) => p.name);
    return { gid, members: [...new Set([...listed, ...primary])].sort() };
  }
  return { gid: null, members: [] };
}

export function parseProcModules(text: string): string[] {
  return text.split('\n').map((l) => l.trim().split(/\s+/)[0]).filter(Boolean);
}

export interface DockerRisk { name: string; id: string; reasons: string[] }

const RISKY_SOURCES = new Set(['/', '/var/run/docker.sock', '/run/docker.sock']);

/** Flag containers from `docker inspect` JSON: privileged, host PID namespace, / or the Docker socket mounted. */
export function judgeDockerInspect(json: string): DockerRisk[] {
  let list: unknown;
  try { list = JSON.parse(json); } catch { return []; }
  if (!Array.isArray(list)) return [];
  const out: DockerRisk[] = [];
  for (const c of list as Array<Record<string, any>>) {
    const reasons: string[] = [];
    const hc = c.HostConfig ?? {};
    if (hc.Privileged === true) reasons.push('--privileged');
    if (hc.PidMode === 'host') reasons.push('--pid=host');
    const sources = new Set<string>();
    for (const m of (c.Mounts ?? []) as Array<Record<string, any>>) if (m.Type === 'bind' && typeof m.Source === 'string') sources.add(m.Source);
    for (const b of (hc.Binds ?? []) as string[]) if (typeof b === 'string') sources.add(b.split(':')[0]);
    for (const s of sources) {
      const norm = s.length > 1 ? s.replace(/\/+$/, '') : s;
      if (RISKY_SOURCES.has(norm)) reasons.push(`bind mount of ${norm}`);
    }
    if (reasons.length) out.push({ name: String(c.Name ?? '').replace(/^\//, ''), id: String(c.Id ?? '').slice(0, 12), reasons: [...new Set(reasons)] });
  }
  return out;
}

// ─── misc ───

/** "7d", "12h", "30m", "2w", "90s" → milliseconds. */
export function parseSince(spec: string): number {
  const m = /^(\d+)\s*([smhdw])$/i.exec(spec.trim());
  if (!m) throw new Error(`invalid --since "${spec}" (expected e.g. 7d, 12h, 30m)`);
  const mult: Record<string, number> = { s: 1e3, m: 60e3, h: 3600e3, d: 86400e3, w: 7 * 86400e3 };
  return Number(m[1]) * mult[m[2].toLowerCase()];
}

/** `dpkg -S a b c` stdout → set of owned paths (diversion lines skipped). */
export function parseDpkgSearch(text: string): Set<string> {
  const owned = new Set<string>();
  for (const raw of text.split('\n')) {
    const m = /^(.+?):\s+(\/.*)$/.exec(raw.trim()); // package names may carry :arch
    if (m && !/^diversion by/.test(raw)) owned.add(m[2]);
  }
  return owned;
}
