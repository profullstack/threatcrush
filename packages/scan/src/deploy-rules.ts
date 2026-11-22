/**
 * Deploy-path rules: where write access to a repository becomes a shell on a
 * host.
 *
 * Why this is a separate engine
 * -----------------------------
 * The code rules read one line at a time, and the workflow rules read one
 * workflow. The defects here are relationships across a whole file:
 *
 *   - a compose file is YAML, and a host-root bind mount is a `volumes:` entry
 *     two levels under a service, not a line pattern;
 *   - "this script runs a compose file the CI job just uploaded" needs the
 *     rsync destination from one line and the `docker compose -f` from another;
 *   - "this callback trusts `installation_id` from the query string" needs to
 *     know that nothing in the same handler asked GitHub who the user is.
 *
 * Every rule here comes from one incident chain on a real fleet (2026-11), and
 * each carries a `reference` to the `attack-vectors/` entry describing it.
 *
 * What these rules claim
 * ----------------------
 * Compose and authorized_keys findings are facts read off configuration, so
 * they are `evidence`. The deploy-script and callback rules are heuristics over
 * text: `contextual` where the file shows both halves of the chain (the upload
 * and the execution, the read and the write), `pattern` otherwise.
 */

import { isMap, isScalar, isSeq, LineCounter, parseDocument } from 'yaml';
import type { Node as YamlNode, Pair, Scalar, YAMLMap } from 'yaml';
import { attackVector } from './references';
import type { Confidence, ScanLanguage, Severity } from './types';
import { severityFor } from './types';

export interface DeployRule {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  consequence: string;
  fix: string;
  reference: string;
}

export interface DeployMatch {
  rule: DeployRule;
  /** 1-based source line. */
  line: number;
  severity: Severity;
  message: string;
}

const RULE_LIST = [
  {
    id: 'compose-host-root-mount',
    title: 'Compose service bind-mounts the host root, a home, or an .ssh directory',
    severity: 'critical',
    confidence: 'evidence',
    cwe: 'CWE-250',
    consequence:
      'The container reads (and with a writable mount, rewrites) host files: every secret under `/`, private keys and `authorized_keys`. Whoever can change this file or what the container runs owns the host.',
    fix: 'Mount only the specific data directory the service needs, read-only where possible. Never mount `/`, `/root`, `/etc`, a whole home directory or any `.ssh` directory.',
    reference: attackVector('ci-forced-command-compose'),
  },
  {
    id: 'compose-docker-socket',
    title: 'Compose service mounts the Docker socket',
    severity: 'high',
    confidence: 'evidence',
    cwe: 'CWE-250',
    consequence:
      'The Docker API is root on the host: the container can start a new privileged container that mounts `/`.',
    fix: 'Remove the socket mount. If the service really needs the API, put a filtering proxy in front of it that allows only the calls it makes.',
    reference: attackVector('ci-forced-command-compose'),
  },
  {
    id: 'compose-privileged',
    title: 'Compose service runs privileged or with SYS_ADMIN / ALL capabilities',
    severity: 'high',
    confidence: 'evidence',
    cwe: 'CWE-250',
    consequence: 'A privileged container can mount host devices and load kernel modules: escaping it is routine.',
    fix: 'Drop `privileged: true` and add back only the individual capabilities the service needs.',
    reference: attackVector('ci-forced-command-compose'),
  },
  {
    id: 'compose-root-user',
    title: 'Compose service explicitly runs as uid 0',
    severity: 'medium',
    confidence: 'evidence',
    cwe: 'CWE-250',
    consequence:
      'Root in the container is root on every host path it mounts. Combined with a bind mount it writes host files as root.',
    fix: 'Run as an unprivileged uid (`user: "1000:1000"`) and give it ownership of only the paths it writes.',
    reference: attackVector('ci-forced-command-compose'),
  },
  {
    id: 'deploy-compose-from-synced-repo',
    title: 'docker compose runs a compose file from a repository checkout on the host',
    severity: 'high',
    confidence: 'contextual',
    cwe: 'CWE-94',
    consequence:
      'The compose file (and its build context) is whatever the last push contained. A push that adds `user: "0:0"` and a `/:/host` volume gets root on the host, whatever the ssh key or forced command was meant to allow.',
    fix: 'Keep the compose file the host runs outside the synced tree, owned by root and not writable by the deploy user; deploy by pulling a pinned image tag instead of building from pushed sources.',
    reference: attackVector('ci-forced-command-compose'),
  },
  {
    id: 'deploy-remote-exec-uploaded-script',
    title: 'Script from the repository is uploaded to a host and run there',
    severity: 'high',
    confidence: 'contextual',
    cwe: 'CWE-94',
    consequence:
      'Anything that can change the repository (a merged PR, a stolen App key pushing to the default branch) changes what runs on the host as the deploy user, which a restricted ssh key was supposed to prevent.',
    fix: 'Install the deploy script on the host out of band (root-owned, not writable by the deploy user) and pin the key to it with `restrict,command="/usr/local/bin/deploy"`; send only data, never code.',
    reference: attackVector('ci-forced-command-compose'),
  },
  {
    id: 'github-app-installation-idor',
    title: 'GitHub App setup callback stores an installation_id from the query string without verifying the user owns it',
    severity: 'high',
    confidence: 'contextual',
    cwe: 'CWE-639',
    consequence:
      "Any signed-in user can visit the callback with someone else's `installation_id` and bind that organisation's installation to their account, then use the App's write features against repositories they have no access to. An App-JWT lookup of the installation succeeds for every installation, so it proves nothing about the user.",
    fix: 'Exchange the OAuth `code` for a user-to-server token and require the id to appear in `GET /user/installations`; also carry a signed, single-use `state` through the install flow.',
    reference: attackVector('github-app-installation-idor'),
  },
  {
    id: 'authorized-keys-unrestricted',
    title: 'authorized_keys entry with no from=, command= or restrict',
    severity: 'medium',
    confidence: 'evidence',
    cwe: 'CWE-284',
    consequence: 'Whoever holds the private half logs in from anywhere and gets a full shell.',
    fix: 'Prefix the key with `restrict` and, where possible, `from="<addresses>"` and `command="<script>"` scoped to what it is for.',
    reference: attackVector('planted-authorized-keys'),
  },
  {
    id: 'authorized-keys-suspicious-comment',
    title: 'authorized_keys entry named like a temporary CI / diagnostic key',
    severity: 'high',
    confidence: 'contextual',
    cwe: 'CWE-506',
    consequence:
      'Intruders plant persistence keys with innocuous dated names (`ci-diag-YYYYMMDD`, `ops-recovery-YYYYMMDD`) and add them to both a user and root.',
    fix: 'Confirm who added the key and when. If nobody can, remove it from every account, then look for other persistence and rotate what the box holds.',
    reference: attackVector('planted-authorized-keys'),
  },
  {
    id: 'authorized-keys-sftp-unjailed',
    title: 'sftp-only key without a chroot can read the whole filesystem',
    severity: 'medium',
    confidence: 'pattern',
    cwe: 'CWE-552',
    consequence:
      '`command="internal-sftp"` limits what the key can run, not what it can read: it downloads every file the account can read, secrets included.',
    fix: 'Give the account a `Match User` block in sshd_config with `ChrootDirectory` (root-owned) and `ForceCommand internal-sftp`, or a jail that restricts reads as well as writes.',
    reference: attackVector('sftp-jail-reads-root'),
  },
  {
    id: 'sshd-sftp-without-chroot',
    title: 'sshd forces sftp without a ChrootDirectory',
    severity: 'medium',
    confidence: 'pattern',
    cwe: 'CWE-552',
    consequence:
      'An sftp-only jail that confines writes but not reads still serves every readable file on the host, including app env files and private keys, to anyone with the deploy key.',
    fix: 'Add `ChrootDirectory` (a root-owned directory holding only what the account should see) to the same Match block, or confine reads as well as writes in a custom jail.',
    reference: attackVector('sftp-jail-reads-root'),
  },
] as const satisfies readonly DeployRule[];

export const DEPLOY_RULES: readonly DeployRule[] = RULE_LIST;

type RuleId = (typeof RULE_LIST)[number]['id'];
const RULE = Object.fromEntries(RULE_LIST.map((r) => [r.id, r])) as Record<RuleId, DeployRule>;

// ── File kinds ────────────────────────────────────────────────────────────

function baseName(path: string): string {
  const p = path.replace(/\\/g, '/');
  return p.slice(p.lastIndexOf('/') + 1);
}

/** `compose.yml`, `docker-compose.prod.yaml`, `compose.override.yml`, ... */
export function isComposePath(relativePath: string): boolean {
  return /^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/i.test(baseName(relativePath));
}

/** `authorized_keys`, `authorized_keys2`, `authorized_keys.bak`. */
export function isAuthorizedKeysPath(relativePath: string): boolean {
  return /^authorized_keys2?(?:\.[\w.-]+)?$/.test(baseName(relativePath));
}

export function isSshdConfigPath(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, '/');
  return baseName(p) === 'sshd_config' || /(?:^|\/)sshd_config\.d\/[^/]+\.conf$/.test(p);
}

const SOURCE_LANGUAGES: readonly ScanLanguage[] = ['javascript', 'typescript', 'python', 'ruby', 'go', 'php', 'java'];

type Emit = (id: RuleId, line: number, message: string, severity?: Severity) => void;

/** Run every deploy rule that applies to this file. Never throws. */
export function evaluateDeployRules(
  relativePath: string,
  text: string,
  language: ScanLanguage,
  isWorkflow = false,
): DeployMatch[] {
  const out: DeployMatch[] = [];
  const emit: Emit = (id, line, message, severity) => {
    const rule = RULE[id];
    if (out.some((m) => m.rule.id === id && m.line === line)) return;
    out.push({ rule, line, message, severity: severityFor(severity ?? rule.severity, rule.confidence) });
  };

  try {
    if (isComposePath(relativePath)) composeRules(text, emit);
    if (isAuthorizedKeysPath(relativePath)) authorizedKeysRules(text, emit);
    if (isSshdConfigPath(relativePath)) sshdRules(text, emit);
    if (isWorkflow || language === 'shell' || /\bSSH_ORIGINAL_COMMAND\b/.test(text)) {
      remoteDeployRules(text, isWorkflow, emit);
    }
    if (SOURCE_LANGUAGES.includes(language)) githubAppCallbackRule(text, emit);
  } catch {
    // A heuristic engine never takes the scan down with it.
  }

  return out.sort((a, b) => a.line - b.line);
}

// ── Compose files ─────────────────────────────────────────────────────────

function yamlGet(map: unknown, key: string): YamlNode | undefined {
  if (!isMap(map)) return undefined;
  for (const pair of (map as YAMLMap).items as Pair[]) {
    if (isScalar(pair.key) && String((pair.key as Scalar).value) === key) return pair.value as YamlNode | undefined;
  }
  return undefined;
}

function yamlStr(node: unknown): string | undefined {
  if (!isScalar(node)) return undefined;
  const v = (node as Scalar).value;
  return v === null || v === undefined ? undefined : String(v);
}

/**
 * The host side of a short-syntax volume (`src:dst[:mode]`). A `${VAR:-x}`
 * expansion contains a colon of its own, so braces are skipped over.
 */
export function volumeSource(spec: string): string | null {
  let depth = 0;
  for (let i = 0; i < spec.length; i++) {
    const ch = spec[i];
    if (ch === '{') depth++;
    else if (ch === '}') depth = Math.max(0, depth - 1);
    else if (ch === ':' && depth === 0) {
      // A Windows drive letter (`C:\...`) is not a separator.
      if (i === 1 && /^[A-Za-z]$/.test(spec[0]!) && /[\\/]/.test(spec[2] ?? '')) continue;
      return spec.slice(0, i);
    }
  }
  return null; // an anonymous or named volume with no host side
}

/** Is this host path the root, a home, /etc, /boot or an .ssh directory? */
export function isDangerousHostPath(source: string): boolean {
  const s = source.trim().replace(/^['"]|['"]$/g, '');
  const norm = s.replace(/\$\{HOME\}|\$HOME/g, '~').replace(/\/+$/, '') || '/';
  if (norm === '/' || norm === '~') return true;
  if (/^\/(?:root|etc|boot)(?:\/|$)/.test(norm)) return true;
  if (norm === '/home' || /^\/home\/[^/]+$/.test(norm)) return true;
  if (/(?:^|\/)\.ssh(?:\/|$)/.test(norm)) return true;
  return false;
}

function isDockerSocket(source: string): boolean {
  return /^(?:\/var)?\/run\/docker\.sock$/.test(source.trim().replace(/^['"]|['"]$/g, ''));
}

function composeRules(text: string, emit: Emit): void {
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc, uniqueKeys: false, strict: false });
  if (doc.errors.length > 0 || !isMap(doc.contents)) return;
  const lineOf = (node: YamlNode | undefined): number => (node?.range ? lc.linePos(node.range[0]).line : 1);

  const services = yamlGet(doc.contents, 'services');
  if (!isMap(services)) return;

  for (const pair of (services as YAMLMap).items as Pair[]) {
    const name = isScalar(pair.key) ? String((pair.key as Scalar).value) : '?';
    const svc = pair.value as YamlNode | undefined;
    if (!isMap(svc)) continue;

    const userNode = yamlGet(svc, 'user');
    const user = yamlStr(userNode);
    const runsAsRoot = user !== undefined && /^(?:0|root)(?::.*)?$/.test(user.trim());
    if (runsAsRoot) emit('compose-root-user', lineOf(userNode), `Service \`${name}\` sets \`user: ${user}\``);

    const priv = yamlGet(svc, 'privileged');
    if (priv && /^true$/i.test(yamlStr(priv) ?? '')) {
      emit('compose-privileged', lineOf(priv), `Service \`${name}\` sets \`privileged: true\``);
    }
    const caps = yamlGet(svc, 'cap_add');
    if (isSeq(caps)) {
      for (const item of caps.items as YamlNode[]) {
        const cap = (yamlStr(item) ?? '').toUpperCase().replace(/^CAP_/, '');
        if (cap === 'SYS_ADMIN' || cap === 'ALL') {
          emit('compose-privileged', lineOf(item), `Service \`${name}\` adds capability ${cap}`);
        }
      }
    }

    const volumes = yamlGet(svc, 'volumes');
    if (!isSeq(volumes)) continue;
    for (const item of volumes.items as YamlNode[]) {
      let source: string | null | undefined;
      let writable = true;
      if (isScalar(item)) {
        const spec = yamlStr(item) ?? '';
        source = volumeSource(spec);
        writable = !/:ro(?:,|$)/.test(spec.slice((source ?? '').length));
      } else if (isMap(item)) {
        const type = yamlStr(yamlGet(item, 'type'));
        if (type && type !== 'bind') continue;
        source = yamlStr(yamlGet(item, 'source'));
        writable = !/^true$/i.test(yamlStr(yamlGet(item, 'read_only')) ?? '');
      }
      if (!source) continue;
      const line = lineOf(item);
      if (isDockerSocket(source)) {
        emit('compose-docker-socket', line, `Service \`${name}\` mounts the Docker socket \`${source}\``);
      } else if (isDangerousHostPath(source)) {
        const how = writable ? 'writable' : 'read-only';
        const asRoot = runsAsRoot ? ', and the service runs as root' : '';
        emit('compose-host-root-mount', line, `Service \`${name}\` bind-mounts host path \`${source}\` (${how}${asRoot})`);
      }
    }
  }
}

// ── authorized_keys ───────────────────────────────────────────────────────

const KEY_TYPE = /^(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$/;

export interface ParsedAuthorizedKey {
  line: number;
  type: string;
  comment: string;
  options: Map<string, string | null>;
}

/** Split authorized_keys lines into options, type and comment, honouring quotes in options. */
export function parseAuthorizedKeyLines(text: string): ParsedAuthorizedKey[] {
  const out: ParsedAuthorizedKey[] = [];
  text.split('\n').forEach((raw, idx) => {
    const line = raw.replace(/\r$/, '').trim();
    if (!line || line.startsWith('#')) return;
    let optionText = '';
    let rest = line;
    if (!KEY_TYPE.test(line.split(/\s+/, 1)[0] ?? '')) {
      let inQuote = false;
      let cut = -1;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '\\' && inQuote) { i++; continue; }
        if (ch === '"') inQuote = !inQuote;
        else if (!inQuote && (ch === ' ' || ch === '\t')) { cut = i; break; }
      }
      if (cut === -1) return;
      optionText = line.slice(0, cut);
      rest = line.slice(cut).trimStart();
    }
    const parts = rest.split(/\s+/);
    if (!KEY_TYPE.test(parts[0] ?? '') || !parts[1]) return;
    const options = new Map<string, string | null>();
    for (const m of optionText.matchAll(/([A-Za-z-]+)(?:="((?:[^"\\]|\\.)*)")?/g)) {
      options.set(m[1]!.toLowerCase(), m[2] ?? null);
    }
    out.push({ line: idx + 1, type: parts[0]!, comment: parts.slice(2).join(' '), options });
  });
  return out;
}

/**
 * Is this key comment the kind an intruder picks to blend in?
 *
 * A temporary-sounding role word (`ci`, `diag`, `debug`, `tmp`, `temp`,
 * `test`, `recovery`, `maint`, `support`) next to a date stamp, and no
 * `user@host`. Real keys are overwhelmingly `user@host` or a person's name; a
 * dated "diagnostic" key nobody remembers adding is the persistence pattern.
 */
export function suspiciousKeyComment(comment: string): boolean {
  const c = comment.trim();
  if (!c || c.includes('@')) return false;
  const role = /(?:^|[-_.\s])(?:ci|cd|diag|diagnostic|debug|tmp|temp|test|recovery|maint|maintenance|support|backdoor)(?=[-_.\s]|\d|$)/i;
  const date = /(?:^|\D)(?:20\d{2}[-_.]?[01]\d[-_.]?[0-3]\d|[0-3]\d[01]\d20\d{2})(?:\D|$)/;
  return role.test(c) && date.test(c);
}

function authorizedKeysRules(text: string, emit: Emit): void {
  for (const key of parseAuthorizedKeyLines(text)) {
    const label = key.comment ? `"${key.comment}"` : '(no comment)';
    const restricted = key.options.has('from') || key.options.has('command') || key.options.has('restrict');
    if (!restricted) emit('authorized-keys-unrestricted', key.line, `Unrestricted ${key.type} key ${label}`);
    if (suspiciousKeyComment(key.comment)) {
      emit(
        'authorized-keys-suspicious-comment',
        key.line,
        `Key ${label} is named like a temporary CI/diagnostic key${restricted ? '' : ' and is unrestricted'}`,
      );
    }
    const command = key.options.get('command') ?? '';
    if (/\b(?:internal-sftp|sftp-server)\b/.test(command)) {
      emit('authorized-keys-sftp-unjailed', key.line, `Key ${label} is sftp-only; sftp alone does not limit reads`);
    }
  }
}

// ── sshd_config ───────────────────────────────────────────────────────────

function sshdRules(text: string, emit: Emit): void {
  interface Block { forceLine: number; chroot: boolean }
  const blocks: Block[] = [];
  let current: Block = { forceLine: 0, chroot: false };
  let globalChroot = false;
  let inMatch = false;
  const flush = (): void => {
    if (current.forceLine) blocks.push(current);
  };
  text.split('\n').forEach((raw, idx) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    const [keyword = '', ...rest] = line.split(/\s+/);
    const kw = keyword.toLowerCase();
    const value = rest.join(' ');
    if (kw === 'match') {
      flush();
      current = { forceLine: 0, chroot: false };
      inMatch = true;
      return;
    }
    if (kw === 'chrootdirectory' && value.toLowerCase() !== 'none') {
      current.chroot = true;
      if (!inMatch) globalChroot = true;
    }
    if (kw === 'forcecommand' && /\b(?:internal-sftp|sftp-server)\b/.test(value)) current.forceLine = idx + 1;
  });
  flush();
  for (const block of blocks) {
    if (block.chroot || globalChroot) continue;
    emit('sshd-sftp-without-chroot', block.forceLine, 'ForceCommand sftp with no ChrootDirectory: reads are not confined');
  }
}

// ── Remote deploy scripts ─────────────────────────────────────────────────

/** Split on `&&`, `||`, `;` and `|` outside quotes. */
function segments(text: string): string[] {
  const out: string[] = [];
  let quote: string | null = null;
  let cur = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\' && quote === '"') { cur += ch + (text[i + 1] ?? ''); i++; continue; }
      if (ch === quote) quote = null;
      cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; cur += ch; continue; }
    if (ch === ';' || ch === '|' || (ch === '&' && text[i + 1] === '&')) {
      out.push(cur);
      cur = '';
      if (text[i + 1] === ch) i++;
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

/** Split into words, keeping quoted runs together (quotes stay on the word). */
function shellWords(text: string): string[] {
  const out: string[] = [];
  let quote: string | null = null;
  let cur = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === quote) quote = null;
      cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; cur += ch; continue; }
    if (ch === ' ' || ch === '\t') { if (cur) out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

function unquote(word: string): string {
  if (word.length >= 2 && (word[0] === '"' || word[0] === "'") && word[word.length - 1] === word[0]) {
    return word.slice(1, -1);
  }
  return word;
}

const WRAPPERS = new Set(['sudo', 'exec', 'command', 'nohup', 'time', 'env', 'timeout', 'doas']);

/** The command words with YAML keys, wrappers and leading `VAR=value` assignments removed. */
function commandOf(segment: string): string[] {
  const words = shellWords(segment.replace(/^[-\s]*(?:run|script|command):\s*[|>]?[-+]?\s*/, ''));
  let i = 0;
  while (i < words.length) {
    const w = words[i]!;
    if (/^[A-Za-z_]\w*=/.test(w) || WRAPPERS.has(w)) { i++; continue; }
    if (words[i - 1] === 'sudo' && w.startsWith('-')) { i++; continue; }
    break;
  }
  return words.slice(i);
}

const SSH_VALUE_OPTS = new Set('BbcDEeFIiJLlmOoPpQRSWw'.split(''));

/** For `ssh [opts] host cmd...`, the remote command text, or null for an interactive ssh. */
function sshRemoteCommand(words: readonly string[]): string | null {
  let i = 1;
  while (i < words.length && words[i]!.startsWith('-')) {
    const opt = words[i]!;
    const letter = opt[opt.length - 1]!;
    i += opt.length === 2 && SSH_VALUE_OPTS.has(letter) ? 2 : 1;
  }
  i++; // host
  if (i >= words.length) return null;
  const rest = words.slice(i).filter((w) => !w.startsWith('<'));
  if (rest.length === 0) return null;
  return rest.length === 1 ? unquote(rest[0]!) : rest.map(unquote).join(' ');
}

/** The remote path of the last `host:path` argument of an rsync/scp command, or null. */
function transferDestination(words: readonly string[]): string | null {
  for (let i = words.length - 1; i > 0; i--) {
    const w = unquote(words[i]!);
    if (w.startsWith('-')) continue;
    const m = /^(?:[\w.${}-]+@)?[\w.${}-]+:(.*)$/.exec(w);
    if (m && !w.includes('://')) return m[1] || '~';
    return null;
  }
  return null;
}

/** `rsync --server ... . /srv/builds/x` as seen by a forced-command wrapper. */
function rsyncServerDestination(words: readonly string[]): string | null {
  if (!words.includes('--server')) return null;
  const last = words[words.length - 1];
  return last && !last.startsWith('-') ? unquote(last) : null;
}

function normDir(path: string): string {
  return path.replace(/\/\*+$/, '').replace(/\/+$/, '') || '/';
}

function joinPath(cwd: string | null, path: string): string {
  if (path.startsWith('/') || path.startsWith('~') || path.startsWith('$')) return path;
  const clean = path.replace(/^\.\//, '');
  return cwd ? `${normDir(cwd)}/${clean}` : clean;
}

function under(path: string, dirs: Iterable<string>): string | null {
  const p = normDir(path);
  for (const d of dirs) {
    const dir = normDir(d);
    if (dir === '~' || dir === '.' || dir === '/') continue;
    if (p === dir || p.startsWith(`${dir}/`)) return dir;
    // A glob or variable in the synced destination (`/srv/builds/*`) covers
    // anything with the same fixed prefix.
    const fixed = dir.split(/[*$]/)[0]!;
    if (fixed.length > 1 && fixed !== dir && p.startsWith(fixed)) return dir;
  }
  return null;
}

const COMPOSE = /\bdocker(?:-compose|\s+compose)\b/;
const COMPOSE_FILE = /(?:^|\s)(?:-f|--file)(?:=|\s+)['"]?([^\s'";|&]+)/;

interface RemoteState {
  cwd: string | null;
  uploads: Set<string>;
  gitDirs: Set<string>;
  forced: boolean;
}

/**
 * One command as it runs on the remote host (inside an ssh command string, an
 * ssh heredoc, an ssh-action `script:`, or a forced-command wrapper).
 */
function remoteSegment(segment: string, line: number, state: RemoteState, emit: Emit): void {
  const words = commandOf(segment);
  const cmd = words[0] ?? '';
  if (cmd === 'cd' && words[1]) {
    state.cwd = joinPath(state.cwd, unquote(words[1]));
    return;
  }
  if (cmd === 'git' && /^(?:pull|clone|fetch|checkout|reset)$/.test(words[1] ?? '')) {
    if (words[1] === 'clone' && words.length > 3) state.gitDirs.add(joinPath(state.cwd, unquote(words[words.length - 1]!)));
    else if (state.cwd) state.gitDirs.add(state.cwd);
    return;
  }
  if (cmd === 'rsync') {
    const dest = rsyncServerDestination(words);
    if (dest) state.uploads.add(dest);
    return;
  }

  if (COMPOSE.test(segment)) {
    const file = COMPOSE_FILE.exec(segment)?.[1];
    const target = file ? joinPath(state.cwd, file) : state.cwd;
    const synced = target ? under(target, state.uploads) : null;
    const pulled = target ? under(target, state.gitDirs) : null;
    const forcedWithRsync = state.forced && state.uploads.size > 0 && Boolean(file);
    if (synced || pulled || forcedWithRsync) {
      const where = synced
        ? `under \`${synced}\`, which this file uploads to`
        : pulled
          ? `in \`${pulled}\`, a git checkout updated on the host`
          : 'in a forced-command allowlist that also accepts rsync uploads';
      const build = /\s--build\b|\sbuild\b/.test(segment) ? ' and builds from it' : '';
      emit(
        'deploy-compose-from-synced-repo',
        line,
        `\`docker compose\` runs ${file ? `\`${file}\`` : 'the compose file in the working directory'} ${where}${build}`,
      );
    }
    return;
  }

  // Running a script by path: `bash /srv/app/deploy.sh`, `./deploy.sh`, `sh x.sh`.
  let script: string | undefined;
  if (/^(?:ba|z|da|k)?sh$|^source$|^\.$/.test(cmd) && words[1] && !words[1].startsWith('-')) script = unquote(words[1]);
  else if (/\.(?:sh|bash|py|rb|pl)$/.test(cmd) || cmd.startsWith('./')) script = cmd;
  if (script) {
    const path = joinPath(state.cwd, script);
    const dir = under(path, state.uploads);
    if (dir) {
      emit('deploy-remote-exec-uploaded-script', line, `Runs \`${script}\` on the host from \`${dir}\`, which this file uploads to`);
    }
  }
}

interface LogicalLine { text: string; line: number }

/** Join backslash-continued lines, keeping the first line's number. */
function logicalLines(text: string): LogicalLine[] {
  const raw = text.split('\n');
  const out: LogicalLine[] = [];
  for (let i = 0; i < raw.length; i++) {
    let t = raw[i]!;
    const start = i + 1;
    while (/\\\s*$/.test(t) && i + 1 < raw.length) {
      t = t.replace(/\\\s*$/, ' ') + raw[++i]!.trim();
    }
    out.push({ text: t, line: start });
  }
  return out;
}

function isCommentLine(text: string): boolean {
  return /^\s*#/.test(text);
}

function remoteDeployRules(text: string, isWorkflow: boolean, emit: Emit): void {
  const forced = /\bSSH_ORIGINAL_COMMAND\b/.test(text);
  const lines = logicalLines(text);

  // Pass 1: every upload destination in the file, so an rsync written after
  // the ssh that uses it (or in another job) still counts.
  const uploads = new Set<string>();
  let sawScpAction = false;
  for (const { text: t } of lines) {
    if (isCommentLine(t)) continue;
    for (const seg of segments(t)) {
      const words = commandOf(seg);
      if (words[0] === 'rsync' || words[0] === 'scp') {
        const dest = transferDestination(words) ?? rsyncServerDestination(words);
        if (dest) uploads.add(dest);
      }
    }
    if (isWorkflow) {
      if (/uses:\s*['"]?appleboy\/scp-action@/.test(t)) sawScpAction = true;
      const target = /^\s*target:\s*['"]?([^'"\s]+)/.exec(t);
      if (target && sawScpAction) {
        uploads.add(target[1]!);
        sawScpAction = false;
      }
    }
    // A forced-command wrapper usually *allows* rsync rather than running it:
    // `rsync\ --server*\ /srv/builds/*)` in a case arm.
    if (forced) {
      const allowed = /rsync(?:\\?\s)+--server[^)\n]*?\s(\/[^\s)"'*]+)/.exec(t);
      if (allowed) uploads.add(allowed[1]!);
    }
  }

  const fresh = (): RemoteState => ({ cwd: null, uploads, gitDirs: new Set(), forced });
  let heredoc: { end: string; state: RemoteState } | null = null;
  let actionScript: { indent: number; state: RemoteState } | null = null;
  let sawSshAction = false;
  const forcedState = fresh();

  for (const { text: t, line } of lines) {
    if (heredoc) {
      if (t.trim() === heredoc.end) { heredoc = null; continue; }
      if (!isCommentLine(t)) for (const seg of segments(t)) remoteSegment(seg, line, heredoc.state, emit);
      continue;
    }
    if (actionScript) {
      const indent = /^\s*/.exec(t)![0].length;
      if (t.trim() && indent <= actionScript.indent) actionScript = null;
      else {
        if (!isCommentLine(t)) for (const seg of segments(t)) remoteSegment(seg, line, actionScript.state, emit);
        continue;
      }
    }
    if (isCommentLine(t)) continue;

    if (isWorkflow) {
      if (/uses:\s*['"]?appleboy\/ssh-action@/.test(t)) sawSshAction = true;
      const script = /^(\s*)script:\s*[|>]?[-+]?\s*$/.exec(t);
      if (script && sawSshAction) {
        actionScript = { indent: script[1]!.length, state: fresh() };
        sawSshAction = false;
        continue;
      }
    }

    if (forced) {
      // In a forced-command wrapper every allowed command runs on this host.
      // A case arm (`pattern) cmd ;;`) is reduced to its command.
      const body = t.replace(/^\s*[^()]*\)\s*/, '').replace(/;;\s*$/, '');
      for (const seg of segments(body)) remoteSegment(seg, line, forcedState, emit);
      continue;
    }

    for (const seg of segments(t)) {
      const words = commandOf(seg);
      if (words[0] !== 'ssh') continue;
      // `ssh host bash -s < deploy.sh`: a local, repository-controlled script
      // piped in as the remote program.
      const piped = /(?:^|\s)(?:ba|z)?sh\s+-s\b[^<]*<(?!<)\s*['"]?([^\s'"<]+)/.exec(seg);
      if (piped) {
        emit('deploy-remote-exec-uploaded-script', line, `Pipes repository script \`${piped[1]}\` into a remote shell`);
        continue;
      }
      const here = /<<-?\s*['"]?(\w+)['"]?/.exec(seg);
      if (here) {
        heredoc = { end: here[1]!, state: fresh() };
        continue;
      }
      const remote = sshRemoteCommand(words);
      if (!remote) continue;
      const state = fresh();
      for (const inner of segments(remote)) remoteSegment(inner, line, state, emit);
    }
  }
}

// ── GitHub App setup callback ─────────────────────────────────────────────

/** Reading `installation_id` from the request's query string, in the common frameworks. */
const INSTALLATION_FROM_QUERY = new RegExp(
  [
    String.raw`searchParams\.get\(\s*['"]installation_id['"]`,
    String.raw`\b(?:req|request|ctx|context)\.(?:query|params)(?:\.installation_id\b|\[\s*['"]installation_id['"])`,
    String.raw`\bquery\.installation_id\b`,
    String.raw`\bquery\[\s*['"]installation_id['"]\s*\]`,
    String.raw`\breq\.query\(\s*['"]installation_id['"]`,
    String.raw`request\.(?:args|GET|query_params)(?:\.get\(\s*|\[\s*)['"]installation_id['"]`,
    String.raw`\bparams\[\s*:installation_id\s*\]`,
    String.raw`\$_(?:GET|REQUEST)\[\s*['"]installation_id['"]`,
    String.raw`Query\(\)\.Get\(\s*"installation_id"`,
    String.raw`getParameter\(\s*"installation_id"`,
    String.raw`\{[^}]*\binstallation_id\b[^}]*\}\s*=\s*(?:await\s+)?(?:req|request|ctx)\.query\b`,
  ].join('|'),
);

/** A database write. */
const PERSISTS =
  /\.(?:insert|upsert|create|createMany|save|update|updateOne|findOneAndUpdate)\s*\(|\bINSERT\s+INTO\b|\bON\s+CONFLICT\b|\bUPDATE\s+\w+\s+SET\b|\.objects\.(?:create|update_or_create|get_or_create)\b/i;

/** Evidence the handler asked GitHub which installations the *user* can see. */
const VERIFIES_USER =
  /\/user\/installations|listInstallationsForAuthenticatedUser|(?:verify|check|assert|ensure|validate|confirm)\w*Installation\w*\s*\(|installationBelongsTo\w*\s*\(|userCanAccessInstallation\s*\(/;

/** Top-level declarations that start a new handler or function. */
const DECLARATION =
  /^(?:export\s+(?:default\s+)?)?(?:async\s+)?function\b|^(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\b|function\b|\(|\w+\s*=>)|^(?:async\s+)?def\s|^func\s|^\s{0,4}(?:public\s+|private\s+|protected\s+)?(?:static\s+)?function\s|^(?:app|router|server)\.(?:get|post|put|all|route)\s*\(|^@\w+\.(?:route|get|post)\b|^\s{0,2}def\s/;

function githubAppCallbackRule(text: string, emit: Emit): void {
  if (!text.includes('installation_id') || !INSTALLATION_FROM_QUERY.test(text)) return;
  const lines = text.split('\n');

  // Chunk the file at top-level declarations: an approximation of "the same
  // handler" that needs no parser and is right for route files, which keep
  // one handler per exported function.
  const chunks: Array<{ start: number; end: number }> = [];
  let start = 0;
  for (let i = 1; i < lines.length; i++) {
    if (DECLARATION.test(lines[i]!)) {
      chunks.push({ start, end: i });
      start = i;
    }
  }
  chunks.push({ start, end: lines.length });

  // Helpers defined in this file that do the verification count when called.
  const verifyingHelpers = new Set<string>();
  for (const c of chunks) {
    const body = lines.slice(c.start, c.end).join('\n');
    if (!VERIFIES_USER.test(body)) continue;
    const name = /(?:function\s+|(?:const|let|var)\s+|def\s+|func\s+)(\w+)/.exec(lines[c.start] ?? '')?.[1];
    if (name) verifyingHelpers.add(name);
  }

  for (const c of chunks) {
    const chunkLines = lines.slice(c.start, c.end);
    const body = chunkLines.join('\n');
    const readAt = chunkLines.findIndex((l) => INSTALLATION_FROM_QUERY.test(l) && !/^\s*(?:\/\/|#|\*)/.test(l));
    if (readAt === -1) continue;
    if (!PERSISTS.test(body)) continue;
    if (VERIFIES_USER.test(body)) continue;
    if ([...verifyingHelpers].some((name) => new RegExp(`\\b${name}\\s*\\(`).test(body))) continue;
    emit(
      'github-app-installation-idor',
      c.start + readAt + 1,
      '`installation_id` is read from the query string and stored, with no check that the signed-in user can access that installation (`GET /user/installations`)',
    );
  }
}
