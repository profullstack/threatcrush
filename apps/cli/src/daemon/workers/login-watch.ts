import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { isIP } from 'node:net';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';
import { getModuleState, insertEvent, setModuleState } from '../../core/state.js';
import { DEFAULT_PROTECTED, ipToBytes, isProtected } from '../firewall/protected.js';
import type { RuleRemediation } from '../firewall/remediation.js';

/**
 * `[login_watch]`: successful SSH logins worth a look.
 *
 * 2026-11-20, dev2: the intruder logged in over SSH as root and anthony with
 * stolen but valid keys, from residential-proxy and datacenter addresses.
 * Nothing failed, so nothing fired. This classifies every accepted login:
 *
 *   - `ssh-login-tor` (critical): from a Tor exit.
 *   - `ssh-login-sensitive` (critical for root, high otherwise): root or a
 *     member of sudo/admin/wheel/docker (or a configured user) logged in from
 *     an address outside `trusted_login_cidrs`, the `[remediation] protected`
 *     list and the private/tailnet ranges. With no trusted CIDRs configured,
 *     every such public login alerts: that is the point.
 *   - `ssh-login-new-network` (medium): the first login ever for that user
 *     from that /24 (IPv6: /48). Seen networks persist in the state db.
 *
 * Alerts carry the user, address, auth method and key fingerprint. With
 * `auto_response = true` (default off) a high/critical one also bans the
 * address (even though it logged in) and kills that user's sshd sessions from
 * it, unless `[remediation]` is in dry_run. Private, loopback, tailnet and
 * protected addresses are never acted on, and never alerted as sensitive.
 *
 *   [login_watch]
 *   enabled = true
 *   sensitive_users = ["root"]                           # plus members of sensitive_groups
 *   sensitive_groups = ["sudo", "admin", "wheel", "docker"]
 *   trusted_login_cidrs = []                             # e.g. ["203.0.113.0/24"]
 *   first_seen = true                                    # new /24 per user (medium)
 *   auto_response = false                                # ban + kill session on high/critical
 */

export interface LoginWatchSection {
  enabled?: boolean;
  sensitive_users?: string[];
  sensitive_groups?: string[];
  trusted_login_cidrs?: string[];
  first_seen?: boolean;
  auto_response?: boolean;
}

export interface LoginWatchSettings {
  enabled: boolean;
  sensitiveUsers: string[];
  sensitiveGroups: string[];
  trustedCidrs: string[];
  firstSeen: boolean;
  autoResponse: boolean;
}

export const DEFAULT_SENSITIVE_GROUPS = ['sudo', 'admin', 'wheel', 'docker'];

function stringList(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) return fallback;
  return [...new Set(value.map((v) => String(v).trim()).filter(Boolean))];
}

export function loginWatchSettings(section?: LoginWatchSection): LoginWatchSettings {
  return {
    enabled: section?.enabled !== false,
    // root is always sensitive, whatever the list says.
    sensitiveUsers: [...new Set(['root', ...stringList(section?.sensitive_users, [])])],
    sensitiveGroups: stringList(section?.sensitive_groups, DEFAULT_SENSITIVE_GROUPS),
    trustedCidrs: stringList(section?.trusted_login_cidrs, []),
    firstSeen: section?.first_seen !== false,
    autoResponse: section?.auto_response === true,
  };
}

/**
 * Members of `groups`: listed members in /etc/group plus every account whose
 * primary group is one of them (/etc/passwd), which /etc/group does not list.
 */
export function groupMembers(groupText: string, passwdText: string, groups: string[]): Set<string> {
  const wanted = new Set(groups);
  const gids = new Set<string>();
  const out = new Set<string>();
  for (const line of groupText.split('\n')) {
    const [name, , gid, members] = line.split(':');
    if (!name || !wanted.has(name)) continue;
    if (gid) gids.add(gid);
    for (const m of (members ?? '').split(',')) if (m.trim()) out.add(m.trim());
  }
  for (const line of passwdText.split('\n')) {
    const [name, , , gid] = line.split(':');
    if (name && gid && gids.has(gid)) out.add(name);
  }
  return out;
}

/** The network a login is remembered by: `1.2.3.0/24`, or the /48 for IPv6. */
export function networkOf(ip: string): string | null {
  const bytes = ipToBytes(ip);
  if (!bytes) return null;
  if (bytes.length === 4) return `${bytes[0]}.${bytes[1]}.${bytes[2]}.0/24`;
  // A v4-mapped v6 address is a v4 login.
  if (bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return `${bytes[12]}.${bytes[13]}.${bytes[14]}.0/24`;
  }
  const h = (i: number) => ((bytes[i] << 8) | bytes[i + 1]).toString(16);
  return `${h(0)}:${h(2)}:${h(4)}::/48`;
}

export type LoginReason = 'tor_exit' | 'sensitive_user' | 'first_seen_network';

export interface LoginClassification {
  ruleId: 'ssh-login-tor' | 'ssh-login-sensitive' | 'ssh-login-new-network';
  severity: EventSeverity;
  reasons: LoginReason[];
  network: string | null;
}

export interface LoginContext {
  isTor: (ip: string) => boolean;
  sensitive: (user: string) => boolean;
  /** trusted_login_cidrs plus the `[remediation]` protected list. */
  trusted: (ip: string) => boolean;
  /** Whether this user has logged in from this network before; undefined when first_seen is off. */
  seenNetwork?: (user: string, network: string) => boolean;
}

/** Why an accepted login is suspicious, or null when it is not. Pure: no I/O. */
export function classifyLogin(login: { user: string; ip: string }, ctx: LoginContext): LoginClassification | null {
  const { user, ip } = login;
  if (!user || !isIP(ip)) return null;
  // Private, loopback, link-local, tailnet (100.64/10, fc00::/7): never ours to judge.
  if (isProtected(ip, DEFAULT_PROTECTED)) return null;
  const network = networkOf(ip);
  const reasons: LoginReason[] = [];
  const tor = ctx.isTor(ip);
  if (tor) reasons.push('tor_exit');
  const trusted = ctx.trusted(ip);
  if (!trusted && ctx.sensitive(user)) reasons.push('sensitive_user');
  if (network && ctx.seenNetwork && !trusted && !ctx.seenNetwork(user, network)) reasons.push('first_seen_network');
  if (!reasons.length) return null;

  if (tor) return { ruleId: 'ssh-login-tor', severity: 'critical', reasons, network };
  if (reasons.includes('sensitive_user')) {
    return { ruleId: 'ssh-login-sensitive', severity: user === 'root' ? 'critical' : 'high', reasons, network };
  }
  return { ruleId: 'ssh-login-new-network', severity: 'medium', reasons, network };
}

// ─── Seen networks ───────────────────────────────────────────────────────────

/** user → network → first/last seen (ISO) and count. */
export type SeenNetworks = Record<string, Record<string, { first: string; last: string; count: number }>>;

export interface SeenStore {
  load(): SeenNetworks | null;
  save(seen: SeenNetworks): void;
}

const STATE_MODULE = 'login-watch';
const STATE_KEY = 'seen-networks';

const dbStore: SeenStore = {
  load: () => {
    try {
      const v = getModuleState(STATE_MODULE, STATE_KEY);
      return v && typeof v === 'object' ? (v as SeenNetworks) : null;
    } catch { return null; }
  },
  save: (seen) => { try { setModuleState(STATE_MODULE, STATE_KEY, seen); } catch { /* db optional */ } },
};

/** `journalctl -o short-unix` "Accepted <method> for <user> from <ip>" → [user, ip, ms]. */
export function parseAcceptedLogins(text: string): Array<{ user: string; ip: string; at: number }> {
  const out: Array<{ user: string; ip: string; at: number }> = [];
  for (const line of text.split('\n')) {
    const m = /^(\d+(?:\.\d+)?)\s.*Accepted \S+ for (\S+) from (\S+) port \d+/.exec(line);
    if (m && isIP(m[3])) out.push({ user: m[2], ip: m[3], at: Math.round(Number(m[1]) * 1000) });
  }
  return out;
}

// ─── Killing a session ───────────────────────────────────────────────────────

/** A peer address as `ss` prints it (`1.2.3.4:22`, `[2001:db8::1]:22`, `[::ffff:1.2.3.4]:22`) → bare IP. */
export function ssPeerIp(field: string): string | null {
  let host = field;
  const bracket = /^\[([^\]]+)\]:\d+$/.exec(field);
  if (bracket) host = bracket[1];
  else host = field.replace(/:\d+$/, '');
  host = host.split('%')[0];
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(host)) host = host.slice(7);
  return isIP(host) ? host : null;
}

/** sshd pids holding an established connection to `ip`, from `ss -Htnp state established`. */
export function sshdPidsForPeer(ssOutput: string, ip: string): number[] {
  const pids = new Set<number>();
  for (const line of ssOutput.split('\n')) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    // Recv-Q Send-Q Local Peer [users:(...)]
    const peer = ssPeerIp(cols[3]);
    if (peer !== ip) continue;
    for (const m of line.matchAll(/\("(sshd[^"]*)",pid=(\d+),/g)) pids.add(Number(m[2]));
  }
  return [...pids];
}

export interface SessionKillDeps {
  run(cmd: string, args: string[]): string | null;
  cmdline(pid: number): string | null;
  kill(pid: number, signal: NodeJS.Signals): void;
}

const realKillDeps: SessionKillDeps = {
  run: (cmd, args) => {
    const res = spawnSync(cmd, args, { encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'] });
    return res.status === 0 ? res.stdout : null;
  },
  cmdline: (pid) => {
    try { return readFileSync(`/proc/${pid}/cmdline`, 'utf-8').replace(/\0+$/, '').replace(/\0/g, ' '); } catch { return null; }
  },
  kill: (pid, signal) => { process.kill(pid, signal); },
};

/**
 * SIGKILL `user`'s sshd session processes connected from `ip`. Only processes
 * whose title names the user (`sshd-session: anthony [priv]`, `sshd: anthony@pts/0`)
 * are touched, never the listener.
 */
export function killSshSessions(user: string, ip: string, deps: SessionKillDeps = realKillDeps): number[] {
  const out = deps.run('ss', ['-Htnp', 'state', 'established']);
  if (!out) return [];
  const killed: number[] = [];
  const title = new RegExp(`^sshd(?:-session)?: ${user.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:@|\\s|$)`);
  for (const pid of sshdPidsForPeer(out, ip)) {
    if (pid <= 1 || pid === process.pid) continue;
    const cmd = deps.cmdline(pid) ?? '';
    if (/listener|-D\b|\/usr\/sbin\/sshd/.test(cmd) || !title.test(cmd)) continue;
    try { deps.kill(pid, 'SIGKILL'); killed.push(pid); } catch { /* gone */ }
  }
  return killed;
}

// ─── The watcher ─────────────────────────────────────────────────────────────

export const LOGIN_REMEDIATION: RuleRemediation = {
  action: 'block',
  description: 'Ban the address that logged in (login_watch auto_response)',
  ban_on_login: true,
  // The login itself marked the address as an operator's; only our own
  // configured addresses may protect it from this ban.
  override_operator_protection: true,
};

const SEVERITY_RANK: Record<EventSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface LoginWatchOptions {
  bus: {
    publish(event: ThreatEvent): void;
    on(name: 'event', fn: (event: ThreatEvent) => void): unknown;
    off(name: 'event', fn: (event: ThreatEvent) => void): unknown;
  };
  settings: LoginWatchSettings;
  tor: { has(ip: string): boolean };
  manager: { isFleetAddress(ip: string): boolean; status(): { dry_run: boolean } };
  log: (line: string) => void;
  store?: SeenStore;
  /** /etc/group and /etc/passwd text. */
  readAccounts?: () => { group: string; passwd: string };
  /** journalctl runner for the first-run baseline. */
  run?: (cmd: string, args: string[]) => string | null;
  killDeps?: SessionKillDeps;
  now?: () => number;
}

export class LoginWatch {
  private seen: SeenNetworks = {};
  private sensitiveCache: { at: number; users: Set<string> } = { at: -Infinity, users: new Set() };
  private readonly now: () => number;
  private readonly store: SeenStore;
  private readonly onEvent = (event: ThreatEvent) => { this.check(event); };

  constructor(private opts: LoginWatchOptions) {
    this.now = opts.now ?? Date.now;
    this.store = opts.store ?? dbStore;
  }

  start(): boolean {
    const s = this.opts.settings;
    if (!s.enabled) return false;
    if (s.firstSeen) this.loadSeen();
    this.opts.bus.on('event', this.onEvent);
    this.opts.log(`[login-watch] sensitive: ${[...this.sensitiveUsers()].join(', ') || 'none'}; trusted CIDRs: ${s.trustedCidrs.join(', ') || 'none (every public login of a sensitive user alerts)'}; auto_response ${s.autoResponse ? 'ON' : 'off'}`);
    return true;
  }

  stop(): void {
    this.opts.bus.off('event', this.onEvent);
  }

  private sensitiveUsers(): Set<string> {
    if (this.now() - this.sensitiveCache.at < 300_000) return this.sensitiveCache.users;
    const users = new Set(this.opts.settings.sensitiveUsers);
    try {
      const { group, passwd } = this.opts.readAccounts?.() ?? {
        group: readFileSync('/etc/group', 'utf-8'),
        passwd: readFileSync('/etc/passwd', 'utf-8'),
      };
      for (const u of groupMembers(group, passwd, this.opts.settings.sensitiveGroups)) users.add(u);
    } catch { /* root alone */ }
    this.sensitiveCache = { at: this.now(), users };
    return users;
  }

  private loadSeen(): void {
    const saved = this.store.load();
    if (saved) { this.seen = saved; return; }
    // First run: learn the last 30 days so every existing habit does not alert.
    const run = this.opts.run ?? ((cmd, args) => {
      const res = spawnSync(cmd, args, { encoding: 'utf-8', timeout: 60_000, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
      return res.status === 0 ? res.stdout : null;
    });
    const out = run('journalctl', ['_COMM=sshd', '_COMM=sshd-session', '--since=-30d', '-o', 'short-unix', '--no-pager', '--grep', 'Accepted ']);
    let n = 0;
    for (const { user, ip, at } of parseAcceptedLogins(out ?? '')) {
      // Tor exits are not learned: a breached box's journal holds the intruder's logins.
      if (this.opts.tor.has(ip) || isProtected(ip, DEFAULT_PROTECTED)) continue;
      const net = networkOf(ip);
      if (!net) continue;
      const iso = new Date(at).toISOString();
      const entry = ((this.seen[user] ??= {})[net] ??= { first: iso, last: iso, count: 0 });
      entry.count++;
      if (iso > entry.last) entry.last = iso;
      if (iso < entry.first) entry.first = iso;
      n++;
    }
    this.store.save(this.seen);
    this.opts.log(`[login-watch] network baseline from the last 30 days: ${Object.keys(this.seen).length} user(s), ${n} login(s)`);
  }

  private trusted(ip: string): boolean {
    return isProtected(ip, this.opts.settings.trustedCidrs) || this.opts.manager.isFleetAddress(ip);
  }

  /** One bus event; the suspicious-login event it raised, if any. */
  check(event: ThreatEvent): ThreatEvent | null {
    if (event.module !== 'ssh-guard' || !/SSH login accepted/.test(event.message)) return null;
    const d = (event.details ?? {}) as Record<string, unknown>;
    const ip = event.source_ip;
    const user = typeof d.ssh_user === 'string' ? d.ssh_user : /SSH login accepted for (\S+)/.exec(event.message)?.[1];
    if (!ip || !user || user === 'unknown') return null;

    const s = this.opts.settings;
    const verdict = classifyLogin({ user, ip }, {
      isTor: (a) => this.opts.tor.has(a),
      sensitive: (u) => this.sensitiveUsers().has(u),
      trusted: (a) => this.trusted(a),
      ...(s.firstSeen ? { seenNetwork: (u: string, net: string) => !!this.seen[u]?.[net] } : {}),
    });

    // Remember the network either way; a Tor exit is never learned.
    const net = networkOf(ip);
    if (s.firstSeen && net && !this.opts.tor.has(ip) && !isProtected(ip, DEFAULT_PROTECTED)) {
      const iso = new Date(this.now()).toISOString();
      const entry = ((this.seen[user] ??= {})[net] ??= { first: iso, last: iso, count: 0 });
      entry.last = iso;
      entry.count++;
      this.store.save(this.seen);
    }
    if (!verdict) return null;

    const method = typeof d.auth_method === 'string' ? d.auth_method : undefined;
    const fp = typeof d.fingerprint === 'string' ? d.fingerprint : undefined;
    const keyComment = typeof d.key_comment === 'string' ? d.key_comment : undefined;
    const how = [method, fp, keyComment ? `(${keyComment})` : ''].filter(Boolean).join(' ');
    const why = verdict.reasons.map((r) => r === 'tor_exit' ? 'Tor exit' : r === 'sensitive_user' ? 'privileged account from an untrusted address' : `first login from ${verdict.network}`).join('; ');

    const actable = s.autoResponse
      && SEVERITY_RANK[verdict.severity] >= SEVERITY_RANK.high
      && !isProtected(ip, DEFAULT_PROTECTED)
      && !this.opts.manager.isFleetAddress(ip)
      && !isProtected(ip, s.trustedCidrs);
    let killed: number[] = [];
    let response: string | undefined;
    if (actable) {
      if (this.opts.manager.status().dry_run) {
        response = 'dry_run: would ban and end the session';
      } else {
        killed = killSshSessions(user, ip, this.opts.killDeps);
        response = `banning; ${killed.length ? `killed sshd ${killed.join(', ')}` : 'no live session found'}`;
      }
    }

    const out: ThreatEvent = {
      timestamp: event.timestamp,
      module: 'login-watch',
      category: 'auth',
      severity: verdict.severity,
      message: `Suspicious SSH login: ${user} from ${ip}${how ? ` via ${how}` : ''}: ${why}${response ? ` (${response})` : ''}`,
      source_ip: ip,
      details: {
        rule_id: verdict.ruleId,
        description: 'A successful login a stolen key or password would also produce. Confirm it was you; if not, rotate the key and check authorized_keys.',
        account: user,
        login_ip: ip,
        network: verdict.network,
        reasons: verdict.reasons,
        tor_exit: verdict.reasons.includes('tor_exit'),
        ...(method ? { auth_method: method } : {}),
        ...(fp ? { fingerprint: fp } : {}),
        ...(keyComment ? { key_comment: keyComment } : {}),
        auto_response: actable,
        ...(killed.length ? { killed_sessions: killed } : {}),
        ...(actable ? { remediation: LOGIN_REMEDIATION } : {}),
        evidence: { at: event.timestamp.toISOString(), module: 'ssh-guard', message: event.message.slice(0, 500) },
      },
    };
    try { insertEvent(out); } catch { /* db optional */ }
    this.opts.bus.publish(out);
    return out;
  }
}
