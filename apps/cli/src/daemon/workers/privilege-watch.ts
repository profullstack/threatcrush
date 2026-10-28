import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, watch, writeFileSync, type FSWatcher } from 'node:fs';
import { dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { ThreatEvent } from '../../types/events.js';
import type { PrivilegedSection } from '../../types/config.js';
import { insertEvent } from '../../core/state.js';
import { DEFAULT_PROTECTED, isProtected } from '../firewall/protected.js';
import {
  diffSnapshots,
  parseSudoMessage,
  takeSnapshot,
  type PrivilegeSnapshot,
  type SnapshotIO,
} from '../../core/privileges/index.js';

/**
 * Privileged access and identity (issue #305, PRD 0019 R3):
 *
 *   - who can become root: uid-0 accounts, sudo/wheel/admin members, sudoers
 *     rules and every login account's authorized_keys, diffed each minute
 *     against the last snapshot;
 *   - the root ledger: each sudo command from the system journal, kept locally
 *     as an info event (denied commands are medium);
 *   - an accepted SSH login from a country that user has never logged in from.
 *
 * Events come from module `privileged-access` and never carry `source_ip`:
 * the login IP of a real user is not an attacker for auto-defence to ban on
 * a geography hunch. A first run only records the baseline.
 */

export interface PrivilegeWatchSettings {
  enabled: boolean;
  geo: boolean;
  pollMs: number;
  /** Fingerprints or comment globs of keys whose addition is expected (high, not critical). */
  expectedKeys?: string[];
  /** React to authorized_keys writes at once (inotify) instead of at the next poll. */
  watchFiles?: boolean;
}

export function privilegeSettings(section: PrivilegedSection | undefined): PrivilegeWatchSettings {
  return {
    enabled: section?.enabled !== false,
    geo: section?.geo !== false,
    pollMs: 60_000,
    expectedKeys: Array.isArray(section?.expected_keys) ? section.expected_keys.map(String).filter(Boolean) : [],
    watchFiles: true,
  };
}

/** A comment glob (`*` wildcard) or an exact SHA256 fingerprint. */
export function keyIsExpected(fingerprint: string, comment: string, expected: string[]): boolean {
  return expected.some((pattern) => {
    if (pattern.startsWith('SHA256:')) return pattern === fingerprint;
    const re = new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 'i');
    return re.test(comment);
  });
}

/** The comment our own self-test key carries; its alert says TEST. */
export const SELFTEST_KEY_COMMENT = 'threatcrush-selftest';

/**
 * A new authorized key is the step that turns one stolen login into
 * persistence (2026-10-27: `ops-recovery-20261027` appended to root's and
 * anthony's authorized_keys and authorized_keys2, then used 852 times). So any
 * addition is critical, which pages on-call, unless `[privileged]
 * expected_keys` names it (then high). The self-test key is labelled TEST.
 */
export function classifyKeyAddition(
  change: { severity: ThreatEvent['severity']; message: string; details: Record<string, unknown> },
  expected: string[],
): { severity: ThreatEvent['severity']; message: string; details: Record<string, unknown> } {
  if (change.details.rule_id !== 'priv-authorized-key-added') return change;
  const fp = String(change.details.fingerprint ?? '');
  const comment = String(change.details.comment ?? '');
  const account = String(change.details.account ?? '?');
  if (comment.includes(SELFTEST_KEY_COMMENT)) {
    return {
      severity: 'critical',
      message: `[TEST] ThreatCrush self-test: new SSH key for ${account} detected (${fp}, ${comment}). This is a test, nothing is wrong.`,
      details: { ...change.details, rule_id: 'priv-authorized-key-selftest', selftest: true },
    };
  }
  if (keyIsExpected(fp, comment, expected)) {
    return { ...change, severity: 'high', details: { ...change.details, expected: true } };
  }
  return {
    severity: 'critical',
    message: `New SSH key added for ${account}: ${change.details.key_type ?? ''} ${fp}${comment ? ` "${comment}"` : ' (no comment)'}, not an expected key; whoever holds it can log in`,
    details: { ...change.details, expected: false },
  };
}

interface LoginHistory { [user: string]: { [country: string]: { first: string; last: string } } }

/**
 * Only an ISO country code crosses over from the geo service, and only after
 * it is checked: anything this worker emits ends up in the daemon log, so no
 * free text from a remote answer (city names, error strings) may reach it.
 */
export interface GeoPoint { countryCode: string }

const COUNTRY_NAMES = new Intl.DisplayNames(['en'], { type: 'region' });

export function countryName(code: string): string {
  try { return COUNTRY_NAMES.of(code) ?? code; } catch { return code; }
}

export interface PrivilegeWatchOptions {
  settings: PrivilegeWatchSettings;
  bus: { publish(event: ThreatEvent): void; on(name: 'event', fn: (event: ThreatEvent) => void): unknown; off(name: 'event', fn: (event: ThreatEvent) => void): unknown };
  snapshotPath: string;
  loginsPath: string;
  cursorPath: string;
  log: (line: string) => void;
  io?: SnapshotIO;
  /** `journalctl` runner: stdout, or null on failure. */
  run?: (cmd: string, args: string[]) => string | null;
  /** Country for a public IP, or null when unknown. */
  geolocate?: (ip: string) => Promise<GeoPoint | null>;
  /** Country codes for many IPs at once (the first-run backfill). */
  geolocateMany?: (ips: string[]) => Promise<Map<string, string>>;
  now?: () => Date;
}

const fsIO: SnapshotIO = {
  readFile: (p) => { try { return readFileSync(p, 'utf-8'); } catch { return null; } },
  readDir: (p) => { try { return readdirSync(p); } catch { return null; } },
  exists: (p) => existsSync(p),
};

function readJson<T>(path: string): T | null {
  try { return JSON.parse(readFileSync(path, 'utf-8')) as T; } catch { return null; }
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(`${path}.tmp`, JSON.stringify(value));
  renameSync(`${path}.tmp`, path);
}

function defaultRun(cmd: string, args: string[]): string | null {
  const res = spawnSync(cmd, args, { encoding: 'utf-8', timeout: 20_000, maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  return res.status === 0 ? res.stdout : null;
}

/** threatcrush.com/api/geo, the same service the TUI attack map uses. */
export async function geolocateViaThreatcrush(ip: string, fetchImpl: typeof fetch = fetch): Promise<GeoPoint | null> {
  const res = await fetchImpl('https://threatcrush.com/api/geo', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ips: [ip] }),
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) return null;
  const body = (await res.json()) as { results?: Record<string, { countryCode?: unknown }> };
  const code = body.results?.[ip]?.countryCode;
  return typeof code === 'string' && /^[A-Z]{2}$/.test(code) ? { countryCode: code } : null;
}

/** Country codes for many IPs, 200 per request (the API's limit); unknowns are left out. */
export async function geolocateManyViaThreatcrush(ips: string[], fetchImpl: typeof fetch = fetch): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (let i = 0; i < ips.length; i += 200) {
    const chunk = ips.slice(i, i + 200);
    const res = await fetchImpl('https://threatcrush.com/api/geo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: chunk }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`geo lookup failed: HTTP ${res.status}`);
    const body = (await res.json()) as { results?: Record<string, { countryCode?: unknown }> };
    for (const ip of chunk) {
      const code = body.results?.[ip]?.countryCode;
      if (typeof code === 'string' && /^[A-Z]{2}$/.test(code)) out.set(ip, code);
    }
  }
  return out;
}

/** `Accepted <method> for <user> from <ip>` lines from sshd: each user's distinct public IPs. */
export function parseAcceptedLogins(text: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const m of text.matchAll(/Accepted \S+ for (\S+) from (\S+) port/g)) {
    const [, user, ip] = m;
    if (isProtected(ip, DEFAULT_PROTECTED)) continue;
    const ips = out.get(user) ?? new Set<string>();
    ips.add(ip);
    out.set(user, ips);
  }
  return out;
}

export class PrivilegeWatch {
  private timers: NodeJS.Timeout[] = [];
  private readonly io: SnapshotIO;
  private readonly run: NonNullable<PrivilegeWatchOptions['run']>;
  private readonly now: () => Date;
  private warnedUnreadable = false;
  private watchers = new Map<string, FSWatcher>();
  private debounce: NodeJS.Timeout | null = null;
  private readonly onEvent = (event: ThreatEvent) => { void this.checkLogin(event); };

  constructor(private opts: PrivilegeWatchOptions) {
    this.io = opts.io ?? fsIO;
    this.run = opts.run ?? defaultRun;
    this.now = opts.now ?? (() => new Date());
  }

  start(): void {
    if (!this.opts.settings.enabled) {
      this.opts.log('[privileged] disabled by [privileged] enabled = false');
      return;
    }
    this.checkSnapshot();
    this.readSudoLedger();
    if (this.opts.settings.geo) {
      this.opts.bus.on('event', this.onEvent);
      void this.backfillLogins();
    }
    if (this.opts.settings.watchFiles) this.watchKeyDirs();
    const timer = setInterval(() => {
      this.checkSnapshot();
      this.readSudoLedger();
      if (this.opts.settings.watchFiles) this.watchKeyDirs();
    }, this.opts.settings.pollMs);
    timer.unref?.();
    this.timers.push(timer);
  }

  stop(): void {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    for (const w of this.watchers.values()) { try { w.close(); } catch { /* gone */ } }
    this.watchers.clear();
    if (this.debounce) clearTimeout(this.debounce);
    this.opts.bus.off('event', this.onEvent);
  }

  /**
   * inotify on every login account's ~/.ssh (and /root/.ssh): a write there
   * re-checks the snapshot within a second, not at the next minute's poll.
   * Re-run each poll so a directory created later is picked up.
   */
  private watchKeyDirs(): void {
    const dirs = new Set<string>();
    for (const line of (this.io.readFile('/etc/passwd') ?? '').split('\n')) {
      const f = line.split(':');
      if (f.length < 7) continue;
      const uid = Number(f[2]);
      const home = f[5];
      if (!home || home === '/' || (uid !== 0 && /(nologin|\/false)$/.test(f[6].trim()))) continue;
      dirs.add(`${home.replace(/\/$/, '')}/.ssh`);
    }
    for (const dir of dirs) {
      if (this.watchers.has(dir) || !this.io.exists(dir)) continue;
      try {
        const w = watch(dir, { persistent: false }, (_type, name) => {
          if (name && !String(name).startsWith('authorized_keys')) return;
          if (this.debounce) clearTimeout(this.debounce);
          this.debounce = setTimeout(() => { this.debounce = null; this.checkSnapshot(); }, 750);
          this.debounce.unref?.();
        });
        w.on('error', () => { try { w.close(); } catch { /* */ } this.watchers.delete(dir); });
        this.watchers.set(dir, w);
      } catch { /* unreadable or gone: the poll still covers it */ }
    }
  }

  private emit(severity: ThreatEvent['severity'], message: string, details: Record<string, unknown>): void {
    const event: ThreatEvent = { timestamp: this.now(), module: 'privileged-access', category: 'auth', severity, message, details };
    try { insertEvent(event); } catch { /* db optional */ }
    this.opts.bus.publish(event);
  }

  checkSnapshot(): void {
    const next = takeSnapshot(this.io, this.now());
    if (next.unreadable.length && !this.warnedUnreadable) {
      this.warnedUnreadable = true;
      this.opts.log(`[privileged] cannot read ${next.unreadable.join(', ')}; run the daemon as root to watch them`);
    }
    const prev = readJson<PrivilegeSnapshot>(this.opts.snapshotPath);
    if (!prev) {
      const keys = Object.values(next.keys).reduce((n, k) => n + Object.keys(k).length, 0);
      this.opts.log(`[privileged] baseline recorded: uid0 [${next.uid0.join(', ')}], ${Object.values(next.admin_groups).flat().length} admin-group member(s), ${Object.keys(next.sudoers).length} sudoers file(s), ${keys} authorized key(s)`);
    } else {
      for (const raw of diffSnapshots(prev, next)) {
        const change = classifyKeyAddition(raw, this.opts.settings.expectedKeys ?? []);
        if (change.details.rule_id === 'priv-authorized-key-added' || change.details.rule_id === 'priv-authorized-key-selftest') {
          this.opts.log(`[privileged] ${change.severity.toUpperCase()} ${change.message}`);
        }
        this.emit(change.severity, change.message, {
          ...change.details,
          evidence: { at: this.now().toISOString(), module: 'privileged-access', message: change.message.slice(0, 500) },
        });
      }
    }
    try { writeJson(this.opts.snapshotPath, next); } catch (err) {
      this.opts.log(`[privileged] could not save snapshot: ${(err as Error).message}`);
    }
  }

  /**
   * New sudo records since the saved journal cursor. The first run only finds
   * the current end of the journal, so history from before the daemon is not
   * replayed as if it had just happened.
   */
  readSudoLedger(): void {
    const cursor = readJson<{ cursor?: string }>(this.opts.cursorPath)?.cursor;
    // A cursor is a position in the whole journal, so the first run takes the
    // current end without the sudo filter: it exists even on a box where sudo
    // has never run.
    const args = cursor
      ? ['-t', 'sudo', '-o', 'json', '--no-pager', `--after-cursor=${cursor}`]
      : ['-o', 'json', '--no-pager', '-n', '0', '--show-cursor'];
    const out = this.run('journalctl', args);
    if (out === null) return;
    let last = cursor ?? /^-- cursor: (\S+)/m.exec(out)?.[1];
    for (const line of cursor ? out.split('\n') : []) {
      if (!line.trim()) continue;
      let rec: Record<string, unknown>;
      try { rec = JSON.parse(line) as Record<string, unknown>; } catch { continue; }
      if (typeof rec.__CURSOR === 'string') last = rec.__CURSOR;
      const entry = typeof rec.MESSAGE === 'string' ? parseSudoMessage(rec.MESSAGE) : null;
      if (!entry) continue;
      this.emit(
        entry.denied ? 'medium' : 'info',
        entry.denied
          ? `sudo denied: ${entry.user} tried ${entry.command} as ${entry.runas}`
          : `sudo: ${entry.user} ran ${entry.command} as ${entry.runas}`,
        { rule_id: entry.denied ? 'priv-sudo-denied' : 'priv-sudo-command', account: entry.user, runas: entry.runas, command: entry.command, tty: entry.tty, pwd: entry.pwd },
      );
    }
    if (last && last !== cursor) {
      try { writeJson(this.opts.cursorPath, { cursor: last }); } catch { /* retried next poll */ }
    }
  }

  /**
   * Seed the login history from the last 30 days of sshd logins, once, when
   * there is none. Learning only from logins after install meant regular
   * automation from another country (a backup box pulling every four hours)
   * raised a "new country" alert on its first run; on dev2 it did, at once.
   */
  async backfillLogins(): Promise<void> {
    if (existsSync(this.opts.loginsPath)) return;
    const out = this.run('journalctl', ['_COMM=sshd', '_COMM=sshd-session', '--since=-30d', '-o', 'cat', '--no-pager']);
    const byUser = parseAcceptedLogins(out ?? '');
    const ips = [...new Set([...byUser.values()].flatMap((s) => [...s]))];
    let codes = new Map<string, string>();
    if (ips.length > 0) {
      try {
        codes = await (this.opts.geolocateMany ?? geolocateManyViaThreatcrush)(ips);
      } catch (err) {
        this.opts.log(`[privileged] login backfill geolocation failed: ${(err as Error).message}`);
        return; // no history file yet, so the next start tries again
      }
    }
    if (existsSync(this.opts.loginsPath)) return; // a live login got there first
    const at = this.now().toISOString();
    const history: LoginHistory = {};
    for (const [user, userIps] of byUser) {
      for (const ip of userIps) {
        const code = codes.get(ip);
        if (code) (history[user] ??= {})[code] = { first: at, last: at };
      }
    }
    try { writeJson(this.opts.loginsPath, history); } catch { /* next start retries */ }
    const summary = Object.entries(history).map(([u, c]) => `${u}: ${Object.keys(c).join('/')}`).join(', ');
    this.opts.log(`[privileged] login baseline from the last 30 days: ${summary || 'no public SSH logins'}`);
  }

  /** An accepted SSH login from a country new for that user. */
  async checkLogin(event: ThreatEvent): Promise<void> {
    if (event.module !== 'ssh-guard' || !event.source_ip) return;
    const user = /SSH login accepted for (\S+)/.exec(event.message)?.[1];
    if (!user || user === 'unknown' || isProtected(event.source_ip, DEFAULT_PROTECTED)) return;
    let geo: GeoPoint | null = null;
    try {
      geo = await (this.opts.geolocate ?? geolocateViaThreatcrush)(event.source_ip);
    } catch (err) {
      this.opts.log(`[privileged] geolocation failed for ${event.source_ip}: ${(err as Error).message}`);
    }
    const country = geo?.countryCode;
    if (!country || !/^[A-Z]{2}$/.test(country)) return;

    const history = readJson<LoginHistory>(this.opts.loginsPath) ?? {};
    const seen = history[user] ?? {};
    const at = this.now().toISOString();
    const known = Object.keys(seen);
    if (known.length > 0 && !seen[country]) {
      this.emit('high', `SSH login for ${user} from a new country: ${countryName(country)}, ${event.source_ip}; seen before from ${known.join(', ')}`, {
        rule_id: 'priv-login-new-country', account: user, login_ip: event.source_ip, country, known_countries: known,
      });
    }
    seen[country] = { first: seen[country]?.first ?? at, last: at };
    history[user] = seen;
    try { writeJson(this.opts.loginsPath, history); } catch { /* next login retries */ }
  }
}
