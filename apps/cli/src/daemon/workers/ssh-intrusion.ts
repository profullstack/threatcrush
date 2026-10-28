import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { ThreatEvent } from '../../types/events.js';
import type { SshdLine } from '../event-bus.js';
import { insertEvent } from '../../core/state.js';
import { DEFAULT_PROTECTED, isAutomationKeyComment, isProtected } from '../firewall/protected.js';
import type { RuleRemediation } from '../firewall/remediation.js';
import { TorExitList } from '../../core/tor-exits.js';
import { AsnLookup, classifyAsn, describeNetwork, type AsnInfo, type NetworkKind } from '../../core/asn.js';
import { takeSnapshot, type SnapshotIO } from '../../core/privileges/index.js';

/**
 * SSH intrusion signals that a stolen key gets past (the 2026-10-26/27 dev2
 * intrusion: logins as anthony and root with a real key, from Tor exits,
 * OVH, an NL host and Google Cloud, then a planted key used hundreds of times):
 *
 *   - `ssh-from-tor`: ANY sshd line naming a Tor exit (a connection attempt,
 *     a failed or an accepted login) is critical, and with `[remediation]
 *     block_tor_ssh` (default on) the exit is banned at once for `max_ban`,
 *     even in dry_run and even though it logged in. Our own addresses (the
 *     pinned/configured allowlist and the dashboard's Known IPs) are never
 *     banned.
 *   - `ssh-key-new-ip`: a key logging in from an address that key has never
 *     used (high), with the network classified (Tor / CI / hosting / VPN /
 *     ISP). A CI deploy key from a CI network is expected (info).
 *   - `ssh-human-key-hosting-login`: a person's key (not automation, by its
 *     authorized_keys comment) logging in from a hosting, cloud or VPN
 *     network (high). People log in from home and phone lines.
 *
 * None of the key-login events carry `source_ip`: a login with a real key
 * is not something to ban on a network hunch. Only the Tor rule bans.
 */

export interface SshIntrusionManager {
  readonly blockTorSsh: boolean;
  isFleetAddress(ip: string): boolean;
  setTorExitCheck(check: (ip: string) => boolean): void;
}

export interface SshIntrusionOptions {
  bus: {
    publish(event: ThreatEvent): void;
    on(name: 'event', fn: (event: ThreatEvent) => void): unknown;
    on(name: 'sshd', fn: (line: SshdLine) => void): unknown;
    off(name: 'event', fn: (event: ThreatEvent) => void): unknown;
    off(name: 'sshd', fn: (line: SshdLine) => void): unknown;
  };
  manager: SshIntrusionManager;
  tor: TorExitList;
  /** Per-key address history: /var/lib/threatcrush/key-logins.json. */
  historyPath: string;
  log: (line: string) => void;
  keyLoginWatch?: boolean;
  asn?: Pick<AsnLookup, 'lookup'>;
  io?: SnapshotIO;
  /** journalctl runner for the first-run baseline: stdout or null. */
  run?: (cmd: string, args: string[]) => string | null;
  now?: () => number;
}

interface KeyHistory {
  [fingerprint: string]: { [ip: string]: { first: string; last: string; count: number } };
}

const TOR_REALERT_MS = 10 * 60_000;
const HOSTING_REALERT_MS = 24 * 3_600_000;

export const TOR_REMEDIATION: RuleRemediation = {
  action: 'block',
  description: 'Ban the Tor exit at once, for max_ban, even in dry_run and even after a successful login',
  enforce_in_dry_run: true,
  ban_on_login: true,
  override_operator_protection: true,
  max_ban: true,
};

/** `journalctl -o short-unix` "Accepted publickey" lines → fingerprint → ip → newest time. */
export function parseKeyLoginsByFingerprint(text: string): Map<string, Map<string, number>> {
  const out = new Map<string, Map<string, number>>();
  for (const line of text.split('\n')) {
    const m = /^(\d+(?:\.\d+)?)\s.*Accepted publickey for \S+ from (\S+) port \d+ \S+?:\s+\S+\s+(SHA256:[A-Za-z0-9+/=]+)/.exec(line);
    if (!m) continue;
    const at = Math.round(Number(m[1]) * 1000);
    const ips = out.get(m[3]) ?? new Map<string, number>();
    if (at > (ips.get(m[2]) ?? 0)) ips.set(m[2], at);
    out.set(m[3], ips);
  }
  return out;
}

function readJson<T>(path: string): T | null {
  try { return JSON.parse(readFileSync(path, 'utf-8')) as T; } catch { return null; }
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(`${path}.tmp`, JSON.stringify(value));
  renameSync(`${path}.tmp`, path);
}

const fsIO: SnapshotIO = {
  readFile: (p) => { try { return readFileSync(p, 'utf-8'); } catch { return null; } },
  readDir: (p) => { try { return readdirSync(p); } catch { return null; } },
  exists: (p) => existsSync(p),
};

function defaultRun(cmd: string, args: string[]): string | null {
  const res = spawnSync(cmd, args, { encoding: 'utf-8', timeout: 60_000, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  return res.status === 0 ? res.stdout : null;
}

export class SshIntrusionWatch {
  private readonly now: () => number;
  private readonly asn: Pick<AsnLookup, 'lookup'>;
  private readonly io: SnapshotIO;
  private readonly run: NonNullable<SshIntrusionOptions['run']>;
  private torAlerted = new Map<string, number>();
  private hostingAlerted = new Map<string, number>();
  private history: KeyHistory = {};
  private keyComments: { at: number; byFp: Map<string, { user: string; comment: string }> } = { at: 0, byFp: new Map() };
  private baselineReady = false;
  private readonly onLine = (line: SshdLine) => { this.checkTorLine(line); };
  private readonly onEvent = (event: ThreatEvent) => { void this.checkKeyLogin(event); };

  constructor(private opts: SshIntrusionOptions) {
    this.now = opts.now ?? Date.now;
    this.asn = opts.asn ?? new AsnLookup();
    this.io = opts.io ?? fsIO;
    this.run = opts.run ?? defaultRun;
  }

  start(): void {
    this.opts.tor.start();
    this.opts.manager.setTorExitCheck((ip) => this.opts.tor.has(ip));
    this.opts.bus.on('sshd', this.onLine);
    if (this.opts.keyLoginWatch !== false) {
      this.opts.bus.on('event', this.onEvent);
      this.loadHistory();
    }
    this.opts.log(`[ssh-intrusion] Tor SSH ban ${this.opts.manager.blockTorSsh ? 'ON (enforced even in dry_run)' : 'OFF (alert only)'}; key-login watch ${this.opts.keyLoginWatch === false ? 'off' : 'on'}`);
  }

  stop(): void {
    this.opts.tor.stop();
    this.opts.bus.off('sshd', this.onLine);
    this.opts.bus.off('event', this.onEvent);
  }

  private emit(event: ThreatEvent): void {
    try { insertEvent(event); } catch { /* db optional */ }
    this.opts.bus.publish(event);
  }

  /** One sshd line: a Tor exit anywhere in it is an intrusion attempt. */
  checkTorLine(line: SshdLine): boolean {
    const ip = line.ip;
    if (!this.opts.tor.has(ip)) return false;
    if (isProtected(ip, DEFAULT_PROTECTED) || this.opts.manager.isFleetAddress(ip)) return false;
    const at = this.now();
    const last = this.torAlerted.get(ip) ?? 0;
    const accepted = /Accepted \S+ for /.test(line.message);
    // A successful login always re-alerts: it is the one that matters.
    if (!accepted && at - last < TOR_REALERT_MS) return false;
    this.torAlerted.set(ip, at);
    if (this.torAlerted.size > 10_000) this.torAlerted.clear();

    const ban = this.opts.manager.blockTorSsh;
    const user = /for (?:invalid user )?(\S+) from/.exec(line.message)?.[1];
    const what = accepted ? `LOGGED IN${user ? ` as ${user}` : ''}` : 'connection attempt';
    this.emit({
      timestamp: line.timestamp,
      module: 'ssh-intrusion',
      category: 'auth',
      severity: accepted || ban ? 'critical' : 'high',
      message: `SSH from Tor exit ${ip} (${what})${ban ? ': banned' : ''}`,
      source_ip: ip,
      details: {
        rule_id: 'ssh-from-tor',
        description: 'Nobody we operate for uses SSH through Tor. A Tor login means a stolen key or password.',
        tor_exit: true,
        accepted,
        ...(user ? { ssh_user: user } : {}),
        ...(ban ? { remediation: TOR_REMEDIATION } : {}),
        evidence: { at: line.timestamp.toISOString(), module: 'ssh-guard', message: line.raw.slice(0, 500) },
      },
    });
    return true;
  }

  private loadHistory(): void {
    const saved = readJson<KeyHistory>(this.opts.historyPath);
    if (saved) {
      this.history = saved;
      this.baselineReady = true;
      return;
    }
    // First run: learn the last 30 days so every existing habit does not alert.
    // Tor exits are not learned: the dev2 journal holds the intruder's own logins.
    const out = this.run('journalctl', ['_COMM=sshd', '_COMM=sshd-session', '--since=-30d', '-o', 'short-unix', '--no-pager', '--grep', 'Accepted publickey']);
    const iso = (ms: number) => new Date(ms).toISOString();
    let pairs = 0;
    for (const [fp, ips] of parseKeyLoginsByFingerprint(out ?? '')) {
      for (const [ip, at] of ips) {
        if (this.opts.tor.has(ip)) continue;
        (this.history[fp] ??= {})[ip] = { first: iso(at), last: iso(at), count: 1 };
        pairs++;
      }
    }
    this.save();
    this.baselineReady = true;
    this.opts.log(`[ssh-intrusion] key-login baseline from the last 30 days: ${Object.keys(this.history).length} key(s), ${pairs} key/address pair(s)`);
  }

  private save(): void {
    try { writeJson(this.opts.historyPath, this.history); } catch (err) {
      this.opts.log(`[ssh-intrusion] could not save key-login history: ${(err as Error).message}`);
    }
  }

  /** Which account a key is authorized for, and its comment (cached 5 minutes). */
  private keyInfo(fp: string): { user: string; comment: string } | null {
    if (this.now() - this.keyComments.at > 300_000) {
      const snap = takeSnapshot(this.io);
      const byFp = new Map<string, { user: string; comment: string }>();
      for (const [user, keys] of Object.entries(snap.keys)) {
        for (const [f, k] of Object.entries(keys)) if (!byFp.has(f)) byFp.set(f, { user, comment: k.comment });
      }
      this.keyComments = { at: this.now(), byFp };
    }
    return this.keyComments.byFp.get(fp) ?? null;
  }

  async checkKeyLogin(event: ThreatEvent): Promise<ThreatEvent | null> {
    if (event.module !== 'ssh-guard' || !this.baselineReady) return null;
    const fp = event.details?.fingerprint;
    const ip = event.source_ip;
    if (typeof fp !== 'string' || !ip || isProtected(ip, DEFAULT_PROTECTED)) return null;

    const seen = this.history[fp] ?? {};
    const isNew = !seen[ip];
    const nowIso = new Date(this.now()).toISOString();
    seen[ip] = { first: seen[ip]?.first ?? nowIso, last: nowIso, count: (seen[ip]?.count ?? 0) + 1 };
    this.history[fp] = seen;
    this.save();

    const tor = this.opts.tor.has(ip);
    const fleet = this.opts.manager.isFleetAddress(ip);
    if (fleet) return null;

    const key = this.keyInfo(fp);
    const automation = key ? isAutomationKeyComment(key.comment) : false;
    let info: AsnInfo | null = null;
    try { info = await this.asn.lookup(ip); } catch { info = null; }
    const kind: NetworkKind = tor ? 'tor' : classifyAsn(info);
    const network = describeNetwork(info, kind);
    const user = typeof event.details?.ssh_user === 'string' ? event.details.ssh_user : (/accepted for (\S+)/i.exec(event.message)?.[1] ?? 'unknown');
    const keyLabel = `${fp}${key?.comment ? ` (${key.comment})` : ''}`;
    const known = Object.keys(seen).filter((a) => a !== ip).length;

    const anonymous = kind === 'hosting' || kind === 'vpn' || kind === 'tor';
    const hostingHit = !automation && anonymous;
    const pairKey = `${fp}|${ip}`;
    const hostingDue = hostingHit && this.now() - (this.hostingAlerted.get(pairKey) ?? 0) >= HOSTING_REALERT_MS;
    if (!isNew && !hostingDue) return null;
    // The Tor rule already raised this, at critical.
    if (tor && this.opts.manager.blockTorSsh) return null;

    let ruleId: string;
    let severity: ThreatEvent['severity'];
    let message: string;
    if (hostingHit) {
      this.hostingAlerted.set(pairKey, this.now());
      ruleId = 'ssh-human-key-hosting-login';
      severity = 'high';
      message = `SSH login as ${user} with a person's key from a ${kind === 'vpn' ? 'VPN/anonymizer' : kind === 'tor' ? 'Tor' : 'hosting/cloud'} network: ${ip}, ${network}${isNew ? ', first time for this key' : ''}`;
    } else if (automation && kind === 'ci') {
      ruleId = 'ssh-key-new-ip';
      severity = 'info';
      message = `SSH deploy key logged in as ${user} from a new CI address ${ip} (${network}), expected`;
    } else {
      ruleId = 'ssh-key-new-ip';
      severity = 'high';
      message = `SSH key logged in as ${user} from an address it never used: ${ip}, ${network}${known ? `; ${known} address(es) known for this key` : ''}`;
    }

    const out: ThreatEvent = {
      timestamp: event.timestamp,
      module: 'ssh-intrusion',
      category: 'auth',
      severity,
      message,
      details: {
        rule_id: ruleId,
        account: user,
        login_ip: ip,
        fingerprint: fp,
        key_comment: key?.comment ?? null,
        key_kind: automation ? 'automation' : 'person',
        network_kind: kind,
        ...(info ? { asn: info.asn, as_name: info.name, as_country: info.country } : {}),
        first_time_for_key: isNew,
        known_addresses_for_key: known,
        evidence: { at: event.timestamp.toISOString(), module: 'ssh-guard', message: `Accepted publickey for ${user} from ${ip} ${fp}` },
      },
    };
    this.emit(out);
    return out;
  }
}
