import { appendFileSync } from 'node:fs';
import { isIP } from 'node:net';
import type { FirewallAdapter } from './adapters.js';
import type { EventBus } from '../event-bus.js';
import { getModuleState, setModuleState } from '../../core/state.js';
import { PATHS } from '../paths.js';
import type { ThreatEvent } from '../../types/events.js';
import { banSeconds, formatDuration, pruneStrikes, recordStrike, type Strike } from './backoff.js';
import {
  DEFAULT_PROTECTED,
  currentSshClient,
  defaultGateways,
  establishedSshPeers,
  isProtected,
} from './protected.js';
import { crawlerVerifier } from './crawlers.js';

export interface BlockEntry {
  ip: string;
  reason: string;
  rule_id?: string;
  blocked_at: number;
  expires_at: number;
  dry_run: boolean;
  /** Which offence this ban was — the rung of the Fibonacci ladder. */
  strikes: number;
  /** How the ban came about, so the dashboard can tell them apart. */
  source: 'auto' | 'manual';
}

export interface RemediationConfig {
  enabled: boolean;
  /**
   * Auto-defence is on and enforcing by default. Dry-run used to be the
   * default, which meant a stock install watched an attack happen and wrote a
   * line about the rule it would have added. The protected set below is what
   * makes enforcing safe to ship as the default.
   */
  dry_run: boolean;
  min_severity: string;
  /** Ceiling for the escalating ladder. Nothing is ever permanent (R2). */
  max_ban_seconds: number;
  /** How long an offence is remembered when deciding the next ban length. */
  strike_memory_seconds: number;
  /** Operator additions to the never-block set. */
  allowlist: string[];
  protect_current_ssh_client: boolean;
  /**
   * Never auto-ban a search crawler verified by forward-confirmed reverse DNS
   * (Googlebot, Bingbot). The event is still recorded; only the ban is skipped.
   * A manual `threatcrush block` still works.
   */
  spare_verified_crawlers: boolean;
}

const DEFAULT_CONFIG: RemediationConfig = {
  enabled: true,
  dry_run: false,
  min_severity: 'high',
  max_ban_seconds: 86400,
  strike_memory_seconds: 86400,
  allowlist: [],
  protect_current_ssh_client: true,
  spare_verified_crawlers: true,
};

const SEVERITY_RANK: Record<string, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

/**
 * Turn a backend's own complaint into something that says what to do about it.
 *
 * `Command failed: nft add table inet threatcrush / Operation not permitted` is
 * true and useless: it reads like the operator needs to be root, when the
 * privilege that is missing belongs to the *daemon*. Nobody should have to
 * work that out from a raw nft error at 3am.
 */
/**
 * Does this event describe an authentication that *succeeded*?
 *
 * Such an event may well be worth alerting on — a root login at 3am is worth
 * knowing about — but banning the address it came from punishes the operator
 * who just logged in, and does it while they are connected.
 */
export function isSuccessfulAuth(message: string): boolean {
  return /login accepted|accepted (?:publickey|password|keyboard-interactive)|session opened/i
    .test(message);
}

export function explainBlockFailure(err: Error, backend: string): string {
  const raw = err.message || String(err);
  const denied = /not permitted|EACCES|EPERM|permission denied|must be root/i.test(raw);
  if (!denied) return `${raw} (backend: ${backend})`;

  const who = typeof process.getuid === 'function' && process.getuid() === 0
    ? 'as root'
    : `as uid ${typeof process.getuid === 'function' ? process.getuid() : '?'}`;

  return (
    `threatcrushd is running ${who} and cannot manage ${backend}. ` +
    'A ban is written by the daemon, not by whoever asked for it. Fix it with one command, ' +
    'which asks for root itself: threatcrush install-service'
  );
}

export class RemediationManager {
  private config: RemediationConfig;
  private blocklist: BlockEntry[] = [];
  private strikes: Record<string, Strike> = {};
  private protectedList: string[] = [];
  private expiryTimer: NodeJS.Timeout | null = null;

  constructor(
    private adapter: FirewallAdapter,
    private bus: EventBus,
    config?: Partial<RemediationConfig>,
    private verifyCrawler: (ip: string) => Promise<string | null> = crawlerVerifier(),
  ) {
    // A copy: addToAllowlist pushes into this array, and sharing it with
    // DEFAULT_CONFIG leaked one manager's runtime additions into the next.
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.config.allowlist = [...this.config.allowlist];

    // Built-ins first, then the operator's, then the two we discover at boot.
    // Assembled once, here, because R1 is only true if every write path shares
    // the same list.
    this.protectedList = [...DEFAULT_PROTECTED, ...this.config.allowlist];
    for (const gateway of defaultGateways()) this.protectedList.push(gateway);
    this.refreshSshProtection();

    // A dry-run adapter cannot enforce whatever the config says.
    if (this.adapter.enforces === false) this.config.dry_run = true;

    this.loadState();
    void this.reconcile();
    this.startExpiryWorker();
  }

  /** Every address that can never be blocked, built-ins included. */
  getProtected(): string[] { return [...this.protectedList]; }

  /**
   * Add whoever is connected over SSH to the never-block set.
   *
   * Re-run on every sweep, not just at startup: a session opened after the
   * daemon started is just as much a lockout risk as one that predates it, and
   * an operator who ssh's in to investigate an incident must not be banned
   * while doing so.
   */
  private refreshSshProtection(): void {
    if (!this.config.protect_current_ssh_client) return;
    const candidates = [currentSshClient(), ...establishedSshPeers()];
    for (const ip of candidates) {
      if (ip && !this.protectedList.includes(ip)) this.protectedList.push(ip);
    }
  }

  isAllowlisted(ip: string): boolean {
    return isProtected(ip, this.protectedList);
  }

  async handleDetection(event: ThreatEvent): Promise<void> {
    if (!this.config.enabled) return;

    const eventRank = SEVERITY_RANK[event.severity] ?? 0;
    const minRank = SEVERITY_RANK[this.config.min_severity] ?? 3;
    if (eventRank < minRank) return;

    // A successful authentication is never grounds for a ban, whatever
    // severity a rule gives it. `ssh-success-after-failures` is `critical`
    // with threshold 1 and matches "SSH login accepted", so with severity
    // alone deciding, **every successful ssh login banned the person who just
    // logged in** — seconds after they did. It never fired before the RFC3339
    // parser fix taught ssh-guard to read auth.log at all, and enforcing by
    // default turned it into a lockout.
    if (isSuccessfulAuth(event.message)) return;

    // A rule-engine detection bans only when the rule asked for it. Banning on
    // severity alone means any rule author who writes `critical` writes a
    // firewall rule by accident — three of the twelve shipped rules declare no
    // remediation at all and were banning anyway.
    if (event.details?.rule_id) {
      const remediation = event.details?.remediation as { action?: string } | undefined;
      if (remediation?.action !== 'block') return;
    }

    const ip = event.source_ip;
    if (!ip || isIP(ip) === 0) return;
    if (this.isAllowlisted(ip)) return;
    // Already contained. The ladder climbs on the *next* offence after this
    // ban expires, not on every packet that arrives while it is in force.
    if (this.blocklist.some((b) => b.ip === ip)) return;

    if (this.config.spare_verified_crawlers) {
      const crawler = await this.verifyCrawler(ip);
      if (crawler) {
        this.logLine(`[remediation] not banning ${ip}: verified crawler ${crawler} (${event.message})`);
        return;
      }
    }

    const ruleId = event.details?.rule_id as string | undefined;
    await this.ban(ip, event.message, { ruleId, source: 'auto' });
  }

  /**
   * Ban `ip`. With no explicit TTL the length comes from the Fibonacci ladder:
   * 1m, 2m, 3m, 5m, 8m, 13m … for the 1st, 2nd, 3rd offence and so on, clamped
   * to `max_ban_seconds`.
   */
  async ban(
    ip: string,
    reason: string,
    opts: {
      ruleId?: string;
      ttlSeconds?: number;
      source?: 'auto' | 'manual';
      /** `cloud` when the dashboard asked for it; the cloud already has that row. */
      origin?: 'cloud';
    } = {},
  ): Promise<{ ok: boolean; entry?: BlockEntry; error?: string }> {
    if (isIP(ip) === 0) return { ok: false, error: `not an IP address: ${ip}` };
    if (this.isAllowlisted(ip)) {
      return { ok: false, error: `${ip} is protected and can never be blocked` };
    }

    const now = Date.now();
    const existing = this.blocklist.find((b) => b.ip === ip);
    if (existing && !opts.ttlSeconds) {
      return { ok: false, error: `${ip} is already banned` };
    }

    // Enforce first, then record. The strike ladder must climb only for bans
    // we actually applied: recording the strike before the block let a failed
    // enforcement — a non-root daemon that cannot write nftables, or any adapter
    // error — inflate the ladder while dropping no packets, so the counter
    // claimed a protection that did not exist. If the block fails we change
    // nothing: no strike, no ledger entry, no kernel rule.
    if (!this.config.dry_run) {
      try {
        await this.adapter.block(ip);
      } catch (err) {
        const message = explainBlockFailure(err as Error, this.adapter.name);
        this.logLine(`[firewall] error blocking ${ip}: ${message}`);
        this.bus.publish({
          timestamp: new Date(),
          module: 'firewall-rules',
          category: 'system',
          severity: 'medium',
          message: `Failed to block ${ip}: ${message}`,
          source_ip: ip,
          details: {
            action: 'block',
            failed: true,
            error: message,
            reason,
            rule_id: opts.ruleId,
            origin: opts.origin,
          },
        });
        return { ok: false, error: message };
      }
    }

    const strike = recordStrike(this.strikes, ip, now, this.config.strike_memory_seconds);
    const ttl = opts.ttlSeconds ?? banSeconds(strike, this.config.max_ban_seconds);

    const entry: BlockEntry = {
      ip,
      reason,
      rule_id: opts.ruleId,
      blocked_at: now,
      expires_at: now + ttl * 1000,
      dry_run: this.config.dry_run,
      strikes: strike,
      source: opts.source ?? 'manual',
    };

    // Re-banning with an explicit TTL replaces the entry rather than stacking.
    this.blocklist = this.blocklist.filter((b) => b.ip !== ip);
    this.blocklist.push(entry);
    this.saveState();

    const mode = this.config.dry_run ? '[DRY-RUN] ' : '';
    const label = `${mode}Banned ${ip} for ${formatDuration(ttl)} (offence #${strike}): ${reason}`;
    this.logLine(`[firewall] ${label}`);
    this.bus.publish({
      timestamp: new Date(),
      module: 'firewall-rules',
      category: 'system',
      severity: 'info',
      message: label,
      source_ip: ip,
      details: {
        action: 'block',
        rule_id: opts.ruleId,
        reason,
        origin: opts.origin,
        dry_run: this.config.dry_run,
        ttl_seconds: ttl,
        strikes: strike,
        source: entry.source,
        backend: this.adapter.name,
      },
    });

    return { ok: true, entry };
  }

  /**
   * Lift a ban. `forget` also drops the strike ledger entry — an operator
   * unbanning by hand is overruling the detection, so the next offence should
   * start at one minute again rather than resuming the ladder.
   */
  async unban(
    ip: string,
    opts: { forget?: boolean; reason?: string; origin?: 'cloud' } = {},
  ): Promise<{ ok: boolean; error?: string }> {
    const idx = this.blocklist.findIndex((b) => b.ip === ip);
    const entry = idx >= 0 ? this.blocklist[idx] : null;

    if (!entry?.dry_run) {
      try {
        await this.adapter.unblock(ip);
      } catch (err) {
        const message = (err as Error).message;
        this.logLine(`[firewall] error unblocking ${ip}: ${message}`);
        return { ok: false, error: message };
      }
    }

    if (idx >= 0) this.blocklist.splice(idx, 1);
    if (opts.forget) delete this.strikes[ip];
    this.saveState();

    if (idx < 0) return { ok: false, error: `${ip} is not banned` };

    this.logLine(`[firewall] Unbanned ${ip}${opts.forget ? ' (strikes cleared)' : ''}`);
    this.bus.publish({
      timestamp: new Date(),
      module: 'firewall-rules',
      category: 'system',
      severity: 'info',
      message: `Unbanned ${ip}`,
      source_ip: ip,
      details: {
        action: 'unblock',
        forget: opts.forget === true,
        reason: opts.reason,
        origin: opts.origin,
        dry_run: entry?.dry_run === true,
      },
    });
    return { ok: true };
  }

  /** Lifts every ban this module placed. The "undo it all" of R12. */
  async flush(): Promise<number> {
    const entries = [...this.blocklist];
    for (const entry of entries) await this.unban(entry.ip);
    return entries.length;
  }

  getBlocklist(): BlockEntry[] {
    return [...this.blocklist].sort((a, b) => b.blocked_at - a.blocked_at);
  }

  getAllowlist(): string[] { return [...this.protectedList]; }

  /** Offence count per address, so the dashboard can show why a ban is long. */
  getStrikes(): Record<string, Strike> { return { ...this.strikes }; }

  status(): {
    enabled: boolean;
    dry_run: boolean;
    backend: string;
    min_severity: string;
    banned: number;
    max_ban_seconds: number;
    warning?: string;
  } {
    return {
      enabled: this.config.enabled,
      dry_run: this.config.dry_run,
      backend: this.adapter.name,
      min_severity: this.config.min_severity,
      banned: this.blocklist.length,
      max_ban_seconds: this.config.max_ban_seconds,
      warning: this.privilegeWarning(),
    };
  }

  /**
   * Set when the daemon intends to enforce but cannot. `nft --version` succeeds
   * for anybody, so backend detection alone will happily pick nftables inside
   * an unprivileged daemon — and then every ban fails at the moment it matters.
   * Saying so up front beats a dashboard that looks armed and is not.
   */
  private privilegeWarning(): string | undefined {
    if (!this.config.enabled || this.config.dry_run) return undefined;
    if (this.adapter.enforces === false) return undefined;
    const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
    if (uid === 0) return undefined;
    return `daemon runs as uid ${uid} and cannot write ${this.adapter.name} rules — bans will fail`;
  }

  addToAllowlist(ip: string): void {
    if (!this.protectedList.includes(ip)) this.protectedList.push(ip);
    if (!this.config.allowlist.includes(ip)) this.config.allowlist.push(ip);
  }

  removeFromAllowlist(ip: string): void {
    // Built-ins are not removable: that is the point of R1.
    if (DEFAULT_PROTECTED.includes(ip)) return;
    this.protectedList = this.protectedList.filter((a) => a !== ip);
    this.config.allowlist = this.config.allowlist.filter((a) => a !== ip);
  }

  stop(): void {
    if (this.expiryTimer) clearInterval(this.expiryTimer);
    this.expiryTimer = null;
  }

  /**
   * R5: bans survive a restart, their TTLs do not. Anything that expired while
   * the daemon was down is dropped, and anything still live is re-applied —
   * the firewall may have been flushed by a reboot underneath us.
   */
  private async reconcile(): Promise<void> {
    const now = Date.now();
    const live = this.blocklist.filter((b) => b.expires_at > now);
    const stale = this.blocklist.filter((b) => b.expires_at <= now);

    for (const entry of stale) {
      if (!entry.dry_run) {
        try { await this.adapter.unblock(entry.ip); } catch { /* already gone */ }
      }
    }

    this.blocklist = live;
    this.saveState();

    let applied: string[] | null = null;
    try { applied = await this.adapter.listBlocked(); } catch { /* backend may not list */ }

    // Drop anything the backend is enforcing that we have no record of.
    //
    // Reconcile used to only *add*, which meant a rule could outlive every
    // trace of its reason: if the state DB failed to open, or was reset, or the
    // daemon died between writing a rule and saving, the address stayed blocked
    // with nothing left to explain or expire it. Observed on dev2 — the
    // blocklist read "Nothing is banned" while three hosts were still being
    // dropped. PRD 0010 R3 exists for exactly this: what we added, we can
    // remove, and only what we can account for stays.
    //
    // This runs even in dry-run, because a dry-run daemon asserting it changes
    // nothing must also not leave yesterday's enforcement standing.
    if (applied) {
      const known = new Set(live.filter((b) => !b.dry_run).map((b) => b.ip));
      for (const ip of applied) {
        if (known.has(ip)) continue;
        this.logLine(`[firewall] reconcile: dropping stale rule for ${ip} (no record of why)`);
        try { await this.adapter.unblock(ip); } catch { /* already gone */ }
      }
    }

    if (this.config.dry_run) return;
    for (const entry of live) {
      if (applied?.includes(entry.ip)) continue;
      try { await this.adapter.block(entry.ip); } catch { /* reported on next ban */ }
    }
  }

  private startExpiryWorker(): void {
    // 10s rather than 30s: the bottom of the ladder is a one-minute ban, and a
    // 30s sweep turns that into anywhere between one and one and a half.
    this.expiryTimer = setInterval(() => void this.processExpiries(), 10_000);
    this.expiryTimer.unref?.();
  }

  private async processExpiries(): Promise<void> {
    const now = Date.now();
    this.refreshSshProtection();
    for (const entry of this.blocklist.filter((b) => b.expires_at <= now)) {
      await this.unban(entry.ip, { reason: 'ban expired' });
    }
    const pruned = pruneStrikes(this.strikes, now, this.config.strike_memory_seconds);
    if (Object.keys(pruned).length !== Object.keys(this.strikes).length) {
      this.strikes = pruned;
      this.saveState();
    }
  }

  private loadState(): void {
    try {
      const saved = getModuleState('firewall-rules', 'blocklist') as BlockEntry[] | undefined;
      if (Array.isArray(saved)) {
        // Entries written by older builds have no expiry or strike count.
        this.blocklist = saved.map((entry) => ({
          ...entry,
          strikes: entry.strikes ?? 1,
          source: entry.source ?? 'auto',
          expires_at: entry.expires_at ?? entry.blocked_at + this.config.max_ban_seconds * 1000,
        }));
      }
    } catch { /* State DB may not be available */ }

    try {
      const saved = getModuleState('firewall-rules', 'strikes') as Record<string, Strike> | undefined;
      if (saved && typeof saved === 'object') this.strikes = saved;
    } catch { /* State DB may not be available */ }
  }

  private saveState(): void {
    try { setModuleState('firewall-rules', 'blocklist', this.blocklist); }
    catch { /* State DB may not be available */ }
    try { setModuleState('firewall-rules', 'strikes', this.strikes); }
    catch { /* State DB may not be available */ }
  }

  private logLine(line: string): void {
    try { appendFileSync(PATHS.logFile, `${new Date().toISOString()} ${line}\n`); }
    catch { /* best-effort */ }
  }
}
