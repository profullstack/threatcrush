import { appendFileSync } from 'node:fs';
import { isIP } from 'node:net';
import type { FirewallAdapter } from './adapters.js';
import type { EventBus } from '../event-bus.js';
import { getModuleState, setModuleState } from '../../core/state.js';
import { PATHS } from '../paths.js';
import type { ThreatEvent } from '../../types/events.js';
import { banSeconds, formatDuration, pruneStrikes, recordStrike, type Strike } from './backoff.js';
import { DEFAULT_PROTECTED, currentSshClient, defaultGateways, isProtected } from './protected.js';

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
}

const DEFAULT_CONFIG: RemediationConfig = {
  enabled: true,
  dry_run: false,
  min_severity: 'high',
  max_ban_seconds: 86400,
  strike_memory_seconds: 86400,
  allowlist: [],
  protect_current_ssh_client: true,
};

const SEVERITY_RANK: Record<string, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

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
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Built-ins first, then the operator's, then the two we discover at boot.
    // Assembled once, here, because R1 is only true if every write path shares
    // the same list.
    this.protectedList = [...DEFAULT_PROTECTED, ...this.config.allowlist];
    if (this.config.protect_current_ssh_client) {
      const ssh = currentSshClient();
      if (ssh) this.protectedList.push(ssh);
    }
    for (const gateway of defaultGateways()) this.protectedList.push(gateway);

    // A dry-run adapter cannot enforce whatever the config says.
    if (this.adapter.enforces === false) this.config.dry_run = true;

    this.loadState();
    void this.reconcile();
    this.startExpiryWorker();
  }

  /** Every address that can never be blocked, built-ins included. */
  getProtected(): string[] { return [...this.protectedList]; }

  isAllowlisted(ip: string): boolean {
    return isProtected(ip, this.protectedList);
  }

  async handleDetection(event: ThreatEvent): Promise<void> {
    if (!this.config.enabled) return;

    const eventRank = SEVERITY_RANK[event.severity] ?? 0;
    const minRank = SEVERITY_RANK[this.config.min_severity] ?? 3;
    if (eventRank < minRank) return;

    const ip = event.source_ip;
    if (!ip || isIP(ip) === 0) return;
    if (this.isAllowlisted(ip)) return;
    // Already contained. The ladder climbs on the *next* offence after this
    // ban expires, not on every packet that arrives while it is in force.
    if (this.blocklist.some((b) => b.ip === ip)) return;

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
    opts: { ruleId?: string; ttlSeconds?: number; source?: 'auto' | 'manual' } = {},
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

    if (!this.config.dry_run) {
      try {
        await this.adapter.block(ip);
      } catch (err) {
        const message = (err as Error).message;
        this.logLine(`[firewall] error blocking ${ip}: ${message}`);
        this.bus.publish({
          timestamp: new Date(),
          module: 'firewall-rules',
          category: 'system',
          severity: 'medium',
          message: `Failed to block ${ip}: ${message}. Ensure the daemon can manage ${this.adapter.name}.`,
          source_ip: ip,
        });
        return { ok: false, error: message };
      }
    }

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
  async unban(ip: string, opts: { forget?: boolean } = {}): Promise<{ ok: boolean; error?: string }> {
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
      details: { action: 'unblock', forget: opts.forget === true },
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
  } {
    return {
      enabled: this.config.enabled,
      dry_run: this.config.dry_run,
      backend: this.adapter.name,
      min_severity: this.config.min_severity,
      banned: this.blocklist.length,
      max_ban_seconds: this.config.max_ban_seconds,
    };
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

    if (this.config.dry_run) return;
    let applied: string[] = [];
    try { applied = await this.adapter.listBlocked(); } catch { /* backend may not list */ }
    for (const entry of live) {
      if (applied.includes(entry.ip)) continue;
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
    for (const entry of this.blocklist.filter((b) => b.expires_at <= now)) {
      await this.unban(entry.ip);
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
