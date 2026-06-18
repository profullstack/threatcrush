import { appendFileSync } from 'node:fs';
import type { FirewallAdapter } from './adapters.js';
import type { EventBus } from '../event-bus.js';
import { getModuleState, setModuleState } from '../../core/state.js';
import { PATHS } from '../paths.js';
import type { ThreatEvent } from '../../types/events.js';

interface BlockEntry {
  ip: string;
  reason: string;
  rule_id?: string;
  blocked_at: number;
  expires_at?: number;
  dry_run: boolean;
}

interface RemediationConfig {
  enabled: boolean;
  dry_run: boolean;
  default_ttl_seconds: number;
  min_severity: string;
  allowlist: string[];
}

const DEFAULT_CONFIG: RemediationConfig = {
  enabled: true,
  dry_run: true,
  default_ttl_seconds: 3600,
  min_severity: 'high',
  allowlist: ['127.0.0.1', '::1'],
};

const SEVERITY_RANK: Record<string, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

export class RemediationManager {
  private config: RemediationConfig;
  private blocklist: BlockEntry[] = [];
  private expiryTimer: NodeJS.Timeout | null = null;

  constructor(
    private adapter: FirewallAdapter,
    private bus: EventBus,
    config?: Partial<RemediationConfig>,
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.loadState();
    this.startExpiryWorker();
  }

  async handleDetection(event: ThreatEvent): Promise<void> {
    if (!this.config.enabled) return;

    const eventRank = SEVERITY_RANK[event.severity] ?? 0;
    const minRank = SEVERITY_RANK[this.config.min_severity] ?? 3;
    if (eventRank < minRank) return;

    const ip = event.source_ip;
    if (!ip) return;
    if (this.isAllowlisted(ip)) return;
    if (this.blocklist.some(b => b.ip === ip)) return;

    const ruleRemediation = event.details?.remediation as Record<string, unknown> | undefined;
    const ttl = (ruleRemediation?.ttl_seconds as number) || this.config.default_ttl_seconds;
    const ruleId = event.details?.rule_id as string | undefined;

    await this.blockIp(ip, event.message, ruleId, ttl);
  }

  async blockIp(ip: string, reason: string, ruleId?: string, ttlSeconds?: number): Promise<boolean> {
    if (this.isAllowlisted(ip)) return false;

    const entry: BlockEntry = {
      ip,
      reason,
      rule_id: ruleId,
      blocked_at: Date.now(),
      expires_at: ttlSeconds ? Date.now() + (ttlSeconds * 1000) : undefined,
      dry_run: this.config.dry_run,
    };

    if (!this.config.dry_run) {
      try {
        await this.adapter.block(ip);
      } catch (err) {
        this.logLine(`[firewall] EACCES or error blocking ${ip}: ${(err as Error).message}`);
        this.bus.publish({
          timestamp: new Date(),
          module: 'firewall-rules',
          category: 'system',
          severity: 'medium',
          message: `Failed to block ${ip}: ${(err as Error).message}. Ensure daemon has CAP_NET_ADMIN.`,
        });
        return false;
      }
    }

    this.blocklist.push(entry);
    this.saveState();

    const mode = this.config.dry_run ? '[DRY-RUN] ' : '';
    const expiryMsg = ttlSeconds ? ` (expires in ${ttlSeconds}s)` : ' (permanent)';
    this.logLine(`[firewall] ${mode}Blocked ${ip}: ${reason}${expiryMsg}`);

    this.bus.publish({
      timestamp: new Date(),
      module: 'firewall-rules',
      category: 'system',
      severity: 'info',
      message: `${mode}Blocked ${ip}: ${reason}${expiryMsg}`,
      source_ip: ip,
      details: { action: 'block', rule_id: ruleId, dry_run: this.config.dry_run, ttl_seconds: ttlSeconds },
    });

    return true;
  }

  async unblockIp(ip: string): Promise<boolean> {
    const idx = this.blocklist.findIndex(b => b.ip === ip);
    if (idx < 0) return false;

    const entry = this.blocklist[idx];
    if (!entry.dry_run) {
      try {
        await this.adapter.unblock(ip);
      } catch (err) {
        this.logLine(`[firewall] Error unblocking ${ip}: ${(err as Error).message}`);
        return false;
      }
    }

    this.blocklist.splice(idx, 1);
    this.saveState();

    this.logLine(`[firewall] Unblocked ${ip}`);
    this.bus.publish({
      timestamp: new Date(),
      module: 'firewall-rules',
      category: 'system',
      severity: 'info',
      message: `Unblocked ${ip}`,
      source_ip: ip,
      details: { action: 'unblock' },
    });

    return true;
  }

  isAllowlisted(ip: string): boolean {
    return this.config.allowlist.includes(ip);
  }

  addToAllowlist(ip: string): void {
    if (!this.config.allowlist.includes(ip)) {
      this.config.allowlist.push(ip);
    }
  }

  removeFromAllowlist(ip: string): void {
    this.config.allowlist = this.config.allowlist.filter(a => a !== ip);
  }

  getBlocklist(): BlockEntry[] { return [...this.blocklist]; }
  getAllowlist(): string[] { return [...this.config.allowlist]; }

  stop(): void {
    if (this.expiryTimer) clearInterval(this.expiryTimer);
    this.expiryTimer = null;
  }

  private startExpiryWorker(): void {
    this.expiryTimer = setInterval(() => void this.processExpiries(), 30_000);
  }

  private async processExpiries(): Promise<void> {
    const now = Date.now();
    const expired = this.blocklist.filter(b => b.expires_at && b.expires_at <= now);
    for (const entry of expired) {
      await this.unblockIp(entry.ip);
    }
  }

  private loadState(): void {
    try {
      const saved = getModuleState('firewall-rules', 'blocklist') as BlockEntry[] | undefined;
      if (Array.isArray(saved)) this.blocklist = saved;
    } catch { /* State DB may not be available */ }
  }

  private saveState(): void {
    try { setModuleState('firewall-rules', 'blocklist', this.blocklist); }
    catch { /* State DB may not be available */ }
  }

  private logLine(line: string): void {
    try { appendFileSync(PATHS.logFile, `${new Date().toISOString()} ${line}\n`); }
    catch { /* best-effort */ }
  }
}
