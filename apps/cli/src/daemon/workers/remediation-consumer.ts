import { isIP } from 'node:net';
import { cloudFetch } from '../../core/cli-config.js';
import { currentLink, type CloudLink } from '../../core/cloud-events.js';
import type { RemediationManager } from '../firewall/remediation.js';
import { DEFAULT_PROTECTED } from '../firewall/protected.js';
import { isAddressOrCidr } from './allowlist-sync.js';

export interface ClaimedAction {
  id: string;
  action_type: string;
  target_value: string;
  expires_at: string | null;
  metadata?: Record<string, unknown> | null;
  created_at?: string;
}

export interface ActionResult {
  status: 'executed' | 'failed';
  error?: string;
  dry_run?: boolean;
  executed_at: string;
}

export type ConsumerManager = Pick<
  RemediationManager,
  'ban' | 'unban' | 'status' | 'getBlocklist' | 'addToAllowlist' | 'removeFromAllowlist'
>;

/** Results the dashboard has not acknowledged yet are retried, up to this many. */
const MAX_UNSENT = 200;

/**
 * Carries out what an operator queued on the dashboard: claims pending
 * actions for this server, runs them through the same `RemediationManager`
 * that auto-defence uses — so the protected set, the org allowlist and dry-run
 * all apply exactly as they do locally — and reports each result back.
 */
export class RemediationConsumer {
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private lastError = '';
  private unsent = new Map<string, { orgId: string; result: ActionResult }>();

  constructor(
    private manager: ConsumerManager,
    private opts: { log: (line: string) => void; pollMs?: number },
  ) {}

  start(): void {
    this.timer = setInterval(() => void this.tick(), this.opts.pollMs ?? 15_000);
    this.timer.unref?.();
    void this.tick();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick(): Promise<void> {
    if (this.running) return;
    const link = currentLink();
    if (!link) return;
    this.running = true;
    try {
      for (const [id, { orgId, result }] of [...this.unsent]) {
        if (await this.report(orgId, id, result)) this.unsent.delete(id);
      }
      for (const action of await this.claim(link)) {
        const result = await this.execute(action);
        this.opts.log(
          `[cloud] dashboard ${action.action_type} ${action.target_value} → ${result.status}` +
          `${result.dry_run ? ' (dry-run)' : ''}${result.error ? `: ${result.error}` : ''}`,
        );
        if (!(await this.report(link.orgId, action.id, result)) && this.unsent.size < MAX_UNSENT) {
          this.unsent.set(action.id, { orgId: link.orgId, result });
        }
      }
    } catch (err) {
      // The next tick retries; a claimed action left `executing` returns to
      // `pending` on the server after five minutes.
      // One line per outage, not one per poll.
      const message = (err as Error).message;
      if (message !== this.lastError) this.opts.log(`[cloud] remediation poll failed: ${message}`);
      this.lastError = message;
    } finally {
      this.running = false;
    }
  }

  private async claim(link: CloudLink): Promise<ClaimedAction[]> {
    const res = await cloudFetch(
      `/api/orgs/${link.orgId}/servers/${link.serverId}/remediations/claim`,
      { method: 'POST', body: '{}' },
    );
    this.lastError = '';
    if (!res.ok) return [];
    const data = await res.json().catch(() => ({})) as { actions?: ClaimedAction[] };
    return Array.isArray(data.actions) ? data.actions : [];
  }

  /** True once the dashboard has the result, or can never take it (409/404). */
  private async report(orgId: string, id: string, result: ActionResult): Promise<boolean> {
    try {
      const res = await cloudFetch(`/api/orgs/${orgId}/remediations/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(result),
      });
      if (res.ok) return true;
      if (res.status === 409 || res.status === 404 || res.status === 400) {
        this.opts.log(`[cloud] dashboard would not take the result for ${id} (${res.status})`);
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  async execute(action: ClaimedAction): Promise<ActionResult> {
    const executed_at = new Date().toISOString();
    const failed = (error: string): ActionResult => ({ status: 'failed', error, executed_at });
    const target = String(action.target_value ?? '').trim();
    const meta = action.metadata ?? {};

    try {
      switch (action.action_type) {
        case 'block': {
          if (isIP(target) === 0) return failed(`not an IP address: ${target}`);
          let ttlSeconds = this.manager.status().max_ban_seconds;
          if (action.expires_at) {
            const until = Date.parse(action.expires_at);
            if (Number.isNaN(until)) return failed(`unreadable expires_at: ${action.expires_at}`);
            ttlSeconds = Math.ceil((until - Date.now()) / 1000);
            if (ttlSeconds <= 0) return failed('expired before this server picked it up');
          }
          const reason = typeof meta.reason === 'string' && meta.reason
            ? meta.reason
            : 'blocked from the ThreatCrush dashboard';
          const result = await this.manager.ban(target, reason, {
            ttlSeconds,
            source: 'manual',
            origin: 'cloud',
            ruleId: typeof meta.rule_id === 'string' ? meta.rule_id : undefined,
          });
          if (!result.ok) return failed(result.error ?? 'block failed');
          return { status: 'executed', dry_run: result.entry?.dry_run === true, executed_at };
        }
        case 'unblock': {
          if (isIP(target) === 0) return failed(`not an IP address: ${target}`);
          const wasBanned = this.manager.getBlocklist().some((b) => b.ip === target);
          const result = await this.manager.unban(target, {
            forget: true,
            origin: 'cloud',
            reason: 'unblocked from the ThreatCrush dashboard',
          });
          // Not banned here is the state the operator asked for.
          if (!result.ok && wasBanned) {
            return failed(result.error ?? 'unblock failed');
          }
          return { status: 'executed', dry_run: this.manager.status().dry_run, executed_at };
        }
        case 'allowlist_add':
          if (!isAddressOrCidr(target)) return failed(`not an IP address or CIDR: ${target}`);
          this.manager.addToAllowlist(target);
          return { status: 'executed', executed_at };
        case 'allowlist_remove':
          if (DEFAULT_PROTECTED.includes(target)) {
            return failed(`${target} is a built-in protected range and cannot be removed`);
          }
          this.manager.removeFromAllowlist(target);
          return { status: 'executed', executed_at };
        default:
          return failed(`unsupported action_type: ${action.action_type}`);
      }
    } catch (err) {
      return failed((err as Error).message);
    }
  }
}
