import { isIP } from 'node:net';
import { cloudFetch } from '../../core/cli-config.js';
import { currentLink } from '../../core/cloud-events.js';
import type { RemediationManager } from '../firewall/remediation.js';

/** A bare IPv4/IPv6 address or a CIDR with a prefix that fits its family. */
export function isAddressOrCidr(value: string): boolean {
  const [network, prefix, extra] = value.split('/');
  const family = isIP(network);
  if (family === 0 || extra !== undefined) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (family === 4 ? 32 : 128);
}

/** Widest range the dashboard may protect: a /8 for IPv4, a /16 for IPv6. */
export const CLOUD_MIN_PREFIX = { 4: 8, 6: 16 } as const;

/**
 * An entry the dashboard may add to this server's never-block set. Anything
 * wider than CLOUD_MIN_PREFIX (0.0.0.0/0, ::/0, 0.0.0.0/1 …) would switch
 * blocking off, so one bad or compromised dashboard write cannot do that to
 * every box in the org. Local config is not limited by this.
 */
export function isCloudAllowEntry(value: string): boolean {
  if (!isAddressOrCidr(value)) return false;
  const [network, prefix] = value.split('/');
  if (prefix === undefined) return true;
  return Number(prefix) >= CLOUD_MIN_PREFIX[isIP(network) as 4 | 6];
}

export type AllowlistManager = Pick<
  RemediationManager,
  'getProtected' | 'addToAllowlist' | 'removeFromAllowlist'
>;

/**
 * Merges the organization's IP/CIDR allowlist (the dashboard's) into this
 * server's never-block set every few minutes.
 *
 * It only ever takes back what it added: an entry that was already protected
 * — a built-in range, the operator's `[remediation] protected`, the SSH
 * client — is left alone when it disappears from the org list.
 */
export class AllowlistSync {
  private timer: NodeJS.Timeout | null = null;
  private owned = new Set<string>();

  constructor(
    private manager: AllowlistManager,
    private opts: { log: (line: string) => void; intervalMs?: number },
  ) {}

  start(): void {
    this.timer = setInterval(() => void this.sync(), this.opts.intervalMs ?? 300_000);
    this.timer.unref?.();
    void this.sync();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async sync(): Promise<void> {
    const link = currentLink();
    if (!link) return;

    let entries: Array<{ type?: string; value?: string }>;
    try {
      const res = await cloudFetch(`/api/orgs/${link.orgId}/allowlists`);
      if (!res.ok) return;
      const data = await res.json() as { entries?: Array<{ type?: string; value?: string }> };
      if (!Array.isArray(data.entries)) return;
      entries = data.entries;
    } catch {
      return; // Keep what we have; try again next interval.
    }

    const wanted = new Set<string>();
    for (const entry of entries) {
      if (entry.type !== 'ip' && entry.type !== 'cidr') continue;
      const value = String(entry.value ?? '').trim();
      if (isCloudAllowEntry(value)) wanted.add(value);
      else if (isAddressOrCidr(value)) this.opts.log(`[cloud] org allowlist: ignoring ${value} (wider than /${CLOUD_MIN_PREFIX[isIP(value.split('/')[0]) as 4 | 6]})`);
    }

    const added: string[] = [];
    const protectedNow = new Set(this.manager.getProtected());
    for (const value of wanted) {
      if (this.owned.has(value) || protectedNow.has(value)) continue;
      this.manager.addToAllowlist(value);
      this.owned.add(value);
      added.push(value);
    }

    const removed: string[] = [];
    for (const value of this.owned) {
      if (wanted.has(value)) continue;
      this.manager.removeFromAllowlist(value);
      this.owned.delete(value);
      removed.push(value);
    }

    if (added.length > 0 || removed.length > 0) {
      this.opts.log(
        `[cloud] org allowlist: +${added.length} -${removed.length} ` +
        `(${[...added.map((v) => `+${v}`), ...removed.map((v) => `-${v}`)].slice(0, 10).join(' ')})`,
      );
    }
  }
}
