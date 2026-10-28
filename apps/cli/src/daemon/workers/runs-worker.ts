import { lookup } from 'node:dns/promises';
import { realpathSync } from 'node:fs';
import { isIP } from 'node:net';
import { resolve, sep } from 'node:path';
import type { EventBus } from '../event-bus.js';
import { cloudFetch, hasSession } from '../../core/cli-config.js';
import { currentLink } from '../../core/cloud-events.js';
import { DEFAULT_PROTECTED, isProtected } from '../firewall/protected.js';
import { runScan } from '../../commands/scan.js';
import { runPentest } from '../../commands/pentest.js';
import { workerId, type RunResult } from '../../core/run-result.js';

const POLL_INTERVAL_MS = 30_000;
const SCHEDULE_INTERVAL_MS = 120_000;

export interface ClaimedRun {
  id: string;
  org_id: string;
  property_id: string;
  type: 'scan' | 'pentest';
  property: { id: string; name: string; kind: string; target: string } | null;
}

/** Addresses a dashboard-queued pentest may never reach from this machine. */
const NOT_PUBLIC = [
  ...DEFAULT_PROTECTED,
  '0.0.0.0/8', '100.64.0.0/10', '192.0.0.0/24', '198.18.0.0/15', '224.0.0.0/3',
  '::/128', '::ffff:0:0/96', '64:ff9b::/96', 'ff00::/8',
];

export function isPublicTarget(ip: string): boolean {
  return isIP(ip) !== 0 && !isProtected(ip, NOT_PUBLIC);
}

/** Why a pentest target may not run from this box (it resolves somewhere private), or null. */
export async function pentestTargetError(
  rawUrl: string,
  resolveHost: (host: string) => Promise<string[]> = async (h) => (await lookup(h, { all: true })).map((a) => a.address),
): Promise<string | null> {
  let url: URL;
  try {
    url = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
  } catch {
    return `not a URL: ${rawUrl}`;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return `not an http(s) URL: ${rawUrl}`;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  let addresses: string[];
  try {
    addresses = isIP(host) ? [host] : await resolveHost(host);
  } catch (err) {
    return `cannot resolve ${host}: ${(err as Error).message}`;
  }
  if (addresses.length === 0) return `cannot resolve ${host}`;
  const inside = addresses.find((a) => !isPublicTarget(a));
  return inside ? `${host} resolves to ${inside}, which is not a public address; dashboard runs never reach inside this network` : null;
}

/** Why a scan of `target` may not run (outside every allowed root), or null. */
export function scanTargetError(target: string, roots: string[], real: (p: string) => string = realpathSync): string | null {
  if (roots.length === 0) {
    return 'dashboard scans of this machine are off; list the directories they may read in [cloud] run_scan_paths';
  }
  let path: string;
  try {
    path = real(resolve(target));
  } catch {
    return `no such path: ${target}`;
  }
  for (const root of roots) {
    let base: string;
    try {
      base = real(resolve(root));
    } catch {
      continue;
    }
    if (path === base || path.startsWith(base.endsWith(sep) ? base : base + sep)) return null;
  }
  return `${target} is outside [cloud] run_scan_paths`;
}

export interface RunsWorkerOptions {
  /** `[cloud] runs = true`. Off by default. */
  enabled: boolean;
  /** `[cloud] run_scan_paths`: the only directories a dashboard scan may read. */
  scanRoots: string[];
  log?: (line: string) => void;
}

/**
 * Executes property runs (scans, pentests) queued on the dashboard for the
 * org this server is linked to, claims them atomically, and posts the result
 * back.
 *
 * Off unless the operator sets `[cloud] runs = true` on this machine: it runs
 * as the daemon (root on a server), takes its target from the cloud, and
 * uploads what it finds. Until 2026-10-28 it was on whenever a session
 * existed and worked for every org the logged-in user belonged to, so anyone
 * who added that user to an org of theirs could have the daemon scan any
 * local path or probe internal URLs and read the results. Now:
 *   - only the org from `threatcrush servers link`;
 *   - a scan only under `[cloud] run_scan_paths`;
 *   - a pentest only against public addresses.
 */
export class RunsWorker {
  private pollTimer: NodeJS.Timeout | null = null;
  private scheduleTimer: NodeJS.Timeout | null = null;
  private running = false;
  private orgIds: string[] = [];

  constructor(private bus: EventBus, private opts: RunsWorkerOptions = { enabled: false, scanRoots: [] }) {}

  async start(): Promise<void> {
    if (!this.opts.enabled) {
      this.opts.log?.('[runs] dashboard property runs off (set [cloud] runs = true to run them on this machine)');
      return;
    }
    if (!hasSession()) return;

    try {
      await this.refreshOrgs();
    } catch {
      // First fetch may fail if the network is down; the tick loop will retry.
    }

    this.bus.announceModule('runs-worker', 'running', `poll ${POLL_INTERVAL_MS / 1000}s`);
    this.tick();
    this.scheduleTick();
    this.pollTimer = setInterval(() => this.tick(), POLL_INTERVAL_MS);
    this.scheduleTimer = setInterval(() => this.scheduleTick(), SCHEDULE_INTERVAL_MS);
  }

  stop(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.scheduleTimer) clearInterval(this.scheduleTimer);
    this.pollTimer = null;
    this.scheduleTimer = null;
    this.bus.announceModule('runs-worker', 'stopped');
  }

  private async scheduleTick(): Promise<void> {
    if (!hasSession()) return;
    try {
      await this.refreshOrgs();
      for (const orgId of this.orgIds) {
        try {
          await cloudFetch(`/api/orgs/${orgId}/schedules/tick`, { method: 'POST' });
        } catch {
          // ignore transient network errors
        }
      }
    } catch {
      // swallow — retry next interval
    }
  }

  private async tick(): Promise<void> {
    if (this.running) return;
    if (!hasSession()) return;

    this.running = true;
    try {
      await this.refreshOrgs();
      for (const orgId of this.orgIds) {
        const claimed = await this.claimOne(orgId);
        if (!claimed) continue;

        const result = await this.execute(claimed);
        await this.finalize(orgId, claimed, result);
      }
    } catch {
      // swallow — we'll try again on the next tick
    } finally {
      this.running = false;
    }
  }

  /** Only the org this server is linked to: never every org its user is in. */
  private async refreshOrgs(): Promise<void> {
    const link = currentLink();
    this.orgIds = link ? [link.orgId] : [];
  }

  private async claimOne(orgId: string): Promise<ClaimedRun | null> {
    try {
      const res = await cloudFetch(`/api/orgs/${orgId}/runs/pending`, {
        method: 'POST',
        body: JSON.stringify({ worker_id: workerId() }),
      });
      if (!res.ok) return null;
      const data = await res.json() as { run?: ClaimedRun | null };
      return data.run ?? null;
    } catch {
      return null;
    }
  }

  async execute(run: ClaimedRun): Promise<RunResult> {
    const target = run.property?.target;
    if (!target) {
      return {
        type: run.type,
        target: '',
        findings: [],
        severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        summary: 'property target missing',
        error: 'property target missing',
      };
    }

    const refused = run.type === 'scan'
      ? scanTargetError(target, this.opts.scanRoots)
      : await pentestTargetError(target);
    if (refused) {
      this.opts.log?.(`[runs] refused ${run.type} ${target}: ${refused}`);
      return {
        type: run.type,
        target,
        findings: [],
        severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        summary: `refused: ${refused}`,
        error: refused,
      };
    }

    this.bus.announceModule('runs-worker', 'running', `${run.type} ${run.property?.name || target}`);

    try {
      if (run.type === 'scan') return await runScan(target);
      return await runPentest(target);
    } catch (err) {
      return {
        type: run.type,
        target,
        findings: [],
        severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        summary: `failed: ${(err as Error).message}`,
        error: (err as Error).message,
      };
    }
  }

  private async finalize(orgId: string, claimed: ClaimedRun, result: RunResult): Promise<void> {
    try {
      await cloudFetch(
        `/api/orgs/${orgId}/properties/${claimed.property_id}/runs/${claimed.id}`,
        {
          method: 'PATCH',
          body: JSON.stringify({
            status: result.error ? 'failed' : 'succeeded',
            findings_count: result.findings.length,
            severity_summary: result.severity_summary,
            summary: result.summary,
            findings: result.findings,
            error: result.error,
            source: 'daemon',
            worker_id: workerId(),
          }),
        },
      );
    } catch {
      // best-effort
    } finally {
      this.bus.announceModule('runs-worker', 'idle');
    }
  }
}
