import type { EventBus } from '../event-bus.js';
import { readCliConfig, authHeaders, isLoggedIn } from '../../core/cli-config.js';
import { runScan } from '../../commands/scan.js';
import { runPentest } from '../../commands/pentest.js';
import { workerId, type RunResult } from '../../core/run-result.js';

const API_URL = process.env.THREATCRUSH_API_URL || 'https://threatcrush.com';
const POLL_INTERVAL_MS = 30_000;
const SCHEDULE_INTERVAL_MS = 120_000;

interface ClaimedRun {
  id: string;
  org_id: string;
  property_id: string;
  type: 'scan' | 'pentest';
  property: { id: string; name: string; kind: string; target: string } | null;
}

/**
 * Polls the server for queued property runs belonging to orgs the logged-in
 * user is a member of, claims them atomically, executes them locally, and
 * posts the result back.
 *
 * No-op unless `~/.threatcrush/config.json` contains a valid bearer token.
 */
export class RunsWorker {
  private pollTimer: NodeJS.Timeout | null = null;
  private scheduleTimer: NodeJS.Timeout | null = null;
  private running = false;
  private orgIds: string[] = [];

  constructor(private bus: EventBus) {}

  async start(): Promise<void> {
    if (!isLoggedIn()) return;

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
    if (!isLoggedIn()) return;
    try {
      if (this.orgIds.length === 0) await this.refreshOrgs();
      for (const orgId of this.orgIds) {
        try {
          await fetch(`${API_URL}/api/orgs/${orgId}/schedules/tick`, {
            method: 'POST',
            headers: authHeaders(),
          });
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
    if (!isLoggedIn()) return;

    this.running = true;
    try {
      if (this.orgIds.length === 0) await this.refreshOrgs();
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

  private async refreshOrgs(): Promise<void> {
    const res = await fetch(`${API_URL}/api/orgs`, { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json() as { organizations?: Array<{ id: string }> };
    this.orgIds = (data.organizations || []).map((o) => o.id);
  }

  private async claimOne(orgId: string): Promise<ClaimedRun | null> {
    try {
      const res = await fetch(`${API_URL}/api/orgs/${orgId}/runs/pending`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ worker_id: workerId() }),
      });
      if (!res.ok) return null;
      const data = await res.json() as { run?: ClaimedRun | null };
      return data.run ?? null;
    } catch {
      return null;
    }
  }

  private async execute(run: ClaimedRun): Promise<RunResult> {
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
      await fetch(
        `${API_URL}/api/orgs/${orgId}/properties/${claimed.property_id}/runs/${claimed.id}`,
        {
          method: 'PATCH',
          headers: authHeaders(),
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
