import type { EventBus } from '../event-bus.js';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';
import type { HardeningResult } from '../../commands/harden.js';
import { cloudFetch } from '../../core/cli-config.js';
import {
  SEVERITY_RANK,
  currentLink,
  detectionEvent,
  findingEvents,
  remediationEvent,
  type CloudLink,
  type IngestEvent,
  type IngestResponse,
} from '../../core/cloud-events.js';
import { CloudSpool, DEFAULT_SPOOL_LIMITS, type SpoolLimits } from './cloud-spool.js';

export interface CloudSyncOptions {
  bus: EventBus;
  version: string;
  hostname: string;
  minSeverity: EventSeverity;
  spoolPath: string;
  log: (line: string) => void;
  /**
   * Modules a loaded rule reads. Their raw events are the evidence a rule
   * counts, and the rule's detection is what gets uploaded; a module no rule
   * covers (dns-monitor, a community module) is uploaded as it reports.
   */
  ruleModules: Set<string>;
  /** Runs the hardening checks without blocking the event loop. */
  runHardening?: () => Promise<HardeningResult[]>;
  spoolLimits?: SpoolLimits;
  batchSize?: number;
  flushMs?: number;
  heartbeatMs?: number;
  hardeningDelayMs?: number;
  hardeningIntervalMs?: number;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
}

/** Keep each request under the 1 MB ingest body limit with room to spare. */
const MAX_BATCH_BYTES = 900 * 1024;

/**
 * Reports this machine to the ThreatCrush dashboard: detections, bans and
 * unbans, hardening findings and a heartbeat.
 *
 * Everything goes through the on-disk spool and leaves on timers, never on the
 * bus listener's stack, so a slow or absent network cannot delay detection or
 * a ban. Does nothing until the machine is logged in and linked; the link is
 * re-read on every tick, so `threatcrush servers link` takes effect without a
 * restart.
 */
export class CloudSync {
  private readonly spool: CloudSpool;
  private readonly batchSize: number;
  private readonly flushMs: number;
  private readonly heartbeatMs: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private timers: NodeJS.Timeout[] = [];
  private flushing: Promise<void> | null = null;
  private backoffMs = 0;
  private retryAt = 0;
  private link: CloudLink | null = null;
  private lastProblem = '';
  private readonly onEvent = (event: ThreatEvent) => this.capture(event);

  constructor(private opts: CloudSyncOptions) {
    this.spool = new CloudSpool(opts.spoolPath, opts.spoolLimits ?? DEFAULT_SPOOL_LIMITS);
    this.batchSize = opts.batchSize ?? 100;
    this.flushMs = opts.flushMs ?? 10_000;
    this.heartbeatMs = opts.heartbeatMs ?? 60_000;
    this.baseBackoffMs = opts.baseBackoffMs ?? 5_000;
    this.maxBackoffMs = opts.maxBackoffMs ?? 300_000;
  }

  start(): void {
    this.link = currentLink();
    this.opts.bus.on('event', this.onEvent);
    const every = (ms: number, fn: () => void) => {
      const timer = setInterval(fn, ms);
      timer.unref?.();
      this.timers.push(timer);
    };
    every(this.flushMs, () => void this.flush());
    every(this.heartbeatMs, () => void this.heartbeat());
    void this.heartbeat();

    if (this.opts.runHardening) {
      const first = setTimeout(() => void this.reportHardening(), this.opts.hardeningDelayMs ?? 60_000);
      first.unref?.();
      this.timers.push(first);
      every(this.opts.hardeningIntervalMs ?? 86_400_000, () => void this.reportHardening());
    }

    if (this.spool.size > 0) {
      this.opts.log(`[cloud] ${this.spool.size} event(s) waiting in the spool from before`);
      void this.flush();
    }
  }

  async stop(): Promise<void> {
    this.opts.bus.off('event', this.onEvent);
    for (const timer of this.timers) clearInterval(timer);
    this.timers = [];
    await this.spool.settled();
  }

  get queued(): number { return this.spool.size; }

  /** Queue hardening results for upload (the CLI posts its own directly). */
  enqueueFindings(results: HardeningResult[]): number {
    const link = this.refreshLink();
    if (!link) return 0;
    for (const event of findingEvents(link.serverId, results)) this.spool.push(event);
    this.kick();
    return results.length;
  }

  /**
   * Upload everything queued, oldest first, until the spool is empty or the
   * dashboard stops answering. Concurrent calls share one run.
   */
  flush(): Promise<void> {
    this.flushing ??= this.drain().finally(() => { this.flushing = null; });
    return this.flushing;
  }

  private capture(event: ThreatEvent): void {
    const link = this.link;
    if (!link) return;
    let out: IngestEvent | null = null;
    if (event.module === 'firewall-rules') {
      out = remediationEvent(link.serverId, event);
    } else if (
      (event.module === 'rule-engine' || !this.opts.ruleModules.has(event.module)) &&
      event.details?.heartbeat !== true &&
      SEVERITY_RANK[event.severity] >= SEVERITY_RANK[this.opts.minSeverity]
    ) {
      out = detectionEvent(link.serverId, event);
    }
    if (!out) return;
    this.spool.push(out);
    if (this.spool.size >= this.batchSize) this.kick();
  }

  /** Flush soon, off the caller's stack, unless we are backing off. */
  private kick(): void {
    if (Date.now() < this.retryAt) return;
    setImmediate(() => void this.flush());
  }

  private refreshLink(): CloudLink | null {
    this.link = currentLink();
    return this.link;
  }

  private async drain(): Promise<void> {
    this.reportDropped();
    if (Date.now() < this.retryAt) return;
    if (!this.refreshLink()) return;

    while (this.spool.size > 0) {
      const batch = this.spool.peek(this.batchSize, MAX_BATCH_BYTES);
      const outcome = await this.post(batch);
      if (outcome === 'retry') return;
      this.spool.ack(batch.length);
    }
  }

  private async post(events: object[]): Promise<'sent' | 'dropped' | 'retry'> {
    let res: Response;
    try {
      res = await cloudFetch('/api/ingest', { method: 'POST', body: JSON.stringify({ events }) });
    } catch (err) {
      this.backOff(`dashboard unreachable (${(err as Error).message})`);
      return 'retry';
    }

    if (res.ok) {
      const body = await res.json().catch(() => ({})) as IngestResponse;
      const rejected = body.rejected ?? [];
      if (rejected.length > 0) {
        const sample = rejected.slice(0, 3).map((r) => `#${r.index}: ${r.error}`).join('; ');
        this.opts.log(`[cloud] ingest rejected ${rejected.length} of ${events.length} event(s): ${sample}`);
      }
      if (this.backoffMs > 0 || this.lastProblem) {
        this.opts.log(`[cloud] dashboard reachable again; uploading ${this.spool.size} queued event(s)`);
      }
      this.backoffMs = 0;
      this.retryAt = 0;
      this.lastProblem = '';
      return 'sent';
    }

    if (res.status === 401) {
      this.backOff('session expired and could not be refreshed — run `threatcrush login`');
      return 'retry';
    }
    if (res.status === 429 || res.status >= 500) {
      this.backOff(`dashboard answered ${res.status}`);
      return 'retry';
    }
    // 400 and other client errors: resending the same bytes cannot succeed.
    const detail = await res.text().catch(() => '');
    this.opts.log(`[cloud] ingest refused a batch (${res.status} ${detail.slice(0, 200)}); dropped ${events.length} event(s)`);
    return 'dropped';
  }

  private backOff(problem: string): void {
    this.backoffMs = this.backoffMs === 0
      ? this.baseBackoffMs
      : Math.min(this.backoffMs * 2, this.maxBackoffMs);
    this.retryAt = Date.now() + this.backoffMs;
    // One line per kind of trouble, not one per retry.
    if (problem !== this.lastProblem) {
      this.opts.log(`[cloud] ${problem}; ${this.spool.size} event(s) spooled, retrying with backoff`);
      this.lastProblem = problem;
    }
  }

  private reportDropped(): void {
    const dropped = this.spool.takeDropped();
    if (dropped > 0) {
      this.opts.log(`[cloud] spool full: dropped the ${dropped} oldest event(s)`);
    }
  }

  /**
   * Proof of life for the dashboard's online/offline badge. Not spooled: a
   * heartbeat replayed late would claim the box was up when nobody knew. A
   * heartbeat that gets through also ends a backoff early.
   */
  private async heartbeat(): Promise<void> {
    const link = this.refreshLink();
    if (!link) return;
    const event = {
      type: 'heartbeat',
      server_id: link.serverId,
      version: this.opts.version,
      hostname: this.opts.hostname,
    };
    try {
      const res = await cloudFetch('/api/ingest', { method: 'POST', body: JSON.stringify({ events: [event] }) });
      if (res.ok && this.retryAt > 0) {
        this.retryAt = 0;
        void this.flush();
      }
    } catch {
      // The spool's own backoff reports an outage; one heartbeat is not news.
    }
  }

  private async reportHardening(): Promise<void> {
    if (!this.refreshLink() || !this.opts.runHardening) return;
    try {
      const results = await this.opts.runHardening();
      const n = this.enqueueFindings(results);
      this.opts.log(`[cloud] hardening checks: queued ${n} finding(s) for upload`);
    } catch (err) {
      this.opts.log(`[cloud] hardening checks failed: ${(err as Error).message}`);
    }
  }
}
