import { randomUUID } from 'node:crypto';
import type { EventBus } from '../event-bus.js';
import type { ThreatEvent } from '../../types/events.js';
import type { AbuseReporterSection } from '../../types/config.js';
import { getEventsForIp } from '../../core/state.js';
import { isReportable, summarizeEvidence } from './abuse-evidence.js';
import { buildPayload, dispatch } from './abuse-destinations.js';
import { resolveConfig, type ResolvedAbuseConfig } from './abuse-config.js';
import { appendReport, currentReports, type AbuseReportRecord } from '../../core/abuse-report-log.js';

/**
 * Reports confirmed attack sources to shared reputation feeds (PRD 0015).
 *
 * It is the mirror image of CloudSync: where CloudSync *uploads* our own
 * detections to our own dashboard, this makes a public statement about someone
 * else's machine on a feed everyone reads. That asymmetry is why the evidence
 * bar in abuse-evidence.ts is not optional, and why this worker does as little
 * as possible on the bus listener's stack — a slow feed must never slow a ban.
 *
 * It is enabled by default but inert until a destination key is present: with
 * no key and not in dry-run it logs once and reports nothing, exactly as cloud
 * sync does nothing until the box is linked.
 */

export interface AbuseReporterOptions {
  bus: EventBus;
  section?: AbuseReporterSection;
  log: (line: string) => void;
  /** Override the audit directory (tests). */
  dir?: string;
  /** Override the clock (tests). */
  now?: () => number;
  flushMs?: number;
}

/** How far back the ledger is read when counting corroboration for a source. */
const EVIDENCE_LOOKBACK_MS = 24 * 60 * 60 * 1000;
/** Candidate sources are abandoned if they never clear the bar within this. */
const PENDING_TTL_MS = 24 * 60 * 60 * 1000;

export class AbuseReporter {
  private readonly cfg: ResolvedAbuseConfig;
  private readonly now: () => number;
  private readonly flushMs: number;
  /** Sources seen blocked, awaiting enough evidence / cooling-off, with when first queued. */
  private pending = new Map<string, number>();
  /** Epoch-ms of live reports sent this process, for the global hourly limit. */
  private recentReports: number[] = [];
  private timer: NodeJS.Timeout | null = null;
  private flushing = false;
  private readonly onEvent = (event: ThreatEvent) => this.capture(event);

  constructor(private opts: AbuseReporterOptions) {
    this.cfg = resolveConfig(opts.section);
    this.now = opts.now ?? (() => Date.now());
    this.flushMs = opts.flushMs ?? 60_000;
  }

  /** Active when it can do something: send live, or at least compute dry-run. */
  get active(): boolean {
    if (!this.cfg.enabled) return false;
    if (this.cfg.dryRun) return true;
    return Boolean(this.cfg.keys.abuseipdb || this.cfg.keys.stopforumspam);
  }

  start(): void {
    if (!this.cfg.enabled) {
      this.opts.log('[abuse] reporter disabled by [abuse-reporter] enabled = false');
      return;
    }
    if (!this.active) {
      this.opts.log(
        '[abuse] reporter on but inert: no destination API key set ' +
        '(ABUSEIPDB_API_KEY or [abuse-reporter] abuseipdb_api_key). Nothing will be reported.',
      );
      return;
    }
    this.opts.bus.on('event', this.onEvent);
    const timer = setInterval(() => void this.flush(), this.flushMs);
    timer.unref?.();
    this.timer = timer;
    const mode = this.cfg.dryRun ? 'dry_run (nothing sent)' : `live → ${this.cfg.destinations.join(', ')}`;
    this.opts.log(
      `[abuse] reporter ${mode}; bar: >=${this.cfg.minCorroboratingSignals} signals + completed handshake, ` +
      `cooling-off ${Math.round(this.cfg.coolingOffSeconds / 60)}m, ` +
      `<=${this.cfg.maxReportsPerHour}/h, ${this.cfg.maxPerSourcePerDay}/source/day`,
    );
  }

  stop(): void {
    this.opts.bus.off('event', this.onEvent);
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  get queued(): number {
    return this.pending.size;
  }

  /** Remember a blocked source as a candidate. No network here — that waits for flush. */
  private capture(event: ThreatEvent): void {
    if (event.module !== 'firewall-rules') return;
    if (event.details?.action !== 'block') return;
    if (event.details?.failed === true) return;
    const ip = event.source_ip;
    if (!ip) return;
    if (!this.pending.has(ip)) this.pending.set(ip, this.now());
  }

  /** Walk the candidates; report the ones that clear the bar and the limits. */
  async flush(): Promise<void> {
    if (this.flushing || !this.active) return;
    this.flushing = true;
    try {
      const now = this.now();
      this.trimRecent(now);
      for (const [ip, queuedAt] of [...this.pending]) {
        if (now - queuedAt > PENDING_TTL_MS) {
          this.pending.delete(ip);
          continue;
        }
        if (!this.cfg.dryRun && this.recentReports.length >= this.cfg.maxReportsPerHour) break;

        const evidence = summarizeEvidence(getEventsForIp(ip, now - EVIDENCE_LOOKBACK_MS));
        const decision = isReportable(ip, evidence, this.cfg, now);
        if (!decision.reportable) {
          // A source still cooling off stays queued; anything else is settled
          // (protected, spoofable, too few signals) and is dropped.
          if (decision.waitSeconds === undefined) this.pending.delete(ip);
          continue;
        }
        if (this.reportedWithin(ip, now, 86_400_000 * this.cfg.maxPerSourcePerDay)) {
          this.pending.delete(ip);
          continue;
        }

        this.pending.delete(ip);
        await this.report(ip, evidence, now);
        if (!this.cfg.dryRun) this.recentReports.push(now);
      }
    } catch (err) {
      this.opts.log(`[abuse] flush error: ${(err as Error).message}`);
    } finally {
      this.flushing = false;
    }
  }

  private async report(ip: string, evidence: ReturnType<typeof summarizeEvidence>, now: number): Promise<void> {
    const payload = buildPayload(ip, evidence);
    const results = this.cfg.dryRun
      ? []
      : await dispatch(payload, this.cfg.destinations, this.cfg.keys);

    const record: AbuseReportRecord = {
      id: randomUUID().slice(0, 8),
      ip,
      reported_at: new Date(now).toISOString(),
      mode: this.cfg.dryRun ? 'dry_run' : 'live',
      categories: payload.categories,
      comment: payload.comment,
      signals: evidence.signals,
      total_events: evidence.total,
      destinations: results,
    };
    try {
      appendReport(record, this.opts.dir);
    } catch (err) {
      this.opts.log(`[abuse] could not write audit record: ${(err as Error).message}`);
    }

    if (this.cfg.dryRun) {
      this.opts.log(`[abuse] [DRY-RUN] would report ${ip} (cats ${payload.categories.join(',')}, ${evidence.signals} signals)`);
    } else {
      const summary = results.map((r) => `${r.destination}:${r.ok ? 'ok' : 'FAIL'} ${r.detail}`).join('; ');
      this.opts.log(`[abuse] reported ${ip} [${record.id}] → ${summary || 'no destinations'}`);
    }
  }

  private trimRecent(now: number): void {
    const cutoff = now - 3_600_000;
    this.recentReports = this.recentReports.filter((t) => t > cutoff);
  }

  /** Has this source had a live report inside `windowMs`, per the audit log? */
  private reportedWithin(ip: string, now: number, windowMs: number): boolean {
    for (const r of currentReports(this.opts.dir)) {
      if (r.ip !== ip || r.mode !== 'live' || r.retracted_at) continue;
      if (now - Date.parse(r.reported_at) < windowMs) return true;
    }
    return false;
  }
}
