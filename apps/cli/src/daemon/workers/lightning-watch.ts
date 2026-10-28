import { accessSync, constants, existsSync } from 'node:fs';
import type { ThreatEvent } from '../../types/events.js';
import { LogTail } from '../../core/log-tail.js';
import { insertEvent } from '../../core/state.js';

/**
 * Core Lightning channel closes (`[lightning]`, on whenever a CLN log is
 * found). On 2026-10-27 the dev2 intruder, as root, closed all four channels
 * in under two minutes and swept the funds on-chain; cln.log said so plainly:
 *
 *   ... -chan#3: State changed from CHANNELD_NORMAL to CHANNELD_SHUTTING_DOWN
 *
 * Each channel leaving CHANNELD_NORMAL for a closing state is `high`; two or
 * more channels within 10 minutes is a `critical` burst (pages on-call). A
 * node operator closing one channel by hand gets one high alert, not a page.
 */

export const DEFAULT_CLN_LOGS = [
  '/home/lightning/.lightning/cln.log',
  '/root/.lightning/cln.log',
  '/var/lib/clightning/cln.log',
  '/home/lightning/.lightning/bitcoin/cln.log',
];

const CLOSE_RE = /^(\S+)\s+\S+\s+(\S+?)-chan#(\d+): State changed from CHANNELD_NORMAL to (CHANNELD_SHUTTING_DOWN|AWAITING_UNILATERAL|CLOSINGD_SIGEXCHANGE|CLOSINGD_COMPLETE)/;

export interface ChannelClose { at: Date; peer: string; channel: string; to: string; line: string }

export function parseChannelClose(line: string): ChannelClose | null {
  const m = CLOSE_RE.exec(line);
  if (!m) return null;
  const at = new Date(m[1]);
  return { at: Number.isNaN(at.getTime()) ? new Date() : at, peer: m[2], channel: `${m[2].slice(0, 12)}…#${m[3]}`, to: m[4], line: line.slice(0, 500) };
}

const BURST_WINDOW_MS = 10 * 60_000;
const BURST_REALERT_MS = 30 * 60_000;

export class ChannelCloseDetector {
  private recent: ChannelClose[] = [];
  private lastBurst = 0;

  /** Events for one log line (none, a close, or a close and a burst). */
  feed(line: string): Array<Pick<ThreatEvent, 'severity' | 'message' | 'details' | 'timestamp'>> {
    const close = parseChannelClose(line);
    if (!close) return [];
    const t = close.at.getTime();
    this.recent = this.recent.filter((c) => t - c.at.getTime() < BURST_WINDOW_MS && c.channel !== close.channel);
    this.recent.push(close);
    const out: Array<Pick<ThreatEvent, 'severity' | 'message' | 'details' | 'timestamp'>> = [{
      timestamp: close.at,
      severity: 'high',
      message: `Lightning channel ${close.channel} closing (${close.to})`,
      details: { rule_id: 'ln-channel-close', peer: close.peer, to_state: close.to, evidence: { at: close.at.toISOString(), module: 'lightning', message: close.line } },
    }];
    if (this.recent.length >= 2 && t - this.lastBurst >= BURST_REALERT_MS) {
      this.lastBurst = t;
      out.push({
        timestamp: close.at,
        severity: 'critical',
        message: `Lightning channel-close burst: ${this.recent.length} channels closing within 10 minutes (${this.recent.map((c) => c.channel).join(', ')}). If nobody here did this, the node is being drained.`,
        details: { rule_id: 'ln-channel-close-burst', channels: this.recent.map((c) => c.channel), evidence: { at: close.at.toISOString(), module: 'lightning', message: close.line } },
      });
    }
    return out;
  }
}

export class LightningWatch {
  private tails: LogTail[] = [];
  private timer: NodeJS.Timeout | null = null;
  private detector = new ChannelCloseDetector();

  constructor(private opts: {
    bus: { publish(event: ThreatEvent): void };
    paths?: string[];
    enabled?: boolean;
    log: (line: string) => void;
  }) {}

  start(): string[] {
    if (this.opts.enabled === false) return [];
    const found: string[] = [];
    for (const path of this.opts.paths?.length ? this.opts.paths : DEFAULT_CLN_LOGS) {
      if (!existsSync(path)) continue;
      try { accessSync(path, constants.R_OK); } catch { continue; }
      this.tails.push(new LogTail(path));
      found.push(path);
    }
    if (!found.length) return [];
    this.timer = setInterval(() => this.poll(), 2000);
    this.timer.unref?.();
    this.opts.log(`[lightning] watching channel closes in ${found.join(', ')}`);
    return found;
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.tails = [];
  }

  poll(): void {
    for (const tail of this.tails) {
      tail.poll((line) => {
        for (const e of this.detector.feed(line)) {
          const event: ThreatEvent = { module: 'lightning', category: 'system', ...e };
          try { insertEvent(event); } catch { /* db optional */ }
          this.opts.bus.publish(event);
        }
      });
    }
  }
}
