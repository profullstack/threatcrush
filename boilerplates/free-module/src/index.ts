/**
 * URLhaus Feed Module — free / MIT-licensed ThreatCrush boilerplate.
 *
 * Polls the abuse.ch URLhaus public CSV feed on an interval, parses newly
 * seen malicious URLs, and emits one `ThreatEvent` per fresh entry. State is
 * persisted via `ctx.setState` so we don't re-emit on restart.
 *
 * This is a fully working integration template — clone it, swap the feed URL
 * and parser for whatever upstream you actually want to ingest from.
 */

import type {
  ThreatCrushModule,
  ModuleContext,
  ThreatEvent,
  EventSeverity,
} from '@threatcrush/sdk';

interface UrlhausEntry {
  id: string;
  dateAdded: string;
  url: string;
  threat: string;
  tags: string[];
}

const SEVERITY_RANK: Record<EventSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export default class UrlhausFeedModule implements ThreatCrushModule {
  name = 'urlhaus-feed';
  version = '0.1.0';
  description = 'Polls URLhaus public feed and emits malicious-URL events';

  private ctx!: ModuleContext;
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;
    this.ctx.logger.info('[%s] initialized', this.name);
  }

  async start(): Promise<void> {
    const intervalSec =
      (this.ctx.config.poll_interval_seconds as number | undefined) ?? 300;
    this.ctx.logger.info(
      '[%s] starting poll loop (every %ds)',
      this.name,
      intervalSec,
    );
    this.running = true;
    // First tick immediately, then on the interval.
    void this.tick();
    this.timer = setInterval(() => void this.tick(), intervalSec * 1000);
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.ctx.logger.info('[%s] stopped', this.name);
  }

  private async tick(): Promise<void> {
    if (!this.running) return;
    const feedUrl =
      (this.ctx.config.feed_url as string | undefined) ??
      'https://urlhaus.abuse.ch/downloads/csv_recent/';

    let entries: UrlhausEntry[] = [];
    try {
      entries = await this.fetchFeed(feedUrl);
    } catch (err) {
      this.ctx.logger.error('[%s] fetch failed: %s', this.name, String(err));
      return;
    }

    const lastSeenId = (this.ctx.getState('last_seen_id') as string) ?? '';
    const threshold =
      (this.ctx.config.severity_threshold as EventSeverity | undefined) ??
      'medium';
    const minRank = SEVERITY_RANK[threshold] ?? SEVERITY_RANK.medium;

    let newest = lastSeenId;
    let emitted = 0;
    for (const entry of entries) {
      if (lastSeenId && entry.id <= lastSeenId) continue;
      const severity = this.classify(entry);
      if (SEVERITY_RANK[severity] < minRank) continue;

      const event: ThreatEvent = {
        timestamp: new Date(entry.dateAdded),
        module: this.name,
        category: 'web',
        severity,
        message: `URLhaus: ${entry.threat} → ${entry.url}`,
        details: {
          urlhaus_id: entry.id,
          url: entry.url,
          threat: entry.threat,
          tags: entry.tags,
        },
      };
      this.ctx.emit(event);
      emitted++;
      if (entry.id > newest) newest = entry.id;
    }

    if (newest && newest !== lastSeenId) {
      this.ctx.setState('last_seen_id', newest);
    }
    this.ctx.logger.info(
      '[%s] processed %d entries, emitted %d',
      this.name,
      entries.length,
      emitted,
    );
  }

  private async fetchFeed(url: string): Promise<UrlhausEntry[]> {
    const res = await fetch(url, { headers: { Accept: 'text/csv' } });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${url}`);
    }
    const csv = await res.text();
    return parseUrlhausCsv(csv);
  }

  private classify(entry: UrlhausEntry): EventSeverity {
    const t = entry.threat.toLowerCase();
    if (t.includes('ransomware') || t.includes('rat')) return 'critical';
    if (t.includes('phishing') || t.includes('botnet')) return 'high';
    if (t.includes('malware')) return 'medium';
    return 'low';
  }
}

/**
 * Parse the URLhaus `csv_recent` format. Comment lines start with `#`.
 * Columns: id, dateadded, url, url_status, last_online, threat, tags,
 *          urlhaus_link, reporter
 */
export function parseUrlhausCsv(csv: string): UrlhausEntry[] {
  const out: UrlhausEntry[] = [];
  for (const rawLine of csv.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const cols = splitCsvRow(line);
    if (cols.length < 7) continue;
    out.push({
      id: cols[0],
      dateAdded: cols[1],
      url: cols[2],
      threat: cols[5],
      tags: cols[6] ? cols[6].split(',').map((t) => t.trim()) : [],
    });
  }
  return out;
}

function splitCsvRow(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuote = !inQuote;
      continue;
    }
    if (ch === ',' && !inQuote) {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out;
}
