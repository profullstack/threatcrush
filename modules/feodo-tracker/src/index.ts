import { isIP } from 'node:net';

import type {
  ModuleContext,
  ThreatCrushModule,
  ThreatEvent,
} from '@threatcrush/sdk';

export interface FeodoIndicator {
  firstSeenUtc: string;
  destinationIp: string;
  destinationPort: number;
  status: string;
  lastOnline: string;
  malware: string;
}

export const DEFAULT_FEED_URL =
  'https://feodotracker.abuse.ch/downloads/ipblocklist.csv';
const STATE_KEY = 'seen_indicators';
const MAX_STORED_INDICATORS = 5000;

export function indicatorKey(indicator: FeodoIndicator): string {
  return `${indicator.destinationIp}:${indicator.destinationPort}:${indicator.firstSeenUtc}`;
}

export function parseFeodoCsv(csv: string): FeodoIndicator[] {
  const indicators: FeodoIndicator[] = [];

  for (const rawLine of csv.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const columns = splitCsvRow(line);
    if (columns[0] === 'first_seen_utc') continue;
    if (columns.length < 6) continue;

    const destinationPort = Number.parseInt(columns[2], 10);
    if (!columns[0] || !isIpAddress(columns[1]) || !isValidPort(destinationPort)) {
      continue;
    }

    indicators.push({
      firstSeenUtc: columns[0],
      destinationIp: columns[1],
      destinationPort,
      status: columns[3].toLowerCase(),
      lastOnline: columns[4],
      malware: columns[5] || 'unknown',
    });
  }

  return indicators;
}

export function toThreatEvent(
  indicator: FeodoIndicator,
  source = DEFAULT_FEED_URL,
): ThreatEvent {
  const isOnline = indicator.status === 'online';
  return {
    timestamp: parseUtcDate(indicator.firstSeenUtc),
    module: 'feodo-tracker',
    category: 'network',
    severity: isOnline ? 'high' : 'medium',
    message: `Feodo Tracker: ${indicator.malware} C2 ${indicator.destinationIp}:${indicator.destinationPort} is ${indicator.status}`,
    source_ip: indicator.destinationIp,
    details: {
      destination_ip: indicator.destinationIp,
      destination_port: indicator.destinationPort,
      c2_status: indicator.status,
      first_seen_utc: indicator.firstSeenUtc,
      last_online: indicator.lastOnline,
      malware: indicator.malware,
      source,
    },
  };
}

export default class FeodoTrackerModule implements ThreatCrushModule {
  name = 'feodo-tracker';
  version = '0.1.0';
  description =
    'Monitors Feodo Tracker for active botnet command-and-control servers';

  private context!: ModuleContext;
  private timer: NodeJS.Timeout | null = null;
  private polling = false;

  async init(context: ModuleContext): Promise<void> {
    this.context = context;
    this.context.logger.info('[%s] initialized', this.name);
  }

  async start(): Promise<void> {
    const intervalSeconds = Math.max(
      60,
      readNumber(this.context.config.poll_interval_seconds, 900),
    );

    await this.poll();
    this.timer = setInterval(() => {
      void this.poll();
    }, intervalSeconds * 1000);
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.context.logger.info('[%s] stopped', this.name);
  }

  private async poll(): Promise<void> {
    if (this.polling) return;
    this.polling = true;

    try {
      const feedUrl = readString(this.context.config.feed_url, DEFAULT_FEED_URL);
      const emitOffline = this.context.config.emit_offline === true;
      const maxEvents = Math.max(
        1,
        Math.floor(readNumber(this.context.config.max_events_per_poll, 100)),
      );
      const indicators = await fetchIndicators(feedUrl);
      const previousKeys = readStoredKeys(this.context.getState(STATE_KEY));
      const seen = new Set(previousKeys);
      const fresh = indicators
        .filter((indicator) => emitOffline || indicator.status === 'online')
        .filter((indicator) => !seen.has(indicatorKey(indicator)))
        .slice(-maxEvents);

      for (const indicator of fresh) {
        this.context.emit(toThreatEvent(indicator, feedUrl));
      }

      const currentKeys = indicators.map(indicatorKey);
      const storedKeys = [
        ...new Set([...currentKeys.reverse(), ...previousKeys]),
      ].slice(0, MAX_STORED_INDICATORS);
      this.context.setState(STATE_KEY, storedKeys);
      this.context.logger.info(
        '[%s] processed %d indicators, emitted %d',
        this.name,
        indicators.length,
        fresh.length,
      );
    } catch (error) {
      this.context.logger.error('[%s] poll failed: %s', this.name, String(error));
    } finally {
      this.polling = false;
    }
  }
}

export async function fetchIndicators(url: string): Promise<FeodoIndicator[]> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') {
    throw new Error('feed_url must use HTTPS');
  }

  const response = await fetch(parsed, {
    headers: {
      Accept: 'text/csv',
      'User-Agent': 'threatcrush-feodo-tracker/0.1.0',
    },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) {
    throw new Error(`Feodo Tracker feed returned HTTP ${response.status}`);
  }
  return parseFeodoCsv(await response.text());
}

function readStoredKeys(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function readString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

function readNumber(value: unknown, fallback: number): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseUtcDate(value: string): Date {
  const normalized = value.includes('T') ? value : `${value.replace(' ', 'T')}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function isValidPort(value: number): boolean {
  return Number.isInteger(value) && value > 0 && value <= 65_535;
}

function isIpAddress(value: string): boolean {
  return isIP(value) !== 0;
}

function splitCsvRow(line: string): string[] {
  const columns: string[] = [];
  let current = '';
  let quoted = false;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (character === ',' && !quoted) {
      columns.push(current);
      current = '';
    } else {
      current += character;
    }
  }
  columns.push(current);
  return columns;
}
