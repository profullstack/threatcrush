import type { AbuseReporterSection } from '../../types/config.js';
import { parseDuration } from '../firewall/backoff.js';
import { NEVER_REPORT_RANGES, type ReportabilityConfig } from './abuse-evidence.js';
import type { DestinationKeys, DestinationName } from './abuse-destinations.js';

/**
 * The resolved, runtime shape of `[abuse-reporter]`. Kept in its own module —
 * pure, no state DB, no network — so the CLI and the tests can read the
 * effective config without pulling in better-sqlite3.
 */
export interface ResolvedAbuseConfig extends ReportabilityConfig {
  enabled: boolean;
  dryRun: boolean;
  destinations: DestinationName[];
  keys: DestinationKeys;
  maxReportsPerHour: number;
  maxPerSourcePerDay: number;
}

export function resolveConfig(section?: AbuseReporterSection): ResolvedAbuseConfig {
  const s = section ?? {};
  const dryRun = s.mode === 'dry_run' ? true : s.mode === 'live' ? false : s.dry_run === true;
  const neverReport = [...NEVER_REPORT_RANGES, ...(s.never_report ?? [])];
  const cooling = parseDuration(s.cooling_off) ?? 3600;
  return {
    enabled: s.enabled !== false,
    dryRun,
    destinations: (s.destinations && s.destinations.length > 0 ? s.destinations : ['abuseipdb']) as DestinationName[],
    keys: {
      abuseipdb: s.abuseipdb_api_key || process.env.ABUSEIPDB_API_KEY || undefined,
      stopforumspam: s.stopforumspam_api_key || process.env.STOPFORUMSPAM_API_KEY || undefined,
    },
    minCorroboratingSignals: Math.max(1, s.min_corroborating_signals ?? 2),
    coolingOffSeconds: cooling,
    neverReport,
    maxReportsPerHour: Math.max(1, s.max_reports_per_hour ?? 50),
    maxPerSourcePerDay: Math.max(1, s.max_reports_per_source_per_day ?? 1),
  };
}
