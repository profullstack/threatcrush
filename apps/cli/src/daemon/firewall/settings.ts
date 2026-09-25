import type { RemediationSection } from '../../types/config.js';
import type { RemediationConfig } from './remediation.js';
import { parseDuration } from './backoff.js';

/**
 * Turns the `[remediation]` TOML section into the manager's settings.
 *
 * Both spellings of the old keys are accepted (`dry_run`, `allowlist`) so an
 * existing config keeps working, but the defaults have moved: absent any
 * config, ThreatCrush now enforces rather than narrating what it would have
 * done.
 */
export function remediationSettings(section?: RemediationSection): Partial<RemediationConfig> {
  if (!section) return {};

  const settings: Partial<RemediationConfig> = {};

  if (typeof section.enabled === 'boolean') settings.enabled = section.enabled;

  // `mode` wins over the legacy boolean when both are present.
  if (section.mode === 'dry_run') settings.dry_run = true;
  else if (section.mode === 'enforce') settings.dry_run = false;
  else if (typeof section.dry_run === 'boolean') settings.dry_run = section.dry_run;

  if (section.min_severity) settings.min_severity = section.min_severity;

  const maxBan = parseDuration(section.max_ban);
  if (maxBan) settings.max_ban_seconds = maxBan;

  const memory = parseDuration(section.strike_memory);
  if (memory) settings.strike_memory_seconds = memory;

  const allow = [...(section.protected ?? []), ...(section.allowlist ?? [])];
  if (allow.length > 0) settings.allowlist = allow;

  if (typeof section.protect_current_ssh_client === 'boolean') {
    settings.protect_current_ssh_client = section.protect_current_ssh_client;
  }

  if (typeof section.spare_verified_crawlers === 'boolean') {
    settings.spare_verified_crawlers = section.spare_verified_crawlers;
  }

  return settings;
}
