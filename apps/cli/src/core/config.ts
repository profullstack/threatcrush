import { readFileSync, existsSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import TOML from '@iarna/toml';
import type { ThreatCrushConfig, ModuleConfig } from '../types/config.js';

const DEFAULT_CONFIG_PATH = '/etc/threatcrush/threatcrushd.conf';
const DEFAULT_CONFDIR = '/etc/threatcrush/threatcrushd.conf.d';

const DEFAULT_CONFIG: ThreatCrushConfig = {
  daemon: {
    pid_file: '/var/run/threatcrush/threatcrushd.pid',
    log_level: 'info',
    log_file: '/var/log/threatcrush/threatcrushd.log',
    state_db: '/var/lib/threatcrush/state.db',
  },
  api: {
    enabled: true,
    bind: '127.0.0.1:9393',
    tls: false,
  },
  alerts: {},
  modules: {
    auto_update: true,
    update_interval: '24h',
    module_dir: '/etc/threatcrush/modules',
    config_dir: DEFAULT_CONFDIR,
  },
};

export function loadConfig(configPath?: string, onError?: (err: Error) => void): ThreatCrushConfig {
  const path = configPath || DEFAULT_CONFIG_PATH;
  if (!existsSync(path)) {
    return { ...DEFAULT_CONFIG };
  }
  try {
    return parseConfigText(readFileSync(path, 'utf-8'));
  } catch (err) {
    onError?.(err as Error);
    return { ...DEFAULT_CONFIG };
  }
}

/**
 * One config file's text as the daemon's config. Throws on invalid TOML (a
 * duplicate key, a header glued to a key): callers decide what a broken file
 * means. `loadConfig` falls back to the defaults; the daemon must not, since
 * the defaults have no `[remediation] protected` list (see loadDaemonConfig).
 */
export function parseConfigText(raw: string): ThreatCrushConfig {
  const parsed = TOML.parse(raw) as unknown as Partial<ThreatCrushConfig>;
  return {
    daemon: { ...DEFAULT_CONFIG.daemon, ...parsed.daemon },
    api: { ...DEFAULT_CONFIG.api, ...parsed.api },
    alerts: parsed.alerts || {},
    modules: { ...DEFAULT_CONFIG.modules, ...parsed.modules },
    remediation: parsed.remediation,
    detection: parsed.detection,
    cloud: parsed.cloud,
    watchdog: parsed.watchdog,
    update: parsed.update,
    threat_feeds: parsed.threat_feeds,
    privileged: parsed.privileged,
    command_history: parsed.command_history,
    lightning: parsed.lightning,
    storage: parsed.storage,
    // TOML's `[abuse-reporter]` parses to a hyphenated key; expose it under
    // the JS-friendly name the rest of the daemon reads.
    abuse_reporter:
      (parsed as Record<string, unknown>)['abuse-reporter'] as ThreatCrushConfig['abuse_reporter'] ??
      parsed.abuse_reporter,
    license: parsed.license,
  };
}

/**
 * The daemon's config, never silently the defaults.
 *
 * 2026-10-28: a duplicated key in dev2's threatcrushd.conf made TOML.parse
 * throw, loadConfig returned the defaults, and the daemon came up with backend
 * auto (fail2ban) and NO protected list, then banned one of our own servers
 * as a scanner within a minute. Now a file that parses is saved as the last
 * good copy; a file that does not is reported and the last good copy is used.
 */
export function loadDaemonConfig(configPath: string, lastGoodPath: string): {
  config: ThreatCrushConfig;
  error?: string;
  usedLastGood: boolean;
} {
  if (!existsSync(configPath)) return { config: { ...DEFAULT_CONFIG }, usedLastGood: false };
  let raw = '';
  try {
    raw = readFileSync(configPath, 'utf-8');
    const config = parseConfigText(raw);
    try {
      mkdirSync(dirname(lastGoodPath), { recursive: true });
      writeFileSync(lastGoodPath, raw, { mode: 0o600 });
    } catch { /* best effort */ }
    return { config, usedLastGood: false };
  } catch (err) {
    const error = `${configPath} is not valid TOML: ${(err as Error).message.split('\n')[0]}`;
    try {
      if (existsSync(lastGoodPath)) {
        return { config: parseConfigText(readFileSync(lastGoodPath, 'utf-8')), error, usedLastGood: true };
      }
    } catch { /* fall through */ }
    return { config: { ...DEFAULT_CONFIG }, error, usedLastGood: false };
  }
}

export function loadModuleConfigs(confDir?: string): Map<string, ModuleConfig> {
  const dir = confDir || DEFAULT_CONFDIR;
  const configs = new Map<string, ModuleConfig>();

  if (!existsSync(dir)) {
    return configs;
  }

  const files = readdirSync(dir).filter((f) => f.endsWith('.conf'));
  for (const file of files) {
    try {
      const raw = readFileSync(join(dir, file), 'utf-8');
      const parsed = TOML.parse(raw) as Record<string, unknown>;
      for (const [name, config] of Object.entries(parsed)) {
        configs.set(name, config as ModuleConfig);
      }
    } catch {
      // skip bad configs
    }
  }

  return configs;
}

export function generateDefaultConfig(detectedServices: string[]): string {
  const config: Record<string, unknown> = {
    daemon: DEFAULT_CONFIG.daemon,
    api: DEFAULT_CONFIG.api,
    modules: DEFAULT_CONFIG.modules,
    // Written out so the opt-out is discoverable; these are also the defaults
    // when the section is absent.
    cloud: { enabled: true, min_severity: 'medium' },
    update: { auto: true, interval: '6h', min_age: '2h' },
    command_history: { enabled: false },
    // Reporting to shared reputation feeds (PRD 0015). On by default but inert
    // until a key is set: nothing is reported without ABUSEIPDB_API_KEY or the
    // key below, and only corroborated, handshake-verified sources ever are.
    'abuse-reporter': {
      enabled: true,
      mode: 'live',
      destinations: ['abuseipdb'],
      // abuseipdb_api_key = "..."   # prefer the ABUSEIPDB_API_KEY env/secret
    },
  };

  return TOML.stringify(config as any);
}

export function generateModuleConfig(
  moduleName: string,
  defaults: Record<string, unknown> = {},
): string {
  const config: Record<string, unknown> = {
    [moduleName]: {
      enabled: true,
      ...defaults,
    },
  };
  return TOML.stringify(config as any);
}
