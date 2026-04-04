import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
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

export function loadConfig(configPath?: string): ThreatCrushConfig {
  const path = configPath || DEFAULT_CONFIG_PATH;
  if (!existsSync(path)) {
    return { ...DEFAULT_CONFIG };
  }

  try {
    const raw = readFileSync(path, 'utf-8');
    const parsed = TOML.parse(raw) as unknown as Partial<ThreatCrushConfig>;
    return {
      daemon: { ...DEFAULT_CONFIG.daemon, ...parsed.daemon },
      api: { ...DEFAULT_CONFIG.api, ...parsed.api },
      alerts: parsed.alerts || {},
      modules: { ...DEFAULT_CONFIG.modules, ...parsed.modules },
      license: parsed.license,
    };
  } catch {
    return { ...DEFAULT_CONFIG };
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
