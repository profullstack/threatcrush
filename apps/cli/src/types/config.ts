export interface DaemonConfig {
  pid_file: string;
  log_level: 'debug' | 'info' | 'warn' | 'error';
  log_file: string;
  state_db: string;
}

export interface ApiConfig {
  enabled: boolean;
  bind: string;
  tls: boolean;
}

export interface AlertChannelConfig {
  enabled: boolean;
  [key: string]: unknown;
}

export interface ModulesConfig {
  auto_update: boolean;
  update_interval: string;
  module_dir: string;
  config_dir: string;
}

/**
 * `[remediation]` — automatic defence. Present in the type because `loadConfig`
 * used to drop the whole section on the floor, so nothing an operator wrote
 * here ever reached the daemon.
 */
export interface RemediationSection {
  enabled?: boolean;
  /** `enforce` (default) or `dry_run`. `dry_run` also accepted as a boolean. */
  mode?: 'enforce' | 'dry_run';
  dry_run?: boolean;
  backend?: 'auto' | 'fail2ban' | 'nftables' | 'iptables' | 'dry-run';
  min_severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Ceiling on the escalating ladder, e.g. "24h". */
  max_ban?: string;
  /** How long an offence counts towards escalation, e.g. "24h". */
  strike_memory?: string;
  /** Extra never-block addresses or CIDRs, on top of the built-in set. */
  protected?: string[];
  /** Historical spelling of `protected`. */
  allowlist?: string[];
  protect_current_ssh_client?: boolean;
  /** Never auto-ban a Googlebot/Bingbot verified by forward-confirmed reverse DNS. Default true. */
  spare_verified_crawlers?: boolean;
  /** Historical spelling, seconds. Superseded by the Fibonacci ladder. */
  default_ttl_seconds?: number;
}

/**
 * `[detection]` — web attack detection on access logs (OWASP CRS, PL1).
 */
export interface DetectionSection {
  /** Inbound anomaly score at which a request is an attack. CRS default: 5 (one CRITICAL rule). */
  anomaly_threshold?: number;
  /** CRS rule ids to switch off, as SecRuleRemoveById would, e.g. [942550]. */
  exclude_rules?: number[];
}

export interface ThreatCrushConfig {
  daemon: DaemonConfig;
  api: ApiConfig;
  alerts: Record<string, AlertChannelConfig>;
  modules: ModulesConfig;
  remediation?: RemediationSection;
  detection?: DetectionSection;
  license?: {
    key_file?: string;
    key?: string;
  };
}

export interface ModuleManifest {
  module: {
    name: string;
    version: string;
    description: string;
    author: string;
    license: string;
    homepage?: string;
    pricing?: {
      type: 'free' | 'paid' | 'freemium';
      price_usd?: number;
    };
    requirements?: {
      threatcrush?: string;
      os?: string[];
      capabilities?: string[];
    };
    config?: {
      defaults?: Record<string, unknown>;
    };
  };
}

export interface ModuleConfig {
  enabled: boolean;
  [key: string]: unknown;
}
