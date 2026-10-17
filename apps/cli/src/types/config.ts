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
  /** The first offence's ban, e.g. "5m"; each later offence doubles it. */
  first_ban?: string;
  /** Ceiling on the escalating ladder, e.g. "7d". */
  max_ban?: string;
  /** How long an offence counts towards escalation, e.g. "30d". */
  strike_memory?: string;
  /** Extra never-block addresses or CIDRs, on top of the built-in set. */
  protected?: string[];
  /** Historical spelling of `protected`. */
  allowlist?: string[];
  protect_current_ssh_client?: boolean;
  /** Never auto-ban a Googlebot/Bingbot verified by forward-confirmed reverse DNS. Default true. */
  spare_verified_crawlers?: boolean;
  /** Historical spelling, seconds. Superseded by the doubling ladder. */
  default_ttl_seconds?: number;
}

/**
 * `[detection]` — web attack detection on access logs (OWASP CRS, PL1).
 */
export interface DetectionSection {
  /** Inbound anomaly score at which a request is an attack. CRS default: 5 (one CRITICAL rule). */
  anomaly_threshold?: number;
  /**
   * Rule ids to switch off, as SecRuleRemoveById would: CRS ids, e.g. [942550],
   * or ThreatCrush's own (10001, an OS file named by the request path).
   * Added to the rules ThreatCrush already leaves off by default.
   */
  exclude_rules?: number[];
  /**
   * Rules ThreatCrush leaves off by default to switch back on, e.g. [941130].
   * Cannot undo `exclude_rules`: a rule listed in both stays off.
   */
  include_rules?: number[];
}

/**
 * `[cloud]` — reporting to the ThreatCrush dashboard. Only does anything once
 * the machine is logged in (`threatcrush login`) and linked
 * (`threatcrush servers link`).
 */
export interface CloudSection {
  /** Default true. `false` keeps detections, findings and bans on this machine. */
  enabled?: boolean;
  /** Lowest detection severity uploaded. Default `medium`. */
  min_severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

/**
 * `[watchdog]` — keep every attack on disk for triage (`threatcrush watchdog`).
 */
export interface WatchdogSection {
  /** Default true. `false` stops the daemon writing the attack log. */
  enabled?: boolean;
  /** Default `<state dir>/watchdog` (/var/lib/threatcrush/watchdog as root). */
  dir?: string;
}

/**
 * `[abuse-reporter]` (PRD 0015) — report confirmed attack sources to shared
 * reputation feeds (AbuseIPDB, StopForumSpam) so compromised hosts get cleaned
 * up, not merely blocked here.
 *
 * This is the one section that makes an **outbound public statement in the
 * operator's name** about someone else's infrastructure, so every default here
 * is conservative and the evidence bar below is not optional. Nothing is ever
 * sent *at* a source — reporting is not retaliation (PRD 0015 Non-Goals).
 *
 * On by default in spirit, but inert until an API key is present: with no
 * `abuseipdb_api_key` (or `ABUSEIPDB_API_KEY`) the reporter loads, logs once and
 * reports nothing — exactly as cloud sync does nothing until the box is linked.
 */
export interface AbuseReporterSection {
  /** Default true. The reporter still sends nothing until a destination key is set. */
  enabled?: boolean;
  /**
   * `live` submits reports; `dry_run` writes the same audit entry marked
   * `would_report` and sends nothing. `dry_run` also accepted as a boolean.
   */
  mode?: 'live' | 'dry_run';
  dry_run?: boolean;
  /** Where to report. Default `["abuseipdb"]`. */
  destinations?: Array<'abuseipdb' | 'stopforumspam'>;
  /** AbuseIPDB key. Prefer the `ABUSEIPDB_API_KEY` env/secret over writing it here. */
  abuseipdb_api_key?: string;
  /** StopForumSpam key. Prefer `STOPFORUMSPAM_API_KEY`. */
  stopforumspam_api_key?: string;
  /**
   * R1: how many distinct corroborating signals a source needs before it is
   * reportable. A single ambiguous hit is never enough. Default 2.
   */
  min_corroborating_signals?: number;
  /**
   * R5: how long a newly-seen source is held before its first report, e.g.
   * "1h", so a single burst does not immediately become a public record.
   */
  cooling_off?: string;
  /** R3: extra never-report addresses/CIDRs, on top of the built-in unsafe set. */
  never_report?: string[];
  /** R8: strip hostnames, paths and credentials from report evidence. Default true; forced true. */
  redact_evidence?: boolean;
  /** R4: global ceiling on reports per hour, so a misconfiguration cannot flood. Default 50. */
  max_reports_per_hour?: number;
  /** R4: a single source is reported at most this often per day. Default 1. */
  max_reports_per_source_per_day?: number;
}

export interface ThreatCrushConfig {
  daemon: DaemonConfig;
  api: ApiConfig;
  alerts: Record<string, AlertChannelConfig>;
  modules: ModulesConfig;
  remediation?: RemediationSection;
  detection?: DetectionSection;
  cloud?: CloudSection;
  watchdog?: WatchdogSection;
  abuse_reporter?: AbuseReporterSection;
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
