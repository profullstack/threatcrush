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
  /** Default true: never ban an address an operator logged in from with a key, or holds a live SSH/mosh session from. */
  protect_recent_operators?: boolean;
  /** How long such an address stays protected after it was last seen, e.g. "30d" (default). */
  operator_memory?: string;
  /** Never auto-ban a Googlebot/Bingbot verified by forward-confirmed reverse DNS. Default true. */
  spare_verified_crawlers?: boolean;
  /**
   * Default true. Ban any SSH connection (attempt or successful login) from a
   * Tor exit relay at once for `max_ban`, even in `dry_run` mode. Setting it
   * here wins over the dashboard's org setting; leave it out to follow that.
   */
  block_tor_ssh?: boolean;
  /** Tor exit list source. Default https://check.torproject.org/torbulkexitlist, refreshed hourly. */
  tor_exit_list_url?: string;
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
  /**
   * Default false. `true` runs the property scans and pentests queued on the
   * dashboard (for the linked org only) on this machine.
   */
  runs?: boolean;
  /** Directories a dashboard-queued scan may read. Default none: scans are refused. */
  run_scan_paths?: string[];
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
 * `[update]` — the daemon keeps itself on the latest release (see
 * daemon/workers/auto-update.ts). On by default.
 */
export interface UpdateSection {
  /** Default true. `false` (or THREATCRUSH_AUTO_UPDATE=0) leaves upgrades to you. */
  auto?: boolean;
  /** How often to check, e.g. "6h" (default; at least 15m). Each check adds up to 1h of jitter. */
  interval?: string;
  /** How long a release must have been published before it is taken. Default "2h". */
  min_age?: string;
  /** Default false: stay on the current major version. */
  allow_major?: boolean;
}

/**
 * `[threat_feeds]` — abuse.ch C2 and malware indicators (see
 * daemon/workers/threat-feeds.ts). Detection is on by default; blocking is not.
 */
export interface ThreatFeedsSection {
  /** Default true. `false` stops fetching, matching and blocking. */
  enabled?: boolean;
  /** Default false. Drop egress to listed IPs (needs [remediation] in enforce mode and nftables). */
  block?: boolean;
  /**
   * Default false. Refuse the listed DOMAINS at the local resolver too
   * (dnsmasq or unbound, after `threatcrush feeds resolver install`; needs
   * [remediation] in enforce mode). systemd-resolved cannot do this.
   */
  block_domains?: boolean;
  /** How often to re-fetch, e.g. "1h" (default; at least 15m). */
  refresh?: string;
  /** ThreatFox confidence floor, 0–100. Default 75. */
  min_confidence?: number;
  /** IPs, CIDRs or domains never matched or blocked. */
  allow?: string[];
  /**
   * File holding an abuse.ch Auth-Key (free at auth.abuse.ch). Needed for
   * ThreatFox and URLhaus since abuse.ch retired its keyless exports; without
   * it only Feodo is fetched and the others show as failed. Preferred over
   * `auth_key` so the key stays out of a config file others may read.
   */
  auth_key_file?: string;
  /** The Auth-Key inline. ABUSECH_AUTH_KEY in the environment also works. */
  auth_key?: string;
}

/**
 * `[privileged]` — who can become root, the sudo ledger, and new-country SSH
 * logins (see daemon/workers/privilege-watch.ts). On by default.
 */
export interface PrivilegedSection {
  /** Default true. */
  enabled?: boolean;
  /**
   * authorized_keys additions that are expected: SHA256 fingerprints, or
   * comment globs such as "github-actions-deploy@*". A new key that matches
   * is reported `high`; any other new key is `critical` (pages on-call).
   */
  expected_keys?: string[];
  /** Default true. Alert when a key logs in from an address it never used before. */
  key_login_watch?: boolean;
  /** Default true. Geolocate accepted SSH logins via threatcrush.com/api/geo to spot a new country. */
  geo?: boolean;
}

export interface SshContextSection {
  /** Default true. */
  enabled?: boolean;
  /** Default true. Reverse DNS and Team Cymru ASN/country lookups (DNS) for public source addresses. */
  network_lookups?: boolean;
  /** Default true. Fetch GitHub's Actions runner ranges from api.github.com/meta (cached a day). */
  github_actions_ranges?: boolean;
  /** Fingerprints (SHA256:...) of keys expected to log in from CI: their logins become a quiet info row. */
  expected_keys?: string[];
  /** Syslog identifier the CI forced command logs under. Default "ci-deploy". */
  ci_deploy_tag?: string;
  /** How far back failed attempts count, seconds. Default 600. */
  failure_window_seconds?: number;
  /** How long to wait for the ci-deploy line and session close before sending, ms. Default 5000, max 20000. */
  settle_ms?: number;
}

/**
 * `[command_history]` stores local snapshots of supported interactive-shell
 * history files. Snapshots are private to root and never uploaded.
 */
export interface CommandHistorySection {
  /** Default false because shell history can contain credentials and private work details. */
  enabled?: boolean;
}

/**
 * `[file_integrity]` hashes configured paths locally and reports changes.
 * Keep disabled until an operator selects paths: a baseline scan reads every
 * regular file under those roots and can add noticeable disk I/O.
 */
export interface FileIntegritySection {
  /** Default false. */
  enabled?: boolean;
  /** Absolute files or directories to baseline and monitor. Symlinks are skipped. */
  paths?: string[];
  /** Existing decoy files to watch; any change or removal is critical. */
  canaries?: string[];
  /** Directories where ThreatCrush should create a hidden canary on first baseline. */
  canary_directories?: string[];
  /** Polling interval in seconds, clamped to 60–86400 (default 900). */
  poll_interval_seconds?: number;
  /**
   * Opt-in response when a canary is written or a mass change fires: find the
   * process holding the changed files open for writing (via /proc/<pid>/fd)
   * and send it SIGSTOP (`"stop"`, recommended and reversible with
   * `kill -CONT`) or SIGKILL (`"kill"`). Default `"off"`: alert only. Re-run
   * `threatcrush install-service` after enabling so the unit gets
   * CAP_SYS_PTRACE, which reading other users' /proc/<pid>/fd requires.
   */
  contain_writer?: 'off' | 'stop' | 'kill';
  /** More candidate writers than this is ambiguous and only alerts (default 3, max 20). */
  contain_max_processes?: number;
  /**
   * Executables never signalled, on top of the built-in list (pid 1, the
   * daemon and its parent, kernel threads, sshd, systemd*). An entry ending
   * in `/` covers every executable under that directory.
   */
  never_contain?: string[];
}

/**
 * `[edr]` consumes selected Linux process events from auditd or, optionally,
 * eBPF (via the `bpftrace` CLI). It is disabled by default; with auditd the
 * operator installs the generated, narrowly scoped audit rules.
 */
export interface EdrSection {
  /** Default false. */
  enabled?: boolean;
  /**
   * Event source. `"auditd"` (default) tails the audit log; `"ebpf"` runs
   * bpftrace (needs root, bpftrace and /sys/kernel/btf/vmlinux) and falls back
   * to auditd when it cannot start; `"auto"` picks eBPF when those are present.
   */
  source?: 'auto' | 'auditd' | 'ebpf';
  /** Default `/var/log/audit/audit.log`. */
  audit_log_path?: string;
  /** Account names whose shell or downloader execution is suspicious. */
  web_service_users?: string[];
  /** Directories where executing a binary should raise an alert. */
  temp_exec_paths?: string[];
  /** Audit successful connect/listen syscalls; can create substantial audit volume. Default false. */
  watch_network_syscalls?: boolean;
  /**
   * With `watch_network_syscalls` on the eBPF source, look the remote address
   * of every outbound connection up in the threat feeds and raise a critical
   * event, naming the process, on a hit. Addresses that are not listed are not
   * stored. Default true.
   */
  match_threat_feeds?: boolean;
  /** Seconds to learn known outbound executables before alerting on newly seen ones (default 60). */
  network_baseline_seconds?: number;
  /** Watch sustained high CPU from binaries running in temporary directories. Default true when EDR is enabled. */
  watch_unknown_temp_cpu?: boolean;
  /** Polling frequency in seconds, clamped to 1–60 (default 2). */
  poll_interval_seconds?: number;
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
  /**
   * Where to report. Default `["abuseipdb"]`. `stopforumspam` only receives
   * sources whose evidence includes a form/signup spam event carrying
   * `details.form_spam = { username, email }` (SFS requires both); every other
   * source is skipped for SFS.
   */
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
  /** `[lightning]`: Core Lightning channel-close alerts. On when a cln.log is found. */
  lightning?: { enabled?: boolean; log_paths?: string[] };
  /**
   * `[docker_logs]`: Postgres auth failures from Docker container logs. On when the Docker socket exists.
   * `app_detections` (default true): containers whose name matches `app_name_pattern` (regex, default
   * every container) may report an attacker by printing `THREATCRUSH_DETECTION {"v":1,"ip":…}`.
   */
  docker_logs?: {
    enabled?: boolean;
    socket?: string;
    name_pattern?: string;
    image_pattern?: string;
    poll_seconds?: number;
    app_detections?: boolean;
    app_name_pattern?: string;
  };
  /** `[postgres_shell]`: a shell or LOLBin under a postgres process (COPY FROM PROGRAM). On by default on Linux. */
  postgres_shell?: { enabled?: boolean; poll_seconds?: number; kill?: boolean; allow_cmdline?: string[] };
  /** `[login_watch]`: suspicious successful SSH logins (Tor, privileged user from an untrusted address, new network). */
  login_watch?: {
    enabled?: boolean;
    sensitive_users?: string[];
    sensitive_groups?: string[];
    trusted_login_cidrs?: string[];
    first_seen?: boolean;
    auto_response?: boolean;
  };
  /**
   * `[ssh_context]`: what every accepted SSH login carries to the dashboard
   * and desktop app: the authorized_keys line (blob masked) and its options,
   * the source address's reverse DNS / ASN / country / GitHub Actions or
   * Tailscale membership, the failed attempts before it, the matching
   * ci-deploy journal line and session length, and a verdict. On by default.
   */
  ssh_context?: SshContextSection;
  detection?: DetectionSection;
  cloud?: CloudSection;
  watchdog?: WatchdogSection;
  update?: UpdateSection;
  threat_feeds?: ThreatFeedsSection;
  privileged?: PrivilegedSection;
  command_history?: CommandHistorySection;
  file_integrity?: FileIntegritySection;
  edr?: EdrSection;
  /** How long the events table keeps history; see core/state.ts pruneEvents. */
  storage?: {
    /** e.g. "14d" (default). Older events are deleted. */
    event_retention?: string;
    /** Hard cap on stored events (default 250,000); the oldest go first. */
    max_events?: number;
  };
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
