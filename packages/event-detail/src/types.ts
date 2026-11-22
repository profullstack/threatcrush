/**
 * The SSH login context an agent attaches to an accepted login
 * (`details.ssh_context` on the bus event, `raw_metadata.evidence.ssh_context`
 * on an uploaded detection). Version 1.
 *
 * Every field is optional except `v`, `at` and `verdict`, so an agent that
 * could not learn something (no journal, no network, an unreadable
 * authorized_keys) still sends what it has, and a reader never assumes more.
 * Older agents send no `ssh_context` at all; readers fall back to the flat
 * evidence fields (`fingerprint`, `key_comment`, `auth_method`, ...).
 *
 * Never carries secret material: the key blob is masked, no private key,
 * no environment.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SourceKind = 'loopback' | 'self' | 'tailscale' | 'private' | 'github-actions' | 'public';

export interface SshKeyContext {
  /** Whether the fingerprint was found in a readable authorized_keys file. */
  found: boolean;
  type?: string;
  fingerprint?: string;
  comment?: string;
  /** The options as written (`restrict`, `command="..."`, `from="..."`). */
  options?: string[];
  command?: string | null;
  from?: string | null;
  restrict?: boolean;
  /** `path:line` of every authorized_keys line carrying this key. */
  files?: string[];
  /** Accounts whose files authorize this key. */
  accounts?: string[];
  /** The authorized_keys line with the key blob masked (`AAAAC3Nz…[masked]`). */
  line_masked?: string;
  /** The same key authorizes root and another account (planted-persistence pattern). */
  in_root_and_user?: boolean;
  /** Comment looks like a dated temporary CI/diagnostic key (`ci-diag-20261120`). */
  suspicious_comment?: boolean;
  /** Listed as an expected CI key by the operator. */
  expected?: boolean;
}

export interface SourceContext {
  ip: string;
  kind: SourceKind;
  rdns?: string | null;
  asn?: number | null;
  as_org?: string | null;
  country?: string | null;
}

export interface FailureContext {
  window_s: number;
  total: number;
  /** Failures from the address that then logged in. */
  same_ip: number;
  /** Failures from any other address. */
  other_ips: number;
  ips?: Array<{ ip: string; count: number }>;
  users?: Array<{ user: string; count: number }>;
  first?: string;
  last?: string;
}

export interface CiDeployContext {
  decision: string;
  repo?: string;
  action?: string;
  command?: string;
  at?: string;
}

export interface SessionContext {
  ci_deploy?: CiDeployContext;
  closed_at?: string;
  duration_s?: number;
  /** Still open when the alert was sent. */
  open?: boolean;
}

export type VerdictLevel = 'expected' | 'likely-ci' | 'internal' | 'review' | 'suspicious';

export interface Verdict {
  level: VerdictLevel;
  severity: Severity;
  summary: string;
  reasons: string[];
}

export interface SshLoginContext {
  v: 1;
  /** When sshd accepted the login (ISO, UTC). */
  at: string;
  host?: string;
  /** The host's UTC offset in minutes at that time (east positive). */
  tz_offset_min?: number;
  /** The host's IANA zone, when known. */
  tz?: string;
  user?: string;
  auth_method?: string;
  port?: number;
  key?: SshKeyContext;
  source?: SourceContext;
  failures?: FailureContext;
  session?: SessionContext;
  verdict: Verdict;
}

/**
 * The common shape of anything the detail view shows: a fleet detection from
 * threatcrush.com, a local daemon event, or a rule-engine detection pushed by
 * the local daemon.
 */
export interface EventLike {
  id: string;
  /** ISO time or epoch ms. */
  at: string | number;
  severity?: string | null;
  title?: string | null;
  message?: string | null;
  description?: string | null;
  rule_id?: string | null;
  module?: string | null;
  source_ip?: string | null;
  username?: string | null;
  /** Server id (fleet) or 'local'. */
  server_id?: string | null;
  /** Display name of the host. */
  host?: string | null;
  /** raw_metadata (fleet) or details (daemon). */
  metadata?: Record<string, unknown> | null;
  status?: string | null;
  occurrences?: number | null;
}
