import type { PasswdEntry } from '../host-scan/parsers.js';

export type RespondSub = 'ip' | 'key' | 'sshd' | 'keys-audit';

/** What the operator asked for, already validated. Travels to remote hosts as argv. */
export interface RespondRequest {
  sub: RespondSub;
  apply: boolean;
  /** `respond ip` */
  ips?: string[];
  ttl?: string;
  /** `respond key`: SHA256 fingerprints, normalised (no trailing `=`). */
  fingerprints?: string[];
  allowLockout?: boolean;
  /** Extra directories to search for private-key copies (default /root /home). */
  searchRoots?: string[];
  /** `respond sshd` */
  lockdown?: boolean;
  allowRootLocalhost?: boolean;
}

export interface GatheredKeyFile {
  /** Account the file belongs to (from AuthorizedKeysFile expansion or the home it sits in). */
  user: string | null;
  path: string;
  /** True when sshd reads it (an AuthorizedKeysFile expansion); false for a stale copy. */
  live: boolean;
  content: string;
}

/** Everything a respond run reads from one host. Gathered by one POSIX script, locally or over ssh. */
export interface Snapshot {
  hostname: string;
  uid: number;
  /** The human behind this run: SUDO_USER, else the login user. */
  user: string;
  /** `client_ip client_port server_ip server_port` of the session running this, if any. */
  sshConnection: string | null;
  passwd: PasswdEntry[];
  keyFiles: GatheredKeyFile[];
  /** Private-key files found on disk and the fingerprint of their public half. */
  privateKeys: Array<{ path: string; fingerprint: string | null }>;
  ss: string;
  journal: string;
  gateways: string[];
  sshd: {
    binary: string | null;
    /** `sshd -T` with no connection spec (empty when not root or sshd is missing). */
    dumpT: string;
    mainConfig: string;
    dropinDir: string;
    /** Every *.conf in the drop-in directory, name to content. */
    dropins: Record<string, string>;
    /** Current content of the two files lockdown writes; null when absent. */
    existing: Record<string, string | null>;
    /** `sshd -T -C user=root,host=x,addr=1.2.3.4` */
    effectiveRemote: string;
    /** `sshd -T -C user=root,host=localhost,addr=127.0.0.1` */
    effectiveLocal: string;
  };
  errors: string[];
}

export type ActionStatus = 'planned' | 'done' | 'failed' | 'refused' | 'needs-root';

/** A concrete step the executor knows how to perform. No analysis happens at apply time. */
export type ActionOp =
  | { op: 'kill'; pids: number[] }
  | { op: 'ss-kill'; ip: string }
  | { op: 'ban'; ip: string; ttl: string }
  | { op: 'strip-key'; file: string; blobs: string[] }
  | { op: 'rm'; file: string }
  | { op: 'shred'; file: string }
  | {
      op: 'sshd-lockdown';
      dir: string;
      files: Array<{ name: string; content: string }>;
      /** What to put back when `sshd -t` fails (null = remove). */
      restore: Array<{ name: string; content: string | null }>;
    };

export interface Action {
  id: string;
  kind: ActionOp['op'];
  /** One line a human reads: what and where. */
  summary: string;
  status: ActionStatus;
  message?: string;
  op: ActionOp;
}

export interface KeyRow {
  user: string | null;
  file: string;
  line: number;
  live: boolean;
  type: string;
  fingerprint: string | null;
  comment: string;
  restrictions: string[];
  /** ms since epoch of the newest `Accepted publickey` for this fingerprint, if any. */
  lastUsed: number | null;
  flags: string[];
}

export interface LoginRow {
  at: number;
  user: string;
  method: string;
  fingerprint: string | null;
}

export interface ConnRow {
  local: string;
  peer: string;
  processes: Array<{ name: string; pid: number }>;
}

export interface Report {
  host: string;
  hostname: string;
  sub: RespondSub;
  apply: boolean;
  root: boolean;
  /** How the host was reached: this machine, a remote threatcrush, or the streamed script. */
  via: 'local' | 'threatcrush' | 'script';
  actions: Action[];
  warnings: string[];
  /** Actions that need root, listed when running read-only without it. */
  needsRoot: string[];
  connections?: Array<ConnRow & { ip: string }>;
  logins?: Array<LoginRow & { ip: string }>;
  failedAttempts?: Record<string, number>;
  keys?: KeyRow[];
  privateKeys?: Array<{ path: string; fingerprint: string | null }>;
  staleFiles?: string[];
  effectiveBefore?: Record<string, string>;
  effectiveAfter?: Record<string, string>;
  /** Commands to install a replacement key, printed when the lockout guard refuses. */
  replacementHelp?: string[];
  error?: string;
}
