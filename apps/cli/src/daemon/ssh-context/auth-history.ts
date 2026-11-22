import type { FailureContext } from '@threatcrush/event-detail';

/**
 * The last hour of sshd authentication outcomes, from the bus's raw `sshd`
 * lines (every sshd line that names a peer, from auth.log or the journal), so
 * an accepted login can say what came before it: how many failures, from
 * which addresses and users, and whether they came from the address that then
 * got in. Also remembers session closes, for the session length.
 *
 * Bounded: at most MAX_ENTRIES lines and one hour, whichever is smaller.
 */

export interface SshdLineLike {
  timestamp: Date;
  message: string;
  ip: string;
}

type Kind = 'failed' | 'invalid' | 'preauth-close';

interface Failure { at: number; ip: string; user: string; kind: Kind; port?: number }
interface Close { at: number; ip: string; port: number; user?: string }

const MAX_ENTRIES = 20_000;
const KEEP_MS = 60 * 60 * 1000;
/** A "Failed password for invalid user X" right after "Invalid user X" is the same attempt. */
const SAME_ATTEMPT_MS = 10_000;

/** What one sshd message says about authentication, or null. Pure. */
export function classifySshdMessage(message: string): { kind: Kind | 'close'; user?: string; port?: number } | null {
  let m = /^Failed (?:password|publickey|none|keyboard-interactive\/pam|keyboard-interactive|hostbased) for (?:invalid user )?(\S+) from \S+ port (\d+)/.exec(message);
  if (m) return { kind: 'failed', user: m[1], port: Number(m[2]) };
  m = /^Invalid user (\S*) from \S+(?: port (\d+))?/.exec(message);
  if (m) return { kind: 'invalid', user: m[1] || '(empty)', port: m[2] ? Number(m[2]) : undefined };
  m = /^(?:Connection closed by|Disconnected from) (?:authenticating|invalid) user (\S+) \S+ port (\d+)/.exec(message);
  if (m) return { kind: 'preauth-close', user: m[1], port: Number(m[2]) };
  m = /^Disconnected from user (\S+) \S+ port (\d+)/.exec(message);
  if (m) return { kind: 'close', user: m[1], port: Number(m[2]) };
  m = /^Received disconnect from \S+ port (\d+):\d+: .*disconnected by user/i.exec(message);
  if (m && !/\[preauth\]/.test(message)) return { kind: 'close', port: Number(m[1]) };
  return null;
}

export class SshAuthHistory {
  private failures: Failure[] = [];
  private closes: Close[] = [];
  private seen = new Map<string, number>();

  constructor(private readonly now: () => number = Date.now) {}

  record(line: SshdLineLike): void {
    const at = line.timestamp instanceof Date ? line.timestamp.getTime() : Date.now();
    if (Number.isNaN(at)) return;
    // auth.log and the journal can both deliver the same line.
    const key = `${at}|${line.message}`;
    if (this.seen.has(key)) return;
    this.seen.set(key, at);
    const c = classifySshdMessage(line.message);
    if (!c) return;
    if (c.kind === 'close') {
      if (c.port) this.closes.push({ at, ip: line.ip, port: c.port, user: c.user });
    } else {
      const user = c.user ?? 'unknown';
      // One connection logs up to three lines for one attempt ("Invalid user",
      // "Failed password for invalid user", "Connection closed by invalid user
      // ... [preauth]"), all with the client's port. Every "Failed" line is an
      // attempt (several per connection, up to MaxAuthTries); the other two
      // count only when that connection logged nothing else.
      const same: Failure[] = [];
      if (c.port !== undefined) {
        for (let i = this.failures.length - 1; i >= 0; i--) {
          const f = this.failures[i];
          if (f.at < at - SAME_ATTEMPT_MS) break;
          if (f.ip === line.ip && f.port === c.port) same.push(f);
        }
      }
      if (c.kind === 'failed') {
        const placeholder = same.find((f) => f.kind !== 'failed');
        if (placeholder) { placeholder.kind = 'failed'; placeholder.user = user; }
        else this.failures.push({ at, ip: line.ip, user, kind: c.kind, port: c.port });
      } else if (same.length === 0) {
        this.failures.push({ at, ip: line.ip, user, kind: c.kind, port: c.port });
      }
    }
    this.prune();
  }

  private prune(): void {
    const cutoff = this.now() - KEEP_MS;
    if (this.failures.length > MAX_ENTRIES) this.failures.splice(0, this.failures.length - MAX_ENTRIES);
    if (this.closes.length > MAX_ENTRIES) this.closes.splice(0, this.closes.length - MAX_ENTRIES);
    while (this.failures.length && this.failures[0].at < cutoff) this.failures.shift();
    while (this.closes.length && this.closes[0].at < cutoff) this.closes.shift();
    if (this.seen.size > MAX_ENTRIES) {
      // Insertion order: the first half is the oldest.
      let drop = this.seen.size - MAX_ENTRIES / 2;
      for (const k of this.seen.keys()) { if (drop-- <= 0) break; this.seen.delete(k); }
    }
  }

  /** Failures in the `windowS` seconds up to `atMs`, grouped, relative to the address that logged in. */
  failuresBefore(atMs: number, ip: string, windowS = 600): FailureContext {
    const from = atMs - windowS * 1000;
    const hits = this.failures.filter((f) => f.at >= from && f.at <= atMs + 1000);
    const byIp = new Map<string, number>();
    const byUser = new Map<string, number>();
    for (const f of hits) {
      byIp.set(f.ip, (byIp.get(f.ip) ?? 0) + 1);
      byUser.set(f.user, (byUser.get(f.user) ?? 0) + 1);
    }
    const sameIp = byIp.get(ip) ?? 0;
    const top = <K extends string>(m: Map<string, number>, k: K) =>
      [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([v, count]) => ({ [k]: v, count }) as { [P in K]: string } & { count: number });
    return {
      window_s: windowS,
      total: hits.length,
      same_ip: sameIp,
      other_ips: hits.length - sameIp,
      ...(hits.length ? {
        ips: top(byIp, 'ip'),
        users: top(byUser, 'user'),
        first: new Date(Math.min(...hits.map((h) => h.at))).toISOString(),
        last: new Date(Math.max(...hits.map((h) => h.at))).toISOString(),
      } : {}),
    };
  }

  /** When the session from `ip`:`port` closed, if it has. */
  closeOf(ip: string, port: number | undefined, afterMs: number): number | null {
    if (!port) return null;
    const c = this.closes.find((x) => x.ip === ip && x.port === port && x.at >= afterMs - 1000);
    return c ? c.at : null;
  }
}
