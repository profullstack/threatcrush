import { execFileSync } from 'node:child_process';
import { isIP } from 'node:net';
import { keyFingerprint, parseAuthorizedKeys, parseDenyList, type AuthorizedKey } from '../host-scan/parsers.js';
import type { GatheredKeyFile, KeyRow, LoginRow, Snapshot } from './types.js';

export const FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

/** `SHA256:abc=` and `SHA256:abc` are the same key; OpenSSH prints the unpadded form. */
export function normaliseFingerprint(fp: string): string {
  return fp.trim().replace(/=+$/, '');
}

/**
 * Turn `respond key` arguments into fingerprints. Each is a `SHA256:` fingerprint
 * or a file: public key line(s), an authorized_keys file, or a private key (whose
 * public half `ssh-keygen -l` reads without the passphrase). Private keys never
 * leave this machine: only the fingerprint goes to remote hosts.
 */
export function resolveKeyTargets(
  args: string[],
  io: {
    readFile: (path: string) => string;
    keygenFingerprint?: (path: string) => string | null;
  },
): { fingerprints: string[]; errors: string[] } {
  const fps = new Set<string>();
  const errors: string[] = [];
  const keygen = io.keygenFingerprint ?? keygenFingerprint;
  for (const arg of args) {
    if (/^SHA256:/.test(arg)) {
      const fp = normaliseFingerprint(arg);
      if (FINGERPRINT_RE.test(fp)) fps.add(fp);
      else errors.push(`not a SHA256 fingerprint: ${arg}`);
      continue;
    }
    let text: string;
    try {
      text = io.readFile(arg);
    } catch (err) {
      errors.push(`cannot read ${arg}: ${(err as Error).message}`);
      continue;
    }
    if (/PRIVATE KEY-----/.test(text)) {
      const fp = keygen(arg);
      if (fp) fps.add(fp);
      else errors.push(`${arg}: private key, but ssh-keygen could not read its public half`);
      continue;
    }
    const deny = parseDenyList(text);
    const before = fps.size;
    for (const fp of deny.fingerprints) fps.add(normaliseFingerprint(fp));
    for (const blob of deny.blobs) {
      const fp = keyFingerprint(blob);
      if (fp) fps.add(fp);
    }
    if (fps.size === before) errors.push(`${arg}: no public key or fingerprint found`);
  }
  return { fingerprints: [...fps], errors };
}

function keygenFingerprint(path: string): string | null {
  try {
    const out = execFileSync('ssh-keygen', ['-l', '-E', 'sha256', '-f', path], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
    const fp = out.trim().split(/\s+/)[1];
    return fp && FINGERPRINT_RE.test(fp) ? fp : null;
  } catch {
    return null;
  }
}

/** Human-readable restrictions of a key: `command="..."`, `from="..."`, `restrict`. */
export function keyRestrictions(key: AuthorizedKey): string[] {
  const out: string[] = [];
  if (key.command !== null) out.push(`command="${key.command}"`);
  if (key.from !== null) out.push(`from="${key.from}"`);
  if (key.restrict) out.push('restrict');
  return out;
}

/** Every key in every gathered file, with the line it sits on. */
export function keyRows(files: GatheredKeyFile[], lastUsed: Map<string, number> = new Map()): Array<KeyRow & { blob: string; parsed: AuthorizedKey }> {
  const rows: Array<KeyRow & { blob: string; parsed: AuthorizedKey }> = [];
  for (const f of files) {
    for (const k of parseAuthorizedKeys(f.content, f.path)) {
      rows.push({
        user: f.user,
        file: f.path,
        line: k.line,
        live: f.live,
        type: k.type,
        fingerprint: k.fingerprint,
        comment: k.comment,
        restrictions: keyRestrictions(k),
        lastUsed: k.fingerprint ? lastUsed.get(k.fingerprint) ?? null : null,
        flags: [],
        blob: k.blob,
        parsed: k,
      });
    }
  }
  return rows;
}

const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** Timestamp of a log line: `journalctl -o short-unix`, ISO 8601 (rsyslog), or classic syslog. */
function lineTime(line: string, now: Date): number | null {
  let m = /^(\d{9,}(?:\.\d+)?)\s/.exec(line);
  if (m) return Math.round(Number(m[1]) * 1000);
  m = /^(\d{4}-\d\d-\d\dT\S+)\s/.exec(line);
  if (m) {
    const t = Date.parse(m[1]);
    return Number.isNaN(t) ? null : t;
  }
  m = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s/.exec(line);
  if (m && m[1] in MONTHS) {
    const d = new Date(now.getFullYear(), MONTHS[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    // A December line read in January belongs to last year.
    if (d.getTime() > now.getTime() + 86400000) d.setFullYear(d.getFullYear() - 1);
    return d.getTime();
  }
  return null;
}

/** `Accepted <method> for <user> from <ip> port <n> ssh2[: <TYPE> SHA256:...]` lines. */
export function parseAcceptedLogins(text: string, now = new Date()): Array<LoginRow & { ip: string; port: number }> {
  const out: Array<LoginRow & { ip: string; port: number }> = [];
  for (const line of text.split('\n')) {
    const m = /Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: [^\s:]+)?(?:: \S+ (SHA256:\S+))?/.exec(line);
    if (!m || !isIP(m[3])) continue;
    const at = lineTime(line, now);
    if (at === null) continue;
    out.push({ at, method: m[1], user: m[2], ip: m[3], port: Number(m[4]), fingerprint: m[5] ? normaliseFingerprint(m[5]) : null });
  }
  return out;
}

/** Failed password / invalid user attempts per source address. */
export function countFailedAttempts(text: string, ips: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const ip of ips) counts[ip] = 0;
  for (const line of text.split('\n')) {
    const m = /(?:Failed \S+ for (?:invalid user )?\S+|Invalid user \S*) from (\S+)/.exec(line);
    if (m && m[1] in counts) counts[m[1]]++;
  }
  return counts;
}

/** Newest login time per key fingerprint. */
export function lastUsedByFingerprint(logins: LoginRow[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const l of logins) {
    if (!l.fingerprint) continue;
    if (l.at > (out.get(l.fingerprint) ?? 0)) out.set(l.fingerprint, l.at);
  }
  return out;
}

/**
 * The key the session running this logged in with: the `Accepted publickey`
 * line whose client address and port match SSH_CONNECTION.
 */
export function sessionKeyFingerprint(sshConnection: string | null, logins: Array<LoginRow & { ip: string; port: number }>): string | null {
  if (!sshConnection) return null;
  const [ip, port] = sshConnection.trim().split(/\s+/);
  const hit = logins.filter((l) => l.ip === ip && String(l.port) === port && l.fingerprint).sort((a, b) => b.at - a.at)[0];
  return hit?.fingerprint ?? null;
}

export interface LockoutVerdict {
  /** Removing the keys would leave the invoking user with no key that gives a shell. */
  lockout: boolean;
  /** The key this very session logged in with is among those being removed. */
  sessionKeyRemoved: boolean;
  /** Keys the invoking user still has afterwards (shell-capable ones). */
  remaining: number;
  /** Other accounts left with no keys at all. */
  othersEmptied: string[];
  reason?: string;
}

/**
 * The guard against the 2026-11-20 mistake: removing the only trusted key
 * before a replacement was installed locked everyone out of the fleet.
 *
 * A `command=` key does not count as access: it runs one command, not a
 * shell, so it cannot be used to repair anything. Neither does a `restrict`
 * key (no pty: a tunnel or automation key, not a way back in for a human).
 * Erring towards refusing is the point; `--allow-lockout` overrides.
 */
export function lockoutCheck(
  rows: Array<Pick<KeyRow, 'user' | 'live' | 'fingerprint'> & { blob: string; parsed: Pick<AuthorizedKey, 'command' | 'restrict'> }>,
  removeFps: Set<string>,
  invoker: string,
  sessionFp: string | null,
): LockoutVerdict {
  const live = rows.filter((r) => r.live);
  const removed = (r: { fingerprint: string | null }) => r.fingerprint !== null && removeFps.has(r.fingerprint);
  const mine = live.filter((r) => r.user === invoker);
  const minesRemoved = mine.filter(removed);
  const remaining = mine.filter((r) => !removed(r) && r.parsed.command === null && !r.parsed.restrict);
  const sessionKeyRemoved = sessionFp !== null && removeFps.has(sessionFp);

  const users = new Set(live.map((r) => r.user).filter((u): u is string => u !== null && u !== invoker));
  const othersEmptied = [...users].filter((u) => {
    const theirs = live.filter((r) => r.user === u);
    return theirs.some(removed) && theirs.every(removed);
  }).sort();

  let lockout = false;
  let reason: string | undefined;
  if ((minesRemoved.length > 0 || sessionKeyRemoved) && remaining.length === 0) {
    lockout = true;
    reason = sessionKeyRemoved
      ? `the key this session logged in with (${sessionFp}) is the only key that gives ${invoker} a shell`
      : `${invoker} would have no key left that gives a shell`;
  }
  return { lockout, sessionKeyRemoved, remaining: remaining.length, othersEmptied, reason };
}

/** What to do before removing a key you still depend on. */
export function replacementHelp(user: string, host: string): string[] {
  return [
    'Install a replacement key FIRST, prove it works, then re-run:',
    '  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -C "<you>@<laptop> $(date +%F)"   # on YOUR machine',
    `  ssh-copy-id -i ~/.ssh/id_ed25519_new.pub ${user}@${host}`,
    `  ssh -i ~/.ssh/id_ed25519_new -o IdentitiesOnly=yes ${user}@${host} true   # must succeed`,
    'or pass --allow-lockout if you have console access to this box.',
  ];
}

/**
 * Flags for `respond keys-audit`: unrestricted, duplicate across accounts,
 * unused inside the window, deploy keys, stale copies.
 */
export function auditFlags(
  rows: Array<KeyRow & { blob: string }>,
  opts: { now: number; unusedDays: number; journalAvailable: boolean },
): KeyRow[] {
  const usersByBlob = new Map<string, Set<string>>();
  for (const r of rows) {
    if (!r.live) continue;
    const set = usersByBlob.get(r.blob) ?? new Set<string>();
    set.add(r.user ?? '?');
    usersByBlob.set(r.blob, set);
  }
  const cutoff = opts.now - opts.unusedDays * 86400000;
  return rows.map((r) => {
    const flags: string[] = [];
    if (!r.live) flags.push('stale copy: sshd does not read this file; delete it');
    const isCommand = r.restrictions.some((x) => x.startsWith('command='));
    const isFrom = r.restrictions.some((x) => x.startsWith('from='));
    if (!isCommand && !isFrom && !r.restrictions.includes('restrict')) flags.push('unrestricted: any source, any command');
    const users = usersByBlob.get(r.blob);
    if (r.live && users && users.size > 1) flags.push(`duplicate: also authorized for ${[...users].filter((u) => u !== (r.user ?? '?')).join(', ')}`);
    if (opts.journalAvailable && r.live && (r.lastUsed === null || r.lastUsed < cutoff)) flags.push(`unused in ${opts.unusedDays} days`);
    if (isCommand) flags.push('deploy key (command=): treat as a secret; rotate if CI secrets may have leaked');
    return { ...publicRow(r), flags };
  });
}

/** Strip analysis-only fields before a row goes into a report. */
export function publicRow(r: KeyRow & { blob?: string; parsed?: unknown }): KeyRow {
  const { blob: _b, parsed: _p, ...row } = r;
  return row;
}

export function snapshotLogins(snap: Snapshot): Array<LoginRow & { ip: string; port: number }> {
  return parseAcceptedLogins(snap.journal);
}
