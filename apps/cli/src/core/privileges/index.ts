/**
 * Who can become root on this box, and how that changes (issue #305,
 * PRD 0019 R3). PRD 0007 covers the SSH side of a compromise; this is what an
 * intruder does next to keep it: add a uid-0 account, join the sudo group,
 * drop a NOPASSWD rule into sudoers.d, or append a key to authorized_keys.
 *
 * Everything here is a pure function of file contents so it can be tested
 * without root; the daemon worker does the reading.
 */

import { createHash } from 'node:crypto';
import type { EventSeverity } from '../../types/events.js';

export interface Account { name: string; uid: number; home: string; shell: string }

/** Groups whose members can run anything as root on common distributions. */
export const ADMIN_GROUPS = ['sudo', 'wheel', 'admin'];

export function parseAccounts(text: string): Account[] {
  const out: Account[] = [];
  for (const line of text.split('\n')) {
    const f = line.split(':');
    if (f.length < 7 || line.startsWith('#')) continue;
    const uid = Number(f[2]);
    if (!f[0] || !Number.isInteger(uid)) continue;
    out.push({ name: f[0], uid, home: f[5], shell: f[6].trim() });
  }
  return out;
}

/** Explicit members of the admin groups, by group. */
export function parseAdminGroups(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of text.split('\n')) {
    const f = line.split(':');
    if (f.length < 4 || !ADMIN_GROUPS.includes(f[0])) continue;
    out[f[0]] = f[3].trim().split(',').map((m) => m.trim()).filter(Boolean).sort();
  }
  return out;
}

/** A shell someone can log in with; system accounts use nologin/false. */
export function canLogIn(account: Account): boolean {
  return !/(nologin|\/false|\/sync|\/shutdown|\/halt)$/.test(account.shell);
}

/**
 * The rules of a sudoers file: comments and blank lines dropped, continuation
 * lines joined, whitespace collapsed. `#include`/`@include` are directives,
 * not comments, and are kept.
 */
export function sudoersRules(text: string): string[] {
  const joined = text.replace(/\\\n/g, ' ');
  const rules: string[] = [];
  for (const raw of joined.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('#') && !/^#include(dir)?\s/.test(line)) continue;
    rules.push(line.replace(/\s+/g, ' '));
  }
  return rules;
}

/**
 * Whether sudo reads this file from an includedir: it skips names ending in
 * `~` or containing a `.` (editor backups, package leftovers), and so do we.
 */
export function sudoReadsIncluded(name: string): boolean {
  return !name.endsWith('~') && !name.includes('.');
}

export interface AuthorizedKey { fingerprint: string; type: string; comment: string }

/** `SHA256:<base64, no padding>` of the key blob, as `ssh-keygen -l` prints it. */
export function keyFingerprint(blobBase64: string): string | null {
  if (!/^[A-Za-z0-9+/]+=*$/.test(blobBase64)) return null;
  const digest = createHash('sha256').update(Buffer.from(blobBase64, 'base64')).digest('base64');
  return `SHA256:${digest.replace(/=+$/, '')}`;
}

/**
 * Keys in an authorized_keys file. Each line is `[options] type blob
 * [comment]`; options may contain quoted spaces, so the key type is found
 * rather than assumed to be the first field.
 */
export function parseAuthorizedKeys(text: string): AuthorizedKey[] {
  const out: AuthorizedKey[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /(?:^|\s)((?:ssh|ecdsa|sk)-[\w@.-]+)\s+([A-Za-z0-9+/]+=*)(?:\s+(.*))?$/.exec(line);
    if (!m) continue;
    const fingerprint = keyFingerprint(m[2]);
    if (fingerprint) out.push({ fingerprint, type: m[1], comment: (m[3] ?? '').trim() });
  }
  return out;
}

export interface PrivilegeSnapshot {
  taken_at: string;
  uid0: string[];
  admin_groups: Record<string, string[]>;
  /** Rules per sudoers file path. */
  sudoers: Record<string, string[]>;
  /** Keys per account, by fingerprint. */
  keys: Record<string, Record<string, { type: string; comment: string }>>;
  /** Files that exist but could not be read (not root, permissions). */
  unreadable: string[];
}

export interface SnapshotIO {
  readFile(path: string): string | null;
  /** Entry names, or null when the directory does not exist or cannot be read. */
  readDir(path: string): string[] | null;
  exists(path: string): boolean;
}

export function takeSnapshot(io: SnapshotIO, now = new Date()): PrivilegeSnapshot {
  const unreadable: string[] = [];
  const read = (path: string): string | null => {
    const text = io.readFile(path);
    if (text === null && io.exists(path)) unreadable.push(path);
    return text;
  };

  const accounts = parseAccounts(read('/etc/passwd') ?? '');
  const snapshot: PrivilegeSnapshot = {
    taken_at: now.toISOString(),
    uid0: accounts.filter((a) => a.uid === 0).map((a) => a.name).sort(),
    admin_groups: parseAdminGroups(read('/etc/group') ?? ''),
    sudoers: {},
    keys: {},
    unreadable,
  };

  const sudoersFiles = ['/etc/sudoers'];
  for (const name of (io.readDir('/etc/sudoers.d') ?? []).sort()) {
    if (sudoReadsIncluded(name)) sudoersFiles.push(`/etc/sudoers.d/${name}`);
  }
  for (const path of sudoersFiles) {
    const text = read(path);
    if (text !== null) snapshot.sudoers[path] = sudoersRules(text);
  }

  for (const account of accounts) {
    if (account.uid !== 0 && (!canLogIn(account) || !account.home || account.home === '/')) continue;
    const keys: PrivilegeSnapshot['keys'][string] = {};
    for (const file of ['authorized_keys', 'authorized_keys2']) {
      const text = read(`${account.home.replace(/\/$/, '')}/.ssh/${file}`);
      for (const k of parseAuthorizedKeys(text ?? '')) keys[k.fingerprint] = { type: k.type, comment: k.comment };
    }
    if (Object.keys(keys).length > 0) snapshot.keys[account.name] = keys;
  }
  return snapshot;
}

export interface PrivilegeChange {
  severity: EventSeverity;
  message: string;
  details: Record<string, unknown>;
}

const added = <T>(before: T[], after: T[]) => after.filter((x) => !before.includes(x));

/**
 * What changed between two snapshots, most severe first. A path that became
 * unreadable is not a removal: comparing a root snapshot to a non-root one
 * would otherwise report every sudoers rule and key as deleted.
 */
export function diffSnapshots(prev: PrivilegeSnapshot, next: PrivilegeSnapshot): PrivilegeChange[] {
  const changes: PrivilegeChange[] = [];

  for (const name of added(prev.uid0, next.uid0)) {
    changes.push({ severity: 'critical', message: `New uid 0 account: ${name}`, details: { rule_id: 'priv-uid0-added', account: name } });
  }
  for (const name of added(next.uid0, prev.uid0)) {
    changes.push({ severity: 'low', message: `uid 0 account removed: ${name}`, details: { rule_id: 'priv-uid0-removed', account: name } });
  }

  for (const group of new Set([...Object.keys(prev.admin_groups), ...Object.keys(next.admin_groups)])) {
    const before = prev.admin_groups[group] ?? [];
    const after = next.admin_groups[group] ?? [];
    for (const m of added(before, after)) {
      changes.push({ severity: 'high', message: `${m} added to the ${group} group (can run anything as root)`, details: { rule_id: 'priv-admin-group-added', group, account: m } });
    }
    for (const m of added(after, before)) {
      changes.push({ severity: 'low', message: `${m} removed from the ${group} group`, details: { rule_id: 'priv-admin-group-removed', group, account: m } });
    }
  }

  for (const path of new Set([...Object.keys(prev.sudoers), ...Object.keys(next.sudoers)])) {
    if (next.unreadable.includes(path) || prev.unreadable.includes(path)) continue;
    const before = prev.sudoers[path];
    const after = next.sudoers[path];
    if (!before && after) {
      changes.push({ severity: 'high', message: `New sudoers file ${path}${after.length ? `: ${after.slice(0, 3).join(' | ')}` : ''}`, details: { rule_id: 'priv-sudoers-added', path, rules: after.slice(0, 20) } });
      continue;
    }
    if (before && !after) {
      changes.push({ severity: 'low', message: `Sudoers file removed: ${path}`, details: { rule_id: 'priv-sudoers-removed', path } });
      continue;
    }
    const plus = added(before ?? [], after ?? []);
    const minus = added(after ?? [], before ?? []);
    if (plus.length) {
      changes.push({ severity: 'high', message: `Sudoers rule added in ${path}: ${plus.slice(0, 3).join(' | ')}`, details: { rule_id: 'priv-sudoers-changed', path, added: plus.slice(0, 20), removed: minus.slice(0, 20) } });
    } else if (minus.length) {
      changes.push({ severity: 'low', message: `Sudoers rule removed in ${path}: ${minus.slice(0, 3).join(' | ')}`, details: { rule_id: 'priv-sudoers-changed', path, removed: minus.slice(0, 20) } });
    }
  }

  for (const user of new Set([...Object.keys(prev.keys), ...Object.keys(next.keys)])) {
    const before = prev.keys[user] ?? {};
    const after = next.keys[user] ?? {};
    for (const fp of Object.keys(after)) {
      if (before[fp]) continue;
      const { type, comment } = after[fp];
      changes.push({
        severity: 'high',
        message: `New SSH key for ${user}: ${type} ${fp}${comment ? ` (${comment})` : ''}`,
        details: { rule_id: 'priv-authorized-key-added', account: user, fingerprint: fp, key_type: type, comment },
      });
    }
    for (const fp of Object.keys(before)) {
      if (after[fp]) continue;
      changes.push({ severity: 'low', message: `SSH key removed for ${user}: ${fp}`, details: { rule_id: 'priv-authorized-key-removed', account: user, fingerprint: fp } });
    }
  }

  const rank: Record<EventSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return changes.sort((a, b) => rank[b.severity] - rank[a.severity]);
}

export interface SudoEntry { user: string; runas: string; command: string; tty?: string; pwd?: string; denied: boolean }

/**
 * A sudo journal MESSAGE: `alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ;
 * COMMAND=/usr/bin/apt update`, or the same with a denial reason before TTY.
 * Password failures are left to the sudo-abuse rule and return null.
 */
export function parseSudoMessage(message: string): SudoEntry | null {
  const m = /^\s*(\S+)\s+:\s+(.*)$/.exec(message);
  if (!m) return null;
  const fields: Record<string, string> = {};
  let reason = '';
  for (const part of m[2].split(' ; ')) {
    const kv = /^([A-Z]+)=(.*)$/.exec(part.trim());
    if (kv) fields[kv[1]] = kv[2];
    else if (!reason) reason = part.trim();
  }
  if (!fields.COMMAND) return null;
  if (/incorrect password|authentication failure/i.test(reason)) return null;
  return {
    user: m[1],
    runas: fields.USER ?? 'root',
    command: fields.COMMAND,
    tty: fields.TTY,
    pwd: fields.PWD,
    denied: /not allowed|not in the sudoers|NOT in sudoers|command not allowed/i.test(reason),
  };
}
