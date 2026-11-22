import { readFileSync, statSync } from 'node:fs';
import type { SshKeyContext } from '@threatcrush/event-detail';
import { suspiciousKeyComment } from '@threatcrush/scan';
import { parseAuthorizedKeys, parsePasswd, type AuthorizedKey } from '../../core/host-scan/parsers.js';

/**
 * Which authorized_keys line a login's fingerprint matches, across root's
 * and every login account's authorized_keys / authorized_keys2: its options
 * (`restrict`, `command=`, `from=`), comment, every file that carries it,
 * and the planted-persistence flags (same key in root's and a user's file, a
 * dated ci/diag comment; attack-vectors/planted-authorized-keys.md).
 *
 * The key blob is never returned: `line_masked` shows its first characters.
 * Files are re-read only when their mtime changes.
 */

export interface KeyFilesIO {
  passwd(): string;
  mtime(path: string): number | null;
  read(path: string): string | null;
}

export const realKeyFilesIO: KeyFilesIO = {
  passwd: () => { try { return readFileSync('/etc/passwd', 'utf-8'); } catch { return ''; } },
  mtime: (p) => { try { return statSync(p).mtimeMs; } catch { return null; } },
  read: (p) => { try { return readFileSync(p, 'utf-8'); } catch { return null; } },
};

const NOLOGIN = /(?:nologin|false|sync|halt|shutdown)$/;

/** `AAAAC3Nz…[masked]`: enough to tell keys apart by eye, not enough to be the key. */
export function maskBlob(blob: string): string {
  return `${blob.slice(0, 8)}…[masked]`;
}

function optionText(o: { name: string; value: string | null }): string {
  return o.value === null ? o.name : `${o.name}="${o.value.replace(/"/g, '\\"')}"`;
}

const MAX_OPTION_CHARS = 300;

/** The line as written, with the blob masked and very long option values cut. */
export function maskedLine(k: AuthorizedKey): string {
  const opts = k.options.map((o) => optionText(o).slice(0, MAX_OPTION_CHARS)).join(',');
  return [opts, k.type, maskBlob(k.blob), k.comment].filter(Boolean).join(' ');
}

interface Placed extends AuthorizedKey { user: string }

export class AuthorizedKeysIndex {
  private files = new Map<string, { mtime: number; keys: Placed[] }>();

  constructor(private readonly io: KeyFilesIO = realKeyFilesIO) {}

  private accounts(): Array<{ name: string; home: string }> {
    return parsePasswd(this.io.passwd())
      .filter((p) => p.uid === 0 || (p.home && p.home !== '/' && !NOLOGIN.test(p.shell)))
      .map((p) => ({ name: p.name, home: p.home.replace(/\/$/, '') }));
  }

  private keysIn(path: string, user: string): Placed[] {
    const mtime = this.io.mtime(path);
    if (mtime === null) { this.files.delete(path); return []; }
    const cached = this.files.get(path);
    if (cached && cached.mtime === mtime) return cached.keys;
    const keys = parseAuthorizedKeys(this.io.read(path) ?? '', path).map((k) => ({ ...k, user }));
    this.files.set(path, { mtime, keys });
    return keys;
  }

  /** Every authorized_keys line carrying `fingerprint`, as login context. */
  lookup(fingerprint: string, expected: ReadonlySet<string> = new Set()): SshKeyContext {
    const matches: Placed[] = [];
    for (const { name, home } of this.accounts()) {
      for (const f of ['authorized_keys', 'authorized_keys2']) {
        for (const k of this.keysIn(`${home}/.ssh/${f}`, name)) if (k.fingerprint === fingerprint) matches.push(k);
      }
    }
    if (!matches.length) return { found: false, fingerprint, ...(expected.has(fingerprint) ? { expected: true } : {}) };
    // The login's own line: prefer a restricted one only if every copy is; report the least restricted.
    const k = matches.find((m) => !m.command && !m.from && !m.restrict) ?? matches[0];
    const accounts = [...new Set(matches.map((m) => m.user))];
    const inRoot = matches.some((m) => m.user === 'root' || m.file.startsWith('/root/'));
    const inOther = matches.some((m) => m.user !== 'root' && !m.file.startsWith('/root/'));
    return {
      found: true,
      type: k.type,
      fingerprint,
      comment: k.comment.slice(0, 200) || undefined,
      options: k.options.map((o) => optionText(o).slice(0, MAX_OPTION_CHARS)),
      command: k.command ? k.command.slice(0, 500) : null,
      from: k.from ? k.from.slice(0, 300) : null,
      restrict: k.restrict,
      files: matches.map((m) => `${m.file}:${m.line}`).slice(0, 10),
      accounts,
      line_masked: maskedLine(k).slice(0, 800),
      in_root_and_user: inRoot && inOther,
      suspicious_comment: suspiciousKeyComment(k.comment),
      ...(expected.has(fingerprint) ? { expected: true } : {}),
    };
  }
}
